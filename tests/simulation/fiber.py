"""Run blocking code, such as the real executor, as a simulator worker.

A ``Fiber`` is a real thread that only runs while the simulator resumes it.
The code inside calls ``fiber.pause(action)`` at each step boundary (for the
executor, from its ``on_step`` hook); that hands control back to the
simulator and blocks the thread until it is resumed. Only one fiber runs at a
time, so a run stays a pure function of its seed.

``fiber_worker`` wraps a fiber as the generator the ``Simulator`` expects.
When the simulator crashes the worker, the generator is closed: the harness
first cuts the fiber off from every durable resource (``before_kill``), then
the fiber is woken with ``Killed``, which unwinds the thread without letting
anything reach the ledger or the services. That is what a killed process looks
like from the outside: whatever it had not committed never happens.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from engine import Action, WorkerGen

_JOIN_SECONDS = 30.0
_STEP_SECONDS = 120.0
"""Wall time one step may take before the run is declared stuck (a deadlock)."""


class Killed(BaseException):
    """Raised inside a fiber that the simulator crashed. Never caught by fiber code."""


class Fiber:
    """A thread that runs only between ``resume`` and its next ``pause``."""

    def __init__(self, name: str, body: Callable[[Fiber], None]) -> None:
        """Prepare the fiber; ``body`` starts on the first ``resume``."""
        self.name = name
        self.label = "start"
        self.done = False
        self._body = body
        self._go = threading.Event()
        self._back = threading.Event()
        self._action: Action | None = None
        self._error: BaseException | None = None
        self._killed = False
        self._thread = threading.Thread(target=self._main, name=name, daemon=True)
        self._started = False

    @property
    def started(self) -> bool:
        """Whether the thread has started (the first ``resume`` happened)."""
        return self._started

    def _main(self) -> None:
        self._wait_for_turn()
        try:
            if not self._killed:
                self._body(self)
        except Killed:
            pass
        except BaseException as exc:  # noqa: BLE001 - handed to the simulator thread
            self._error = exc
        finally:
            self.done = True
            self._action = None
            self._back.set()

    def _wait_for_turn(self) -> None:
        self._go.wait()
        self._go.clear()

    def pause(self, action: Action) -> None:
        """Called by the fiber's own code: yield ``action`` and wait to be resumed.

        Raises:
            Killed: the simulator crashed this worker while it was paused.
        """
        self._action = action
        self.label = getattr(action, "label", "sleep")
        self._back.set()
        self._wait_for_turn()
        if self._killed:
            raise Killed

    def resume(self) -> Action | None:
        """Run the fiber to its next pause. Returns its action, or None when it finished.

        Raises:
            BaseException: whatever the fiber's code raised (other than ``Killed``).
        """
        if not self._started:
            self._started = True
            self._thread.start()
        self._back.clear()
        self._go.set()
        if not self._back.wait(_STEP_SECONDS):
            raise RuntimeError(f"fiber {self.name} did not reach its next step in time")
        if self._error is not None:
            error, self._error = self._error, None
            raise error
        return None if self.done else self._action

    def kill(self) -> None:
        """End a paused fiber with ``Killed`` and wait for its thread to exit."""
        if not self._started or self.done:
            return
        self._killed = True
        self._back.clear()
        self._go.set()
        self._thread.join(_JOIN_SECONDS)
        if self._thread.is_alive():
            raise RuntimeError(f"fiber {self.name} did not exit after it was killed")


def fiber_worker(
    fiber: Fiber, before_kill: Callable[[], None], on_kill: Callable[[str], None]
) -> WorkerGen:
    """Drive ``fiber`` as a simulator worker.

    If the simulator closes the generator (a crash) while the fiber is paused,
    ``before_kill`` runs first, then the fiber is killed and ``on_kill`` gets
    the label of the step it died at.
    """
    try:
        while (action := fiber.resume()) is not None:
            yield action
    finally:
        if fiber.started and not fiber.done:
            label = fiber.label
            before_kill()
            fiber.kill()
            on_kill(label)
