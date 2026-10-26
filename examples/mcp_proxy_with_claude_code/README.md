# The MCP proxy with Claude Code

Claude Code talks to a small notes server only through Arbitr. You will see
Arbitr hold tools until you accept them, block a destructive call, and hold a
tool again when the server quietly rewrites its description.

## Set up

In an empty folder:

```text
pip install "arbitr[cli,mcp]"
arbitr init
```

Copy `notes_server.py`, `policy.yaml` and `.mcp.json` from this folder into
it (`policy.yaml` replaces the starter one), then add this to `arbitr.yaml`:

```yaml
mcp:
  principal: you@example.com
  on_tool_change: require_approval
```

`.mcp.json` tells Claude Code to start the server through the proxy:
`arbitr mcp-proxy --server notes --upstream "python notes_server.py"`.

## The manual check

1. Start Claude Code in the folder (`claude`) and approve the project's
   `notes` MCP server when asked. Ask: "What tools does the notes server
   have?" It has none yet: Arbitr holds new tools until someone accepts them.
2. In another terminal, look at what is held, read each definition, and
   accept it:

   ```text
   arbitr mcp pin ls
   arbitr mcp pin show notes add_note
   ```

   `show` ends with the exact command that pins the definition you just read,
   for example `arbitr mcp pin accept notes add_note --hash 3f9a...`. Run it
   for each of the three tools. The hash makes sure that what gets pinned is
   what you read, even if the server changes it in between.

3. Back in Claude Code, run `/mcp` to reconnect the server, then ask it to
   add a note saying "hello" and to list the notes. Both work.
4. Ask it to delete all notes. The call is refused: "Blocked by policy
   'no-mass-delete'". The notes are still there.
5. Quit Claude Code. Start it again with `NOTES_EVIL=1 claude`: the server now
   rewrites `add_note`'s description with hidden instructions. Ask for the
   tools: `add_note` is gone, held as changed. `arbitr mcp pin show notes
   add_note` prints the new description as a diff. Do not accept it.
6. `arbitr runs ls` and `arbitr intents ls` show every call, and
   `arbitr verify` checks the audit chain, including the pins.

Each step is also run without Claude Code by Arbitr's own tests
(`tests/mcp/test_example.py`), with a scripted MCP client in place of
Claude Code.
