# MCP proxy

`arbitr mcp-proxy` sits between an MCP client (Claude Code, Claude Desktop,
Cursor, or any other) and one MCP server. Point the client at the proxy
instead of the server, and every tool call goes through Arbitr's ledger and
policy, and every tool definition is pinned. Install it with
`pip install "arbitr[cli,mcp]"`.

## Run it in front of a server

Add an `mcp` section to `arbitr.yaml`:

```yaml
mcp:
  principal: alice@example.com      # who the agent acts for (ARBITR_PRINCIPAL overrides it)
  on_tool_change: require_approval  # or deny, or allow
  call_timeout: 60s
  servers:
    github:
      trust_annotations: false
      tools:
        create_issue: { effect: external_comm }
```

Then run the proxy with the server's own command line (or its URL):

```text
arbitr mcp-proxy --server github --upstream "npx -y @modelcontextprotocol/server-github" --upstream-env GITHUB_TOKEN
```

`--server` names the server in pins and in tool names: the proxy's tools are
called `mcp:<server>/<tool>` in the ledger and in policy rules, so a rule can
say `when: { tool: "mcp:github/delete_repository" }`. The `mcp-basics` policy
pack holds safe defaults for every `mcp*` tool.

A stdio server only gets a small default environment. Name the variables it
needs with `--upstream-env` (repeat it); nothing else is passed on. For an
HTTP server, give its URL and any headers with `--upstream-header "Name: value"`.
Write a secret as `--upstream-header "Authorization: env:UPSTREAM_AUTH"` so the
value is read from the variable `UPSTREAM_AUTH` and never appears on the
command line or in `.mcp.json`.

## Point Claude Code at it

```text
claude mcp add --transport stdio github -- arbitr mcp-proxy --server github --upstream "npx -y @modelcontextprotocol/server-github" --upstream-env GITHUB_TOKEN
```

Or in a project's `.mcp.json`:

```json
{
  "mcpServers": {
    "github": {
      "type": "stdio",
      "command": "arbitr",
      "args": ["mcp-proxy", "--server", "github",
               "--upstream", "npx -y @modelcontextprotocol/server-github",
               "--upstream-env", "GITHUB_TOKEN"]
    }
  }
}
```

The proxy reads its config from `ARBITR_CONFIG` or `arbitr.yaml` in the folder
the client starts it in; pass `--config` to be explicit. In stdio mode the
proxy never writes to standard output, which is the MCP channel.

## Tool pinning

The first time the proxy sees a tool, and whenever a tool's definition
changes (its name, description, input schema, annotations, anything), the
definition is held, recorded in the audit chain as `tool_def_changed`, and
not shown to the client. A server that rewrites a tool description after you
installed it (to slip instructions to the model) cannot reach the model that
way. Calls to a held tool are refused with a message that says how to accept
it.

```text
arbitr mcp pin ls                       # pinned tools, and held ones with their hashes
arbitr mcp pin show github create_issue # the held definition, as a diff against the pinned one
arbitr mcp pin accept github create_issue --hash <the hash show printed>
arbitr mcp pin accept github --all --hash <hash> --hash <hash>   # several reviewed at once
```

`show` ends with the exact `accept` command for the definition it printed.
Accepting needs that hash: if the server changes the definition after you
read it, the hash no longer matches and nothing is pinned. `--yes` instead of
`--hash` accepts whatever is held at that moment, without that check.

`on_tool_change` decides what happens to new and changed definitions:
`require_approval` (the default) and `deny` hold them until someone accepts
them (with `deny` the message says the change is refused); `allow` accepts
them at once and records who: `policy:on_tool_change=allow`. Pins are part of
the ledger, so `arbitr verify` notices a pin edited behind its back.

## What a tool is allowed to claim

MCP servers describe their tools with hints: `readOnlyHint`,
`destructiveHint`, `idempotentHint`, `openWorldHint`. A server can lie, so
hints that make a tool stricter always count (a destructive hint makes it
destructive, an open-world hint makes it an outbound action), and hints that
would loosen it count only for a server you mark `trust_annotations: true`.
Even then, an open-world hint keeps a read-only tool an outbound action: a
fetch can carry data out in its URL. Without hints a tool is a write, and its
output is untrusted. Per-tool settings in the config win over both.

A trusted `idempotentHint` makes the tool's idempotency `native`. For an MCP
tool that means "calling it again with the same arguments has no further
effect", so after a crash Arbitr may run it again. The proxy never sends the
ledger's idempotency key to the server.

## Calls

A call goes through the ledger in one run per client, for the configured
principal. Over stdio that is the whole proxy process (a client starts one
proxy per server), whatever MCP protocol version the client speaks; over
HTTP it is one MCP session. The run carries taint and per-run budgets from
call to call. Over stdio the agent id is `mcp.agent_id`, or else the name the
client reports for itself. The server's answer is the receipt: the same call with
the same arguments in the same run returns it without calling the server
again. A stop (denied, waiting for approval, outcome unknown) comes back as
an MCP error result with a short message for the model. An error result from
the server is passed back as it is and recorded as a failure, so the call can
run again. A call that times out, or whose connection to the server is lost
before the answer, may have happened, so it is an unknown outcome and is not
run again on a retry.

When the server says its tools changed, the proxy tells the client, which
lists them again (and new definitions are pinned as above).

## Over HTTP

```text
arbitr mcp-proxy --server github --upstream "..." --http --host 127.0.0.1 --port 8765
```

HTTP mode serves streamable HTTP at `/mcp` and never runs open: every request
needs a bearer token, and each token maps to a principal. Store only the
token's SHA-256 in the config:

```yaml
mcp:
  http_tokens:
    - principal: alice@example.com
      sha256: <the 64 hex digits of the token's SHA-256>
      agent_id: ci-bot   # optional; else mcp.agent_id, else mcp-proxy:<server>
```

Over HTTP the agent id never comes from the client. HTTP clients must use a
session-based MCP protocol version (the 2025 versions); requests in the newer
session-less form are refused with status 400, because their calls could not
share a run.

```text
python -c "import hashlib, sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "<your token>"
claude mcp add --transport http github http://127.0.0.1:8765/mcp --header "Authorization: Bearer <your token>"
```

## Limits

- A stdio server runs as your user, so it can read the ledger and its key and
  could rewrite pins. Pinning protects the model from changed tool
  descriptions, not your machine from a hostile program. Run servers you do
  not trust as another user or in a container.
- HTTP mode has no TLS: tokens and calls are clear text on the network. Keep
  it on `127.0.0.1` (the proxy warns otherwise) or put a TLS proxy in front.
- If a stdio server dies, the proxy keeps answering with errors until the
  client restarts it.
- The proxy forwards the arguments the model sent as they are; it does not
  know how the server will convert them. Numeric rules read numbers sent as
  text the way most servers convert them.
- A server could change a tool between the list the client saw and a call.
  The proxy re-lists when the server says its tools changed.
- One proxy fronts one server. Run one per server.

See `examples/mcp_proxy_with_claude_code/` for a complete setup with a fake
server you can try.
