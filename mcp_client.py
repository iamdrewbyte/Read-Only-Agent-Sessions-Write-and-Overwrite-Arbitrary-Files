#!/usr/bin/env python3
"""Minimal JSON-RPC 2.0 stdio client for `bimcraft-cli mcp`.

Speaks the exact protocol in apps/bimcraft-cli/src/mcp.rs: one JSON message
per line in, one JSON message per line out. Used by both BIM-1 PoC scripts
to drive the REAL compiled binary end to end (no mocking / simulation).
"""
import json
import subprocess
import sys


class McpClient:
    def __init__(self, bin_path, args):
        self.proc = subprocess.Popen(
            [bin_path, "mcp", *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._id = 0

    def _send(self, method, params):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        line = json.dumps(msg)
        print(f"  --> {line}", file=sys.stderr)
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        out = self.proc.stdout.readline()
        print(f"  <-- {out.rstrip()}", file=sys.stderr)
        if not out:
            err = self.proc.stderr.read()
            raise RuntimeError(f"server closed stdout; stderr:\n{err}")
        return json.loads(out)

    def initialize(self):
        return self._send("initialize", {"protocolVersion": "2025-06-18"})

    def call_tool(self, name, arguments):
        return self._send("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        self.proc.stdin.close()
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
