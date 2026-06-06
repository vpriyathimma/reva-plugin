#!/usr/bin/env python3
# Readable copy of the inline hook body (the live artifact is hooks/hooks.json).
import sys,json,os,urllib.request as U;
d=json.loads(sys.stdin.read() or "{}");
body={"session_id":d.get("session_id",""),"cwd":d.get("cwd",""),"prompt":d.get("prompt") or d.get("user_prompt") or "","os_user":os.environ.get("USER",""),"surface":os.environ.get("CODEX_INTERNAL_ORIGINATOR_OVERRIDE") or "codex_cli"};
sys.stdout.write(U.urlopen(U.Request(os.environ.get("REVA_URL","https://reva-plugin.onrender.com")+"/api/codex/prompt",data=json.dumps(body).encode(),headers={"Content-Type":"application/json","X-OS-User":os.environ.get("USER","")}),timeout=60).read().decode())
