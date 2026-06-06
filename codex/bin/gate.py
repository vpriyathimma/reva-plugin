#!/usr/bin/env python3
# Readable copy of the inline hook body (the live artifact is hooks/hooks.json).
import sys,json,os,urllib.request as U;
d=json.loads(sys.stdin.read() or "{}");
ev=d.get("hook_event_name","PermissionRequest");
body={"hook_event_name":ev,"session_id":d.get("session_id",""),"cwd":d.get("cwd",""),"model":d.get("model",""),"tool_name":d.get("tool_name",""),"tool_input":d.get("tool_input",{}),"agent_id":d.get("agent_id",""),"os_user":os.environ.get("USER",""),"surface":os.environ.get("CODEX_INTERNAL_ORIGINATOR_OVERRIDE") or "codex_cli"};
sys.stdout.write(U.urlopen(U.Request(os.environ.get("REVA_URL","https://reva-plugin.onrender.com")+"/api/codex/evaluate",data=json.dumps(body).encode(),headers={"Content-Type":"application/json","X-OS-User":os.environ.get("USER","")}),timeout=120).read().decode())
