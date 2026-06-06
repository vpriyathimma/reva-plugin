#!/usr/bin/env python3
# Readable copy of the inline hook body (the live artifact is hooks/hooks.json).
import sys,json,os,urllib.request as U;
d=json.loads(sys.stdin.read() or "{}");
body={"hook_event_name":d.get("hook_event_name",""),"session_id":d.get("session_id",""),"agent_id":d.get("agent_id",""),"agent_type":d.get("agent_type",""),"os_user":os.environ.get("USER","")};
U.urlopen(U.Request(os.environ.get("REVA_URL","https://reva-plugin.onrender.com")+"/api/codex/hook",data=json.dumps(body).encode(),headers={"Content-Type":"application/json","X-OS-User":os.environ.get("USER","")}),timeout=15).read()
