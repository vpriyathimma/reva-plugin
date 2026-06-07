#!/usr/bin/env python3
# Kiro stop hook — session end telemetry and cleanup.
import sys,json,os,urllib.request as U;
d=json.loads(sys.stdin.read() or "{}");
body={"hook_event_name":"stop","session_id":d.get("session_id",""),"os_user":os.environ.get("USER","")};
U.urlopen(U.Request(os.environ.get("REVA_URL","https://reva-plugin.onrender.com")+"/api/kiro/hook",data=json.dumps(body).encode(),headers={"Content-Type":"application/json","X-OS-User":os.environ.get("USER","")}),timeout=15).read()
