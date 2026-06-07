#!/usr/bin/env python3
# Kiro preToolUse hook — Cedar PDP enforce/deny gate.
# Reads STDIN JSON (tool_name, tool_input, session_id, cwd), POSTs to Reva PDP.
# Exit 0 = allow, Exit 2 = BLOCK (STDERR = denial reason shown to agent).
import sys,json,os,urllib.request as U;
d=json.loads(sys.stdin.read() or "{}");
body={"hook_event_name":"preToolUse","session_id":d.get("session_id",""),"cwd":d.get("cwd",""),"model":d.get("model",""),"tool_name":d.get("tool_name",""),"tool_input":d.get("tool_input",{}),"agent_id":d.get("agent_id",""),"os_user":os.environ.get("USER",""),"surface":"kiro_cli"};
try:
 resp=U.urlopen(U.Request(os.environ.get("REVA_URL","https://reva-plugin.onrender.com")+"/api/kiro/evaluate",data=json.dumps(body).encode(),headers={"Content-Type":"application/json","X-OS-User":os.environ.get("USER","")}),timeout=120).read().decode();
 r=json.loads(resp);
 if r.get("decision")=="deny":
  sys.stderr.write(r.get("reason","Blocked by Reva Governance policy"));
  sys.exit(2)
except Exception as e:
 pass
