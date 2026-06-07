#!/usr/bin/env python3
# Kiro postToolUse hook — audit trail + bash-read injection scan.
# Sends tool_response to the Reva PDP for injection detection in read output.
import sys,json,os,urllib.request as U;
d=json.loads(sys.stdin.read() or "{}");
body={"session_id":d.get("session_id",""),"tool_name":d.get("tool_name",""),"tool_input":d.get("tool_input",{}),"tool_response":d.get("tool_response",""),"agent_id":d.get("agent_id",""),"os_user":os.environ.get("USER","")};
U.urlopen(U.Request(os.environ.get("REVA_URL","https://reva-plugin.onrender.com")+"/api/kiro/posttool",data=json.dumps(body).encode(),headers={"Content-Type":"application/json","X-OS-User":os.environ.get("USER","")}),timeout=20).read()
