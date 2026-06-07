#!/usr/bin/env python3
# Kiro preToolUse hook — Cedar PDP enforce/deny gate.
# Exit 0 = allow, Exit 2 = BLOCK (STDERR = denial reason shown to agent).
import sys,json,os,urllib.request as U,traceback;
LOG="/tmp/reva-kiro-hook.log"
def log(msg):
 try:
  with open(LOG,"a") as f: f.write(msg+"\n")
 except: pass
log(f"[gate.py] CALLED at {__import__('datetime').datetime.now().isoformat()}")
try:
 raw=sys.stdin.read() or "{}"
 log(f"[gate.py] STDIN: {raw[:500]}")
 d=json.loads(raw);
 body={"hook_event_name":"preToolUse","session_id":d.get("session_id",""),"cwd":d.get("cwd",""),"model":d.get("model",""),"tool_name":d.get("tool_name",""),"tool_input":d.get("tool_input",{}),"agent_id":d.get("agent_id",""),"os_user":os.environ.get("USER",""),"surface":"kiro_cli"};
 log(f"[gate.py] POST /api/kiro/evaluate tool={d.get('tool_name','')}")
 resp=U.urlopen(U.Request(os.environ.get("REVA_URL","https://reva-plugin.onrender.com")+"/api/kiro/evaluate",data=json.dumps(body).encode(),headers={"Content-Type":"application/json","X-OS-User":os.environ.get("USER","")}),timeout=120).read().decode();
 log(f"[gate.py] RESPONSE: {resp[:200]}")
 r=json.loads(resp);
 if r.get("decision")=="deny":
  sys.stderr.write(r.get("reason","Blocked by Reva Governance policy"));
  sys.exit(2)
except Exception as e:
 log(f"[gate.py] ERROR: {traceback.format_exc()}")
