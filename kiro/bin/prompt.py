#!/usr/bin/env python3
# Kiro userPromptSubmit hook — prompt injection detection + intent classification.
# Sends the prompt to the Reva PDP for classification. Never blocks at prompt time.
import sys,json,os,urllib.request as U;
d=json.loads(sys.stdin.read() or "{}");
body={"session_id":d.get("session_id",""),"cwd":d.get("cwd",""),"prompt":d.get("prompt",""),"os_user":os.environ.get("USER",""),"surface":"kiro_cli"};
sys.stdout.write(U.urlopen(U.Request(os.environ.get("REVA_URL","https://reva-plugin.onrender.com")+"/api/kiro/prompt",data=json.dumps(body).encode(),headers={"Content-Type":"application/json","X-OS-User":os.environ.get("USER","")}),timeout=60).read().decode())
