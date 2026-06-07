#!/usr/bin/env python3
# Kiro agentSpawn hook — captures authenticated identity via `kiro-cli whoami --format json`
# and sends the full Kiro identity + git context to the Reva PDP backend.
# All fields from whoami are forwarded — nothing is skipped.
import sys,json,os,subprocess,re,platform,urllib.request as U;
d=json.loads(sys.stdin.read() or "{}");
cwd=d.get("cwd") or os.getcwd();
# ── Kiro identity: run `kiro-cli whoami --format json` ──
ki={};
try:
 r=subprocess.run(["kiro-cli","whoami","--format","json"],capture_output=True,text=True,timeout=10);
 if r.returncode==0 and r.stdout.strip():
  ki=json.loads(r.stdout.strip())
except: pass
# Fallback: try plain `kiro-cli whoami` and parse text output
if not ki.get("email"):
 try:
  r2=subprocess.run(["kiro-cli","whoami"],capture_output=True,text=True,timeout=10);
  if r2.returncode==0:
   for line in r2.stdout.splitlines():
    if "Email:" in line: ki["email"]=line.split("Email:")[1].strip()
    if "Builder ID" in line: ki["accountType"]="BuilderId"
    if "Identity Center" in line: ki["accountType"]="IdentityCenter"
    if "Google" in line and "accountType" not in ki: ki["accountType"]="Social"
    if "GitHub" in line and "accountType" not in ki: ki["accountType"]="Social"
    if "Profile:" in line:
     arn=line.split("Profile:")[1].strip().split()
     if len(arn)>0: ki["profileArn"]=arn[-1] if "arn:" in arn[-1] else arn[0]
    m=re.search(r'\((https?://\S+)\)',line)
    if m: ki["startUrl"]=m.group(1)
 except: pass
# ── Git context ──
G=lambda x: subprocess.run(x,capture_output=True,text=True,cwd=cwd).stdout.strip();
br=G(["git","branch","--show-current"]);
ru=G(["git","remote","get-url","origin"]);
mm=re.search(r"([A-Z]+-[0-9]+)",br);
# ── Model: capture from kiro-cli settings or agent config ──
kmodel=d.get("model","");
if not kmodel:
 try: kmodel=subprocess.run(["kiro-cli","settings","chat.model"],capture_output=True,text=True,timeout=5).stdout.strip()
 except: pass
if not kmodel:
 try: kmodel=subprocess.run(["kiro-cli","settings","chat.defaultModel"],capture_output=True,text=True,timeout=5).stdout.strip()
 except: pass
body={"session_id":d.get("session_id",""),"cwd":cwd,"os_user":os.environ.get("USER",""),"model":kmodel or "auto","os_type":platform.system(),"hostname":platform.node(),"surface":"kiro_cli","kiro_identity":ki,"git_email":G(["git","config","user.email"]),"git_name":G(["git","config","user.name"]),"git_branch":br,"git_remote_url":ru,"jira_ticket_id":(mm.group(1) if mm else ""),"connection_type":("ssh" if os.environ.get("SSH_CONNECTION") else "local")};
sys.stdout.write(U.urlopen(U.Request(os.environ.get("REVA_URL","https://reva-plugin.onrender.com")+"/api/kiro/session",data=json.dumps(body).encode(),headers={"Content-Type":"application/json","X-OS-User":os.environ.get("USER","")}),timeout=30).read().decode())
