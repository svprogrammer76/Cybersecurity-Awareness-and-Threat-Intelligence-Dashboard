from __future__ import annotations
import csv, os, sqlite3
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk, SOURCE_RELIABILITY
from data.generate_threat_data import generate

ROOT=Path(__file__).resolve().parent.parent
DB=Path(os.getenv("DATABASE_PATH",ROOT/"data/dashboard.sqlite3"))
app=Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"]=1024*1024

def connect():
    DB.parent.mkdir(parents=True,exist_ok=True); c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    c=connect(); c.execute("CREATE TABLE IF NOT EXISTS threats (threat_id TEXT PRIMARY KEY, timestamp TEXT, threat_name TEXT, threat_category TEXT, indicator_type TEXT, indicator_value TEXT, source_name TEXT, confidence_score INTEGER, severity TEXT, risk_score INTEGER, status TEXT, first_seen TEXT, last_seen TEXT, country_or_region_optional TEXT, description TEXT, mitre_tactic_optional TEXT, mitre_technique_optional TEXT, cve_id_optional TEXT, dataset_label TEXT, observation_count INTEGER, campaign_id TEXT, source_reliability INTEGER)"); c.execute("CREATE TABLE IF NOT EXISTS analyst_notes (id INTEGER PRIMARY KEY, threat_id TEXT, note TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"); c.execute("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, threat_id TEXT, title TEXT, status TEXT DEFAULT 'OPEN', created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    if c.execute("SELECT count(*) FROM threats").fetchone()[0]==0:
        path=ROOT/"data/threat_intelligence_dataset.csv"
        if not path.exists(): generate(path)
        with path.open(encoding="utf-8",newline="") as f: rows=list(csv.DictReader(f))
        cols=list(rows[0]); c.executemany(f"INSERT OR IGNORE INTO threats ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",[[r[k] for k in cols] for r in rows])
    c.commit(); c.close()

def rows(sql,args=()):
    c=connect(); result=[dict(r) for r in c.execute(sql,args).fetchall()]; c.close(); return result
@app.get("/")
def home(): return send_from_directory(ROOT/"frontend","index.html")
@app.get("/static/<path:name>")
def static(name): return send_from_directory(ROOT/"frontend",name)
@app.get("/api/health")
def health(): return jsonify(ok=True,dataset="SYNTHETIC / DEMO ONLY")
@app.get("/api/threats")
def threats():
    where=[]; args=[]
    for key,col in [("severity","severity"),("category","threat_category"),("indicator_type","indicator_type"),("status","status")]:
        value=request.args.get(key)
        if value: where.append(f"{col}=?"); args.append(value.upper())
    for key,op in [("min_risk",">="),("min_confidence",">=")]:
        v=request.args.get(key)
        if v:
            try: int(v)
            except ValueError: return jsonify(error=f"{key} must be integer"),400
            where.append(("risk_score" if key=="min_risk" else "confidence_score")+op+"?"); args.append(int(v))
    order=request.args.get("sort","newest"); ordering={"newest":"timestamp DESC","risk":"risk_score DESC","confidence":"confidence_score DESC","observations":"observation_count DESC"}.get(order)
    if not ordering:return jsonify(error="Unsupported sort"),400
    query="SELECT * FROM threats"+(" WHERE "+" AND ".join(where) if where else "")+" ORDER BY "+ordering+" LIMIT 250"
    return jsonify(items=rows(query,args),limit=250)
@app.get("/api/threats/<threat_id>")
def threat_detail(threat_id):
    found=rows("SELECT * FROM threats WHERE threat_id=?",(threat_id,))
    if not found:return jsonify(error="Threat not found"),404
    t=found[0]; t["related_indicators"]=rows("SELECT indicator_type,indicator_value,threat_id FROM threats WHERE campaign_id=? AND threat_id<>? LIMIT 15",(t["campaign_id"],threat_id)); t["notes"]=rows("SELECT note,created_at FROM analyst_notes WHERE threat_id=? ORDER BY id DESC",(threat_id,)); t["alerts"]=rows("SELECT id,title,status,created_at FROM alerts WHERE threat_id=?",(threat_id,)); t["timeline"]=[{"date":t["first_seen"],"event":"First synthetic observation"},{"date":t["last_seen"],"event":"Last synthetic observation"}]; return jsonify(t)
@app.get("/api/search")
def search():
    value=request.args.get("indicator",""); v=validate_indicator(value)
    if not v["valid"]:return jsonify(**v),400
    matches=rows("SELECT * FROM threats WHERE lower(indicator_value)=lower(?) LIMIT 25",(v["normalized_value"],))
    return jsonify(validation=v,known_in_demo_dataset=bool(matches),results=matches,notice="Database lookup only. No network connections were made.")
@app.get("/api/enrich")
def enrich():
    value=request.args.get("indicator",""); v=validate_indicator(value)
    if not v["valid"]:return jsonify(**v),400
    found=rows("SELECT * FROM threats WHERE lower(indicator_value)=lower(?)",(v["normalized_value"],))
    if not found:return jsonify(validation=v,known=False,related_alerts=[],related_indicators=[],analyst_notes=[],notice="No local synthetic observation; this is not a reputation verdict.")
    return jsonify(validation=v,known=True,records=found,associated_categories=sorted(set(x["threat_category"] for x in found)),average_confidence=round(sum(x["confidence_score"] for x in found)/len(found)),max_risk=max(x["risk_score"] for x in found),related_indicators=list({x["indicator_value"] for x in found}),related_alerts=[x for x in found if x["severity"] in ("HIGH","CRITICAL")],analyst_notes=[x["description"] for x in found[:3]])
@app.get("/api/stats")
def stats():
    total=rows("SELECT COUNT(*) n,ROUND(AVG(confidence_score)) confidence FROM threats")[0]; sev=rows("SELECT severity label,COUNT(*) value FROM threats GROUP BY severity"); cat=rows("SELECT threat_category label,COUNT(*) value FROM threats GROUP BY threat_category ORDER BY value DESC"); types=rows("SELECT indicator_type label,COUNT(*) value FROM threats GROUP BY indicator_type"); status=rows("SELECT status label,COUNT(*) value FROM threats GROUP BY status"); month=rows("SELECT substr(timestamp,1,7) label,COUNT(*) value FROM threats GROUP BY label ORDER BY label"); tactics=rows("SELECT mitre_tactic_optional label,COUNT(*) value FROM threats WHERE mitre_tactic_optional<>'' GROUP BY label"); return jsonify(total=total["n"],average_confidence=total["confidence"],critical=sum(x["value"] for x in sev if x["label"]=="CRITICAL"),high=sum(x["value"] for x in sev if x["label"]=="HIGH"),active_indicators=rows("SELECT COUNT(DISTINCT indicator_value) n FROM threats WHERE status IN ('NEW','UNDER_REVIEW','MONITORING')")[0]["n"],open_investigations=rows("SELECT COUNT(*) n FROM threats WHERE status IN ('NEW','UNDER_REVIEW')")[0]["n"],vulnerabilities=rows("SELECT COUNT(*) n FROM threats WHERE indicator_type='CVE ID'")[0]["n"],severity=sev,categories=cat,indicator_types=types,status=status,timeline=month,tactics=tactics)
@app.post("/api/threats/<threat_id>/notes")
def add_note(threat_id):
    data=request.get_json(silent=True) or {}; note=data.get("note","").strip()
    if len(note)<1 or len(note)>1000:return jsonify(error="Note must contain 1–1000 characters"),400
    c=connect()
    if not c.execute("SELECT 1 FROM threats WHERE threat_id=?",(threat_id,)).fetchone():c.close(); return jsonify(error="Threat not found"),404
    c.execute("INSERT INTO analyst_notes(threat_id,note) VALUES(?,?)",(threat_id,note)); c.commit(); c.close(); return jsonify(ok=True),201
@app.get("/api/alerts")
def alerts():
    c=connect(); c.execute("INSERT INTO alerts(threat_id,title) SELECT t.threat_id, 'Review '+t.severity+' synthetic observation' FROM threats t WHERE t.severity IN ('HIGH','CRITICAL') AND NOT EXISTS(SELECT 1 FROM alerts a WHERE a.threat_id=t.threat_id)"); c.commit(); c.close(); return jsonify(items=rows("SELECT a.*,t.threat_category,t.indicator_value,t.risk_score FROM alerts a JOIN threats t USING(threat_id) ORDER BY a.created_at DESC LIMIT 250"))
@app.patch("/api/alerts/<int:alert_id>")
def update_alert(alert_id):
    status=(request.get_json(silent=True) or {}).get("status","").upper()
    if status not in ("OPEN","INVESTIGATING","CLOSED"):return jsonify(error="Status must be OPEN, INVESTIGATING, or CLOSED"),400
    c=connect(); cur=c.execute("UPDATE alerts SET status=? WHERE id=?",(status,alert_id)); c.commit(); c.close(); return (jsonify(ok=True),200) if cur.rowcount else (jsonify(error="Alert not found"),404)
@app.get("/api/vulnerabilities")
def vulnerabilities():return jsonify(items=rows("SELECT * FROM threats WHERE indicator_type='CVE ID' ORDER BY risk_score DESC LIMIT 100"),note="Synthetic CVE-shaped examples are not verified vulnerability records.")
@app.get("/api/awareness/modules")
def modules():return jsonify(items=MODULES)
@app.get("/api/quiz")
def quiz():return jsonify(questions=[{k:v for k,v in q.items() if k!="answer"} for q in QUIZ])
@app.post("/api/quiz/submit")
def quiz_submit():
    answers=(request.get_json(silent=True) or {}).get("answers",[])
    if not isinstance(answers,list):return jsonify(error="answers must be an array"),400
    correct=sum(i<len(QUIZ) and int(a)==QUIZ[i]["answer"] for i,a in enumerate(answers) if str(a).isdigit()); score=round(correct/len(QUIZ)*100); return jsonify(correct=correct,total=len(QUIZ),awareness_score=score,recommendations=["Review phishing recognition and reporting." if score<80 else "Keep practicing incident reporting and MFA habits."])
MODULES=[{"title":t,"summary":s,"actions":a} for t,s,a in [("Phishing awareness","Pause before acting on urgent or unexpected messages.","Verify through a known channel; report suspicious messages."),("Password security","Use unique passwords and a password manager.","Never reuse work credentials; enable MFA."),("MFA","MFA adds a verification step to sign-in.","Deny unexpected prompts and report repeated requests."),("Social engineering","Attackers may use urgency, authority, or familiarity.","Verify identity before sharing data or approving access."),("Safe browsing","Look carefully at destinations and unexpected downloads.","Use approved bookmarks; do not open suspicious URLs."),("Secure Wi-Fi","Public networks can expose sensitive sessions.","Use approved secure access and avoid sensitive work on unknown networks."),("Software updates","Updates address known software weaknesses.","Install approved updates promptly and restart when required."),("Ransomware awareness","Unexpected encrypted files or extortion notes need rapid reporting.","Disconnect per policy and contact the security team; do not investigate alone."),("Removable media","Unknown USB devices may introduce risk.","Use only approved media and report found devices."),("Data privacy","Collect and share only information needed for the task.","Use approved storage, access controls, and retention rules."),("Mobile security","Phones hold work accounts and sensitive data.","Keep devices updated, locked, and report loss promptly."),("Remote work","Home environments still need secure habits.","Lock screens, protect conversations, and use approved access methods."),("Cloud account security","Cloud sharing settings can expose data.","Review recipients and permissions before sharing."),("Incident reporting","Fast reporting improves response.","Report suspected incidents promptly, even if unsure."),("AI-enabled scam awareness","Generated messages and voices can imitate trusted people.","Independently verify unusual requests using a known contact method.")]]
QUIZ=[{"question":q,"options":o,"answer":a} for q,o,a in [("An urgent email asks you to sign in using its link. What is safest?",["Use the link quickly","Open the known service directly and report the message","Forward to colleagues"],1),("An unexpected MFA prompt appears. What should you do?",["Approve it","Deny it and report it","Share the code"],1),("What does an IOC match establish?",["Confirmed compromise","A lead requiring context and investigation","Actor identity"],1),("What is a safe response to an unknown USB?",["Plug it in","Give it to IT/security without connecting it","Take it home"],1),("What is the purpose of software updates?",["Address issues including security weaknesses","Disable monitoring","Guarantee no risk"],0),("How should an unusual payment request be verified?",["Reply to the same message","Use a separately known contact route","Assume urgency is proof"],1),("A suspicious link appears. What should you do?",["Visit it in private mode","Do not open it; report it","Send it to a friend"],1),("How should work passwords be handled?",["Reuse one memorable password","Use unique passwords and an approved manager","Share with teammates"],1),("What does MITRE ATT&CK describe?",["A threat score","Observed adversary behaviors and knowledge","An antivirus product"],1),("What should you do after a suspected incident?",["Hide it until confirmed","Report promptly using policy","Delete all evidence"],1),("A shared cloud file is no longer needed by a recipient. What now?",["Leave access forever","Remove unneeded access per policy","Make it public"],1),("A caller requests confidential data urgently. What is safest?",["Verify identity through an approved channel","Provide it immediately","Ask for a personal email"],0),("Why use MFA?",["Add a sign-in verification layer","Replace all updates","Prove a message is safe"],0),("What does CVSS help communicate?",["Vulnerability severity characteristics","Proof of exploitation","Actor attribution"],0),("An IOC can be stale or shared. What follows?",["Treat as confirmed incident","Check context and validate before decisions","Ignore every IOC"],1),("What is safest on public Wi-Fi?",["Perform sensitive work without protections","Use approved secure access methods","Disable device lock"],1),("A colleague reports a suspicious message. What is useful?",["Thank them and follow reporting process","Ask them to click it","Delete the report"],0),("What is data minimization?",["Keep only data needed for a purpose","Copy all data","Share broadly"],0),("An unknown software update popup appears. What do you do?",["Install blindly","Use approved update mechanisms","Disable security tools"],1),("What does correlation mean?",["Evidence of possible relationship, not proof","Guaranteed attribution","Confirmed breach"],0),("A device is lost. What is best?",["Report promptly to IT/security","Wait a week","Post credentials online"],0),("A known brand name appears in a domain. Is it automatically trustworthy?",["Yes","No; verify the exact destination independently","Only on mobile"],1),("A file hash matches a synthetic demo record. What does it mean?",["Malware confirmed","A dataset match only; investigate context","File should be executed"],1),("What is a least-privilege approach?",["Grant only access needed for work","Grant administrator access to all","Share accounts"],0),("Why protect analyst notes?",["They may contain sensitive operational context","They are always public","They have no security value"],0),("A security alert triggers. What is the right next step?",["Review evidence and follow triage process","Declare breach immediately","Ignore it"],0),("What does confidence measure?",["Evidence quality/credibility","Potential impact alone","Number of users"],0),("How should suspicious URLs be handled in this demo?",["Open automatically","Analyze as data without visiting","Scan externally"],1),("A colleague asks for an MFA code. What should you do?",["Send it","Never share it; verify/report","Post it in chat"],1),("What is an appropriate incident report?",["When, what, and relevant observations through approved channels","Speculation only","Public social media post"],0),("How should AI-generated voice requests be verified?",["Trust the voice","Call back via a known number","Send confidential files"],1),("Threat intelligence should primarily support what?",["Informed defensive decisions","Automatic attribution","Guaranteed prevention"],0)]]
if __name__=="__main__":
    init_db(); app.run(host="127.0.0.1",port=5000,debug=False)
