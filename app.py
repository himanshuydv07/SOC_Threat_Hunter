#!/usr/bin/env python3
"""
Flask Dashboard — Wazuh Threat Hunter SOAR v5
All fixes: real timing in /api/state, srcip in alerts, SOAR activity log,
           MEDIUM+ triggers, soar_timing for dashboard chart/boxes
"""
import subprocess, os, io, time, threading, requests
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file, Response

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

from wazuh_threat_hunter import (
    process_alerts, get_dashboard_state, wazuh,
    alerts_store, metrics_store, nist_counts,
    get_nist_score, mitre_seen, timing_store
)

app = Flask(__name__)

POLL_INTERVAL   = int(os.getenv("POLL_INTERVAL",  "60"))
N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL",    "http://localhost:5678/webhook/wazuh-alerts")
FLASK_BASE_URL  = os.getenv("FLASK_BASE_URL",     "http://localhost:8080")
SOAR_MIN_LEVEL  = int(os.getenv("SOAR_MIN_LEVEL", "12"))

NIST_MAP  = {"CRITICAL":"RS","HIGH":"DE","MEDIUM":"PR","LOW":"ID"}
NIST_FULL = {"ID":"Identify","PR":"Protect","DE":"Detect","RS":"Respond","RC":"Recover"}
NIST_ACTIONS = {
    "CRITICAL": "Isolate endpoint immediately + block source IP + escalate to SOC",
    "HIGH":     "Investigate endpoint + monitor network traffic + review logs",
    "MEDIUM":   "Review logs + check related events + update detection rules",
    "LOW":      "Log and monitor + schedule review in next cycle"
}

soar_activity = []  # real SOAR log with timing

def get_severity(level: int) -> str:
    if level >= 12: return "CRITICAL"
    if level >= 8:  return "HIGH"
    if level >= 5:  return "MEDIUM"
    return "LOW"

def get_nist_data(level: int):
    sev   = get_severity(level)
    phase = NIST_MAP.get(sev, "DE")
    return phase, NIST_FULL.get(phase, phase), NIST_ACTIONS.get(sev, "Investigate")

def _soar_log(action_type, ip, desc, duration_ms, success):
    soar_activity.insert(0, {
        "type":        action_type,
        "ip":          ip,
        "desc":        desc,
        "duration_ms": duration_ms,
        "success":     success,
        "timestamp":   datetime.utcnow().isoformat()
    })
    if len(soar_activity) > 200: soar_activity.pop()

def trigger_n8n(alert: dict):
    try:
        level = int(alert.get("rule_level", alert.get("level", 0)))
        if level < SOAR_MIN_LEVEL:
            return
        sev                       = get_severity(level)
        phase, phase_full, action = get_nist_data(level)
        srcip                     = alert.get("agent_ip", alert.get("srcip", "N/A"))

        payload = {
            "body": {
                "timestamp":          alert.get("timestamp", datetime.utcnow().isoformat()),
                "severity":           sev,
                "agent":              {"name": alert.get("agent", "unknown"), "ip": srcip},
                "rule":               {"level": level, "description": alert.get("rule_desc", "No description")},
                "data":               {"srcip": srcip},
                "mitre_id":           alert.get("mitre_id",     "T0000"),
                "mitre_name":         alert.get("mitre_name",   "Unknown"),
                "mitre_tactic":       alert.get("mitre_tactic", "Unknown"),
                "nist":               {"phase": phase, "phase_full": phase_full, "recommended_action": action},
                "nist_phase":         phase,
                "nist_label":         phase_full,
                "recommended_action": action,
                "pdf_url":            f"{FLASK_BASE_URL}/api/report/pdf",
                "block_url":          f"{FLASK_BASE_URL}/soar/block-ip?ip={srcip}",
                "unblock_url":        f"{FLASK_BASE_URL}/soar/unblock-ip?ip={srcip}",
            }
        }
        t0  = time.time()
        r   = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=8)
        ms  = round((time.time() - t0) * 1000)
        ok  = r.status_code < 300

        _soar_log("email", srcip,
                  f"L{level} {sev} — {alert.get('rule_desc','')[:45]}", ms, ok)

        # Write real email_ms into timing_store for chart
        if timing_store:
            timing_store[0]["email_ms"] = ms

        app.logger.info(f"[n8n] L{level} {srcip} → {r.status_code} ({ms}ms)")
    except Exception as e:
        _soar_log("email", "N/A", f"n8n failed: {str(e)[:50]}", 0, False)
        app.logger.error(f"[n8n] {e}")

def _action_page(title, message, ok):
    color = "#27ae60" if ok else "#e74c3c"
    icon  = "&#10003;" if ok else "&#10007;"
    return Response(f"""<!DOCTYPE html><html><head><meta charset='UTF-8'><title>{title}</title>
<style>body{{margin:0;font-family:'Segoe UI',sans-serif;background:#05080f;display:flex;align-items:center;justify-content:center;height:100vh}}
.card{{background:#0a0f1e;border:2px solid {color};border-radius:12px;padding:48px 56px;text-align:center;max-width:480px;box-shadow:0 0 40px {color}22}}
h1{{color:{color};font-size:26px;margin:0 0 16px}}p{{color:#c8d8f0;font-size:14px;line-height:1.8;margin:0}}
code{{background:#0d1424;padding:2px 8px;border-radius:4px;color:#00d4ff;font-family:monospace;font-size:12px}}
a{{display:inline-block;margin-top:24px;padding:10px 28px;background:{color};color:#fff;border-radius:6px;text-decoration:none;font-weight:bold}}</style>
</head><body><div class='card'><h1>{icon} {title}</h1><p>{message}</p><a href="javascript:window.close()">Close</a></div></body></html>""",
    mimetype="text/html")

@app.route("/soar/block-ip", methods=["GET","POST"])
def block_ip():
    ip = request.args.get("ip") or (request.get_json(silent=True) or {}).get("ip")
    if not ip:
        return _action_page("Error", "No IP provided.", False), 400
    rule = f"WAZUH_BLOCK_{ip}"
    subprocess.run(f'netsh advfirewall firewall delete rule name="{rule}"', shell=True, capture_output=True)
    t0  = time.time()
    res = subprocess.run(
        f'netsh advfirewall firewall add rule name="{rule}" dir=in action=block remoteip={ip} enable=yes',
        shell=True, capture_output=True, text=True)
    ms  = round((time.time() - t0) * 1000)
    if res.returncode == 0:
        _soar_log("block", ip, f"Firewall rule added: {rule}", ms, True)
        if timing_store: timing_store[0]["block_ms"] = ms
        return _action_page("IP Blocked",
            f"IP <b>{ip}</b> blocked via Windows Firewall.<br>Rule: <code>{rule}</code> | Time: <code>{ms}ms</code>", True)
    _soar_log("block", ip, f"Block failed: {res.stderr[:40]}", ms, False)
    return _action_page("Block Failed",
        f"Could not block <b>{ip}</b>.<br>{res.stderr or 'Run Flask as Administrator'}", False), 500

@app.route("/soar/unblock-ip", methods=["GET","POST"])
def unblock_ip():
    ip = request.args.get("ip") or (request.get_json(silent=True) or {}).get("ip")
    if not ip:
        return _action_page("Error", "No IP provided.", False), 400
    rule = f"WAZUH_BLOCK_{ip}"
    t0   = time.time()
    res  = subprocess.run(f'netsh advfirewall firewall delete rule name="{rule}"',
                          shell=True, capture_output=True, text=True)
    ms   = round((time.time() - t0) * 1000)
    if res.returncode == 0:
        _soar_log("unblock", ip, f"Firewall rule removed: {rule}", ms, True)
        return _action_page("IP Unblocked",
            f"Rule for <b>{ip}</b> removed.<br>Time: <code>{ms}ms</code>", True)
    _soar_log("unblock", ip, f"No rule found for {ip}", ms, False)
    return _action_page("Unblock Failed", f"No rule for <b>{ip}</b>, or access denied.", False), 404

@app.route("/api/report/pdf")
def download_pdf():
    try:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter,
            topMargin=0.6*inch, bottomMargin=0.6*inch, leftMargin=0.6*inch, rightMargin=0.6*inch)
        styles = getSampleStyleSheet()
        S = {
            "title": ParagraphStyle("T", parent=styles["Title"],   fontSize=20, textColor=colors.HexColor("#1a1a2e"), spaceAfter=4),
            "sub":   ParagraphStyle("S", parent=styles["Normal"],  fontSize=9,  textColor=colors.HexColor("#666"), spaceAfter=12),
            "h2":    ParagraphStyle("H", parent=styles["Heading2"],fontSize=12, textColor=colors.HexColor("#0f3460"), spaceBefore=14, spaceAfter=6),
        }
        story = []
        story.append(Paragraph("WAZUH THREAT HUNTER — SECURITY REPORT", S["title"]))
        story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | CONFIDENTIAL", S["sub"]))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e"), spaceAfter=10))

        nist_pct = get_nist_score()
        story.append(Paragraph("Executive Summary", S["h2"]))
        t_sum = Table([
            ["Metric","Value"],
            ["Total Alerts",          str(metrics_store.get("total",0))],
            ["Critical (L12+)",       str(metrics_store.get("critical",0))],
            ["High (L8-11)",          str(metrics_store.get("high",0))],
            ["Medium (L5-7)",         str(metrics_store.get("medium",0))],
            ["MITRE Techniques",      str(len(mitre_seen))],
            ["NIST Phases Active",    str(sum(1 for v in nist_counts.values() if v>0))],
            ["SOAR Actions",          str(len(soar_activity))],
        ], colWidths=[3.5*inch,3*inch])
        t_sum.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1a1a2e")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f0f4ff")]),
            ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#ccc")),("PADDING",(0,0),(-1,-1),7),
        ]))
        story.append(t_sum); story.append(Spacer(1,10))

        story.append(Paragraph("SOAR Activity Log", S["h2"]))
        soar_rows = [["Time","Action","IP","Duration","Status"]]
        for s in soar_activity[:15]:
            soar_rows.append([s["timestamp"][11:19],s["type"].upper(),s["ip"],f"{s['duration_ms']}ms","OK" if s["success"] else "FAIL"])
        if len(soar_rows)==1: soar_rows.append(["—","No actions yet","—","—","—"])
        t_soar = Table(soar_rows, colWidths=[1*inch,1.2*inch,1.5*inch,1*inch,0.8*inch])
        t_soar.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0f3460")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f5f5ff")]),
            ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#ddd")),("PADDING",(0,0),(-1,-1),5),
        ]))
        story.append(t_soar); story.append(Spacer(1,10))

        story.append(Paragraph("NIST CSF Compliance", S["h2"]))
        nist_rows = [["Phase","Name","Alerts","Coverage"]]
        for k,label in {"ID":"Identify","PR":"Protect","DE":"Detect","RS":"Respond","RC":"Recover"}.items():
            nist_rows.append([k,label,str(nist_counts.get(k,0)),f"{nist_pct.get(k,0)}%"])
        t_nist = Table(nist_rows, colWidths=[0.8*inch,1.8*inch,1.5*inch,1.5*inch])
        t_nist.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#16213e")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#e8f0fe")]),
            ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#ccc")),("PADDING",(0,0),(-1,-1),7),
        ]))
        story.append(t_nist); story.append(Spacer(1,10))

        story.append(Paragraph("Latest 15 Incidents", S["h2"]))
        a_rows = [["Level","Severity","Description","MITRE","NIST","Agent"]]
        for a in alerts_store[:15]:
            a_rows.append([str(a.get("rule_level","?")),a.get("severity","N/A"),
                           str(a.get("rule_desc",""))[:36],a.get("mitre_id","N/A"),
                           a.get("nist_phase","N/A"),str(a.get("agent","N/A"))[:14]])
        sev_c = {"CRITICAL":colors.HexColor("#e74c3c"),"HIGH":colors.HexColor("#e67e22"),
                 "MEDIUM":colors.HexColor("#d4ac0d"),"LOW":colors.HexColor("#27ae60")}
        t_a = Table(a_rows, colWidths=[0.5*inch,0.85*inch,2.6*inch,0.85*inch,0.6*inch,1*inch])
        ast = [("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0f3460")),
               ("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
               ("FONTSIZE",(0,0),(-1,-1),8),
               ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f5f5ff")]),
               ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#ddd")),("PADDING",(0,0),(-1,-1),5)]
        for i,a in enumerate(alerts_store[:15],start=1):
            c = sev_c.get(a.get("severity","LOW"),colors.gray)
            ast += [("TEXTCOLOR",(1,i),(1,i),c),("FONTNAME",(1,i),(1,i),"Helvetica-Bold")]
        t_a.setStyle(TableStyle(ast))
        story.append(t_a); story.append(Spacer(1,16))
        story.append(HRFlowable(width="100%",thickness=1,color=colors.HexColor("#ccc"),spaceAfter=6))
        story.append(Paragraph(f"Wazuh Threat Hunter | github.com/Gattrey0803 | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",S["sub"]))
        doc.build(story)
        buf.seek(0)
        return send_file(buf, mimetype="application/pdf", as_attachment=True,
            download_name=f"wazuh-report-{datetime.utcnow().strftime('%Y%m%d-%H%M')}.pdf")
    except Exception as e:
        app.logger.error(f"[PDF] {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/")
def index(): return render_template("dashboard.html")

@app.route("/api/state")
def api_state():
    state = get_dashboard_state()

    # FIX: inject real SOAR timing into timing array
    if timing_store:
        t = timing_store[0]
        if state["timing"]:
            state["timing"][0].update({
                "email_ms": t.get("email_ms"),
                "block_ms": t.get("block_ms"),
            })

    # FIX: soar_activity and soar_timing for dashboard
    state["soar_activity"] = soar_activity[:50]
    state["soar_timing"] = {
        "last_email_ms": next((s["duration_ms"] for s in soar_activity if s["type"]=="email" and s["success"]), None),
        "last_block_ms": next((s["duration_ms"] for s in soar_activity if s["type"]=="block" and s["success"]), None),
        "total_actions": len(soar_activity),
    }
    return jsonify(state)

@app.route("/api/alerts")
def api_alerts(): return jsonify(alerts_store[:50])

@app.route("/api/metrics")
def api_metrics():
    return jsonify({"metrics":metrics_store,"nist":get_nist_score(),
                    "mitre_count":len(mitre_seen),"status":"LIVE" if wazuh.token else "STANDBY"})

@app.route("/api/refresh")
def api_refresh():
    new_alerts = process_alerts()
    for a in new_alerts:
        if int(a.get("rule_level", a.get("level", 0))) >= SOAR_MIN_LEVEL:
            trigger_n8n(a)
    return jsonify({"ok":True,"new":len(new_alerts),"timestamp":datetime.utcnow().isoformat()})

def background_poller():
    wazuh.authenticate()
    while True:
        try:
            new_alerts = process_alerts()
            for a in new_alerts:
                if int(a.get("rule_level", a.get("level", 0))) >= SOAR_MIN_LEVEL:
                    trigger_n8n(a)
        except Exception as e:
            app.logger.error(f"[Poller] {e}")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    threading.Thread(target=background_poller, daemon=True).start()
    app.logger.info("Wazuh Threat Hunter SOAR v5 starting on :8080")
    app.run(host="0.0.0.0", port=8080, debug=False)