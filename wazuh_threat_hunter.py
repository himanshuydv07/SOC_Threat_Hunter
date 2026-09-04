import os, time, logging, requests, urllib3
from datetime import datetime
from dotenv import load_dotenv
from mitre_mapper import get_mitre_tag

urllib3.disable_warnings()
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ThreatHunter")

WAZUH_API  = os.getenv("WAZUH_API_URL", "https://localhost:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_PASS", "MyS3cr37P450r.*-")

NIST_MAP  = {"CRITICAL":"RS","HIGH":"DE","MEDIUM":"PR","LOW":"ID"}
NIST_FULL = {"ID":"Identify","PR":"Protect","DE":"Detect","RS":"Respond","RC":"Recover"}

alerts_store  = []
metrics_store = {"total":0,"critical":0,"high":0,"medium":0,"low":0}
nist_counts   = {"ID":0,"PR":0,"DE":0,"RS":0,"RC":0}
mitre_seen    = set()
timing_store  = []
_seen_alert_ids = set()

def get_severity(level):
    try:
        l = int(level)
        if l >= 12: return "CRITICAL"
        if l >= 8:  return "HIGH"
        if l >= 5:  return "MEDIUM"
        return "LOW"
    except:
        return "MEDIUM"

def rule_triage(alert):
    t0    = time.time()
    desc  = alert.get("description", alert.get("message", "Unknown"))
    level = alert.get("level", 3)
    sev   = get_severity(level)
    mitre_id, mitre_name, mitre_tactic = get_mitre_tag(desc)
    nist_phase = NIST_MAP.get(sev, "DE")
    actions = {
        "CRITICAL": "Isolate endpoint + block IP",
        "HIGH":     "Investigate + monitor",
        "MEDIUM":   "Review logs",
        "LOW":      "Log and monitor"
    }
    return {
        "severity":           sev,
        "summary":            desc[:80],
        "mitre_id":           mitre_id,
        "mitre_name":         mitre_name,
        "mitre_tactic":       mitre_tactic,
        "nist_phase":         nist_phase,
        "recommended_action": actions.get(sev, "Investigate"),
        "triage_ms":          round((time.time() - t0) * 1000)
    }

class WazuhClient:
    def __init__(self):
        self.token = None
        self.token_expiry = 0

    def authenticate(self):
        try:
            r = requests.post(f"{WAZUH_API}/security/user/authenticate",
                              auth=(WAZUH_USER, WAZUH_PASS), verify=False, timeout=10)
            r.raise_for_status()
            self.token = r.json()["data"]["token"]
            self.token_expiry = time.time() + 800
            log.info("Wazuh auth OK")
            return True
        except Exception as e:
            log.error(f"Wazuh auth failed: {e}")
            return False

    def headers(self):
        if time.time() > self.token_expiry:
            self.authenticate()
        return {"Authorization": f"Bearer {self.token}"}

    def get_alerts(self, limit=20):
        try:
            r = requests.get(f"{WAZUH_API}/manager/logs", headers=self.headers(),
                             params={"limit": limit, "sort": "-timestamp"}, verify=False, timeout=15)
            r.raise_for_status()
            return r.json().get("data", {}).get("affected_items", [])
        except Exception as e:
            log.error(f"Fetch alerts failed: {e}")
            return []

    def get_agents(self):
        try:
            r = requests.get(f"{WAZUH_API}/agents", headers=self.headers(),
                             params={"limit": 50}, verify=False, timeout=15)
            r.raise_for_status()
            return r.json().get("data", {}).get("affected_items", [])
        except:
            return []

    def get_sca(self, agent_id):
        try:
            r = requests.get(f"{WAZUH_API}/sca/{agent_id}", headers=self.headers(),
                             verify=False, timeout=15)
            r.raise_for_status()
            return r.json().get("data", {}).get("affected_items", [])
        except:
            return []

    def get_fim(self, agent_id):
        try:
            r = requests.get(f"{WAZUH_API}/syscheck/{agent_id}", headers=self.headers(),
                             params={"limit": 10}, verify=False, timeout=15)
            r.raise_for_status()
            return r.json().get("data", {}).get("affected_items", [])
        except:
            return []

wazuh = WazuhClient()

def process_alerts():
    global alerts_store, _seen_alert_ids
    if not wazuh.token:
        if not wazuh.authenticate():
            return []
    t0       = time.time()
    raw_list = wazuh.get_alerts(limit=20)
    if not raw_list:
        log.info("No alerts from Wazuh")
        return []

    new_alerts = []
    for raw in raw_list:
        aid = raw.get("timestamp", "") + raw.get("description", "")[:30]
        if aid in _seen_alert_ids:
            continue
        _seen_alert_ids.add(aid)
        if len(_seen_alert_ids) > 2000:
            oldest = list(_seen_alert_ids)[:500]
            for k in oldest: _seen_alert_ids.discard(k)

        triage = rule_triage(raw)
        sev    = triage["severity"]
        metrics_store["total"] += 1
        metrics_store[sev.lower()] = metrics_store.get(sev.lower(), 0) + 1
        np = triage["nist_phase"]
        nist_counts[np] = nist_counts.get(np, 0) + 1
        mitre_seen.add(triage["mitre_id"])

        # FIX: srcip stored in BOTH agent_ip AND srcip so dashboard ML works
        srcip = raw.get("agent_ip", raw.get("srcip", "127.0.0.1"))

        alert_obj = {
            "id":                 aid,
            "timestamp":          raw.get("timestamp", datetime.utcnow().isoformat()),
            "agent":              raw.get("tag", "manager"),
            "agent_ip":           srcip,
            "srcip":              srcip,   # FIX: dashboard ML uses srcip
            "rule_desc":          raw.get("description", ""),
            "rule_level":         raw.get("level", 0),
            "severity":           sev,
            "summary":            triage["summary"],
            "mitre_id":           triage["mitre_id"],
            "mitre_name":         triage["mitre_name"],
            "mitre_tactic":       triage["mitre_tactic"],
            "nist_phase":         np,
            "nist_label":         NIST_FULL.get(np, np),
            "recommended_action": triage["recommended_action"],
            "triage_ms":          triage["triage_ms"],
            "pipeline_ms":        round((time.time() - t0) * 1000),
        }
        alerts_store.insert(0, alert_obj)
        new_alerts.append(alert_obj)

    alerts_store = alerts_store[:200]
    pipeline_ms  = round((time.time() - t0) * 1000)

    timing_store.insert(0, {
        "timestamp":        datetime.utcnow().isoformat(),
        "alerts_processed": len(new_alerts),
        "pipeline_ms":      pipeline_ms,
        "email_ms":         None,  # filled by app.py after n8n
        "block_ms":         None,  # filled by app.py after firewall
    })
    timing_store[:] = timing_store[:50]

    log.info(f"process_alerts: {len(new_alerts)} new | {pipeline_ms}ms")
    return new_alerts

def get_endpoint_data():
    agents = wazuh.get_agents()
    result = []
    for a in agents[:10]:
        aid = a.get("id", "000")
        if aid == "000": continue
        fim = wazuh.get_fim(aid)
        result.append({
            "id":         aid,
            "name":       a.get("name", "unknown"),
            "ip":         a.get("ip", "N/A"),
            "os":         a.get("os", {}).get("name", "N/A"),
            "status":     a.get("status", "disconnected"),
            "last_seen":  a.get("lastKeepAlive", "N/A"),
            "fim_events": len(fim)
        })
    return result

def get_server_security_data():
    agents = wazuh.get_agents()
    result = []
    for a in agents[:5]:
        aid = a.get("id", "000")
        if aid == "000": continue
        sca       = wazuh.get_sca(aid)
        sca_score = 0
        if sca:
            sca_score = round((sca[0].get("pass", 0) / max(sca[0].get("total_checks", 1), 1)) * 100)
        result.append({
            "agent_id":      aid,
            "agent_name":    a.get("name", "unknown"),
            "sca_score":     sca_score,
            "sca_policy":    sca[0].get("name", "N/A") if sca else "N/A",
            "vuln_count":    0,
            "critical_vulns": []
        })
    return result

def get_nist_score():
    total = sum(nist_counts.values())
    if total == 0:
        return {k: 0 for k in nist_counts}
    return {k: round((v / total) * 100) for k, v in nist_counts.items()}

def get_dashboard_state():
    return {
        "metrics":         metrics_store,
        "mitre_count":     len(mitre_seen),
        "alerts":          alerts_store[:50],
        "nist_scores":     get_nist_score(),
        "nist_counts":     nist_counts,
        "timing":          timing_store[:10],
        "endpoints":       get_endpoint_data(),
        "server_security": get_server_security_data(),
        "status":          "LIVE" if wazuh.token else "STANDBY",
        "last_update":     datetime.utcnow().isoformat(),
    }