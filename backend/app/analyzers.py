from collections import defaultdict, Counter
from datetime import timedelta
from app.intelligence import classify_endpoint
from app.timelines import build_attack_timeline, build_narrative

def analyze_events(events, log_type):
    ip_stats = defaultdict(list)
    intent_hits = defaultdict(lambda: defaultdict(int))
    findings = []

    for e in events:
        if e.ip:
            ip_stats[e.ip].append(e)
            intent = classify_endpoint(e.action)
            intent_hits[e.ip][intent] += 1

    for ip, evs in ip_stats.items():
        evs_sorted = sorted(evs, key=lambda x: x.timestamp or 0)
        window = []
        for e in evs_sorted:
            if e.status == "FAILED":
                window.append(e)
                window = [x for x in window if e.timestamp and x.timestamp and
                          e.timestamp - x.timestamp <= timedelta(minutes=1)]
                if len(window) >= 5:
                    findings.append({
                        "type": "brute_force",
                        "ip": ip,
                        "attempts": len(window),
                        "severity": 7,
                        "confidence": 0.85,
                        "evidence": [x.raw for x in window[-3:]]
                    })
                    break

    dangerous = {"recon", "auth_attack", "exploit"}
    for ip, intents in intent_hits.items():
        hit = dangerous.intersection(intents.keys())
        if len(hit) >= 2:
            findings.append({
                "type": "attack_chain_detected",
                "ip": ip,
                "intents": list(hit),
                "severity": 9,
                "confidence": 0.9,
                "evidence": dict(intents)
            })

    for ip, evs in ip_stats.items():
        had_fail = any(e.status == "FAILED" for e in evs)
        had_success = any(e.status in ["SUCCESS", "200"] for e in evs)
        if had_fail and had_success:
            findings.append({
                "type": "possible_compromise",
                "ip": ip,
                "severity": 10,
                "confidence": 0.95,
                "evidence": [e.raw for e in evs[-3:]]
            })

    risk_score = min(100, sum(f["severity"] * 10 for f in findings))
    risk_level = "LOW"
    if risk_score >= 40:
        risk_level = "MEDIUM"
    if risk_score >= 70:
        risk_level = "HIGH"

    timeline = build_attack_timeline(events)
    narrative = build_narrative(timeline)

    return {
        "log_type": log_type,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary": narrative,
        "findings": findings,
        "top_suspicious_ips": Counter([f["ip"] for f in findings]).most_common(5),
        "statistics": {
            "total_events": len(events),
            "unique_ips": len(ip_stats),
            "attackers": len(set(f["ip"] for f in findings))
        },
        "timeline": timeline
    }
