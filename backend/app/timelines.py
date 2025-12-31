def build_attack_timeline(events):
    timeline = []

    for e in events:
        if e.ip:
            timeline.append({
                "time": str(e.timestamp),
                "ip": e.ip,
                "action": e.action,
                "status": e.status
            })

    return timeline[:50]  # cap for sanity


def build_narrative(timeline):
    if not timeline:
        return "No suspicious activity detected."

    first = timeline[0]
    last = timeline[-1]

    return (
        f"Between {first['time']} and {last['time']}, multiple suspicious "
        f"requests were observed. Attack patterns include authentication abuse, "
        f"endpoint probing, and possible exploitation attempts."
    )
