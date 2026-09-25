def os_from_ttl(ttl):
    if ttl is None:
        return ""
    if ttl <= 64:
        return "Linux / Unix / Android"
    if ttl <= 128:
        return "Windows"
    return "Сетевое устройство / роутер"


def probe_ttl(ip, timeout=2):
    try:
        from scapy.all import ICMP, IP, sr1

        reply = sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=0)
        if reply is not None:
            return int(reply.ttl)
    except Exception:
        pass
    return None


def os_hint(ip, timeout=2):
    ttl = probe_ttl(ip, timeout)
    label = os_from_ttl(ttl)
    if ttl is None:
        return ""
    return f"{label} (TTL {ttl})"
