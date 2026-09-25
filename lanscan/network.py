import ipaddress
import os
import socket


def primary_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def detect_cidr(ip=None):
    ip = ip or primary_ip()
    prefix = _detect_prefix(ip)
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _detect_prefix(ip):
    try:
        from scapy.all import conf

        target = int(ipaddress.IPv4Address(ip))
        best = None
        for entry in conf.route.routes:
            net, mask = entry[0], entry[1]
            if mask in (0, 0xFFFFFFFF):
                continue
            if (target & mask) == (net & mask):
                length = bin(mask).count("1")
                if best is None or length > best:
                    best = length
        if best:
            return best
    except Exception:
        pass
    return 24


def parse_target(text):
    text = (text or "").strip()
    if not text:
        raise ValueError("Пустое значение цели")
    if "/" in text:
        network = ipaddress.ip_network(text, strict=False)
        return [str(host) for host in network.hosts()] or [str(network.network_address)]
    if "-" in text:
        base, _, tail = text.rpartition(".")
        start_text, _, end_text = tail.partition("-")
        start, end = int(start_text), int(end_text)
        if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
            raise ValueError("Некорректный диапазон октетов")
        ipaddress.ip_address(f"{base}.{start}")
        return [f"{base}.{octet}" for octet in range(start, end + 1)]
    ipaddress.ip_address(text)
    return [text]


def is_root():
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes

        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False
