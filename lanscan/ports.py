import asyncio
import ssl
from dataclasses import dataclass

from .fingerprint import fingerprint, version_label

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 123, 135, 137, 139, 143, 161, 389,
    443, 445, 465, 500, 515, 587, 631, 636, 993, 995, 1080, 1194, 1433, 1521,
    1723, 1883, 1900, 2049, 2082, 2083, 2375, 3000, 3128, 3306, 3389, 5000,
    5060, 5222, 5353, 5432, 5555, 5601, 5900, 5985, 6379, 7070, 8000, 8006,
    8008, 8080, 8081, 8086, 8123, 8443, 8888, 9000, 9090, 9200, 10000, 11211,
    27017, 32400, 49152, 51820,
]

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    81: "http-alt", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 500: "isakmp",
    515: "printer", 587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "ms-sql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 1900: "upnp", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2375: "docker", 3000: "http-dev", 3128: "http-proxy",
    3306: "mysql", 3389: "ms-wbt-server", 5000: "upnp-http", 5060: "sip",
    5222: "xmpp", 5353: "mdns", 5432: "postgresql", 5555: "adb", 5601: "kibana",
    5900: "vnc", 5985: "wsman", 6379: "redis", 7070: "realserver",
    8000: "http-alt", 8006: "proxmox", 8008: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8086: "influxdb", 8123: "home-assistant", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch",
    10000: "webmin", 11211: "memcached", 27017: "mongodb", 32400: "plex",
    49152: "upnp", 51820: "wireguard",
}

NOTES = {
    21: "FTP - данные и пароли передаются без шифрования",
    23: "Telnet - трафик без шифрования",
    25: "SMTP - почтовый сервер",
    80: "HTTP - без TLS",
    110: "POP3 - без шифрования",
    111: "RPC - часто раскрывает внутренние сервисы",
    135: "MSRPC - доступ к службам Windows",
    139: "NetBIOS - устаревший общий доступ Windows",
    143: "IMAP - без шифрования",
    161: "SNMP - часто открыт с community 'public'",
    445: "SMB - общий доступ к файлам Windows",
    512: "rexec - устаревший удалённый вызов",
    513: "rlogin - устаревший удалённый вход",
    1433: "MS SQL - СУБД Microsoft",
    2049: "NFS - сетевая файловая система",
    2375: "Docker API - без TLS, полный контроль над хостом",
    3306: "MySQL/MariaDB - СУБД",
    3389: "RDP - удалённый рабочий стол Windows",
    5432: "PostgreSQL - СУБД",
    5555: "ADB - отладочный доступ Android",
    5900: "VNC - удалённый доступ к экрану",
    6379: "Redis - часто без аутентификации по умолчанию",
    9200: "Elasticsearch - часто без аутентификации",
    11211: "Memcached - без аутентификации, риск усиления DDoS",
    27017: "MongoDB - исторически без аутентификации по умолчанию",
}

HTTP_PORTS = {80, 81, 591, 2082, 3000, 3128, 5000, 5601, 8000, 8006, 8008,
              8080, 8081, 8086, 8123, 8888, 9000, 9090, 10000}
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443, 2083}


@dataclass
class OpenPort:
    port: int
    service: str
    banner: str = ""
    product: str = ""
    version: str = ""

    @property
    def version_text(self):
        return version_label(self.product, self.version)

    @property
    def note(self):
        return NOTES.get(self.port, "")


def service_name(port):
    return SERVICES.get(port, "unknown")


def parse_ports(text):
    result = set()
    for chunk in (text or "").replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            start_text, _, end_text = chunk.partition("-")
            result.update(range(int(start_text), int(end_text) + 1))
        else:
            result.add(int(chunk))
    return sorted(port for port in result if 1 <= port <= 65535)


def scan_ports(ip, ports, timeout=1.0, concurrency=500, grab=True, progress_cb=None):
    return asyncio.run(_scan_all(ip, ports, timeout, concurrency, grab, progress_cb))


async def _scan_all(ip, ports, timeout, concurrency, grab, progress_cb):
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(_scan_one(ip, port, timeout, grab, semaphore)) for port in ports]
    results = []
    for task in asyncio.as_completed(tasks):
        result = await task
        if progress_cb:
            progress_cb()
        if result:
            results.append(result)
    results.sort(key=lambda item: item.port)
    return results


async def _scan_one(ip, port, timeout, grab, semaphore):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except (asyncio.TimeoutError, OSError):
            return None
        banner = ""
        if grab:
            banner = await _grab_banner(ip, port, reader, writer, timeout)
        else:
            _close(writer)
    entry = OpenPort(port=port, service=service_name(port), banner=banner)
    entry.product, entry.version = fingerprint(port, banner)
    return entry


async def _grab_banner(ip, port, reader, writer, timeout):
    try:
        if port in TLS_PORTS:
            _close(writer)
            return await _tls_info(ip, port, timeout)
        if port in HTTP_PORTS:
            writer.write(
                f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: lanscan\r\n\r\n".encode()
            )
            await writer.drain()
        elif port == 6379:
            writer.write(b"INFO\r\n")
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        _close(writer)
        if port == 3306:
            return _mysql_banner(data)
        if port == 6379:
            return _redis_banner(data)
        return _format_banner(data)
    except Exception:
        _close(writer)
        return ""


async def _tls_info(ip, port, timeout):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context, server_hostname=ip),
            timeout=timeout,
        )
    except Exception:
        return "TLS/SSL"
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        _close(writer)
        if ssl_object:
            version = ssl_object.version() or "TLS"
            cipher = ssl_object.cipher()
            return f"{version} | {cipher[0]}" if cipher else version
        return "TLS/SSL"
    except Exception:
        return "TLS/SSL"


def _mysql_banner(data):
    if len(data) > 5 and data[4] == 0x0A:
        try:
            end = data.index(0, 5)
            version = data[5:end].decode("latin-1", "replace")
            product = "MariaDB" if "mariadb" in version.lower() else "MySQL"
            return f"{product} {version}"
        except ValueError:
            pass
    return _format_banner(data)


def _redis_banner(data):
    text = data.decode("latin-1", "replace")
    for line in text.splitlines():
        if line.startswith("redis_version:"):
            return line.strip()
    if text.startswith("-NOAUTH") or "NOAUTH" in text:
        return "Redis (-NOAUTH: требуется аутентификация)"
    return _format_banner(data)


def _format_banner(data):
    if not data:
        return ""
    text = data.decode("latin-1", "replace")
    if text.startswith("HTTP"):
        lines = text.split("\r\n")
        status = lines[0].strip()
        server = ""
        for line in lines[1:]:
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
        return f"{status} | Server: {server}" if server else status
    return " ".join(text.split())[:160]


def _close(writer):
    try:
        writer.close()
    except Exception:
        pass
