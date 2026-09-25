import re

_RULES = [
    (re.compile(r"OpenSSH[_/-]([\w.]+)", re.I), "OpenSSH"),
    (re.compile(r"dropbear[_/-]?([\d.]+)?", re.I), "Dropbear SSH"),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I), "Microsoft IIS"),
    (re.compile(r"\bnginx/([\d.]+)", re.I), "nginx"),
    (re.compile(r"\bnginx\b", re.I), "nginx"),
    (re.compile(r"Apache/([\d.]+)", re.I), "Apache httpd"),
    (re.compile(r"\bApache\b", re.I), "Apache httpd"),
    (re.compile(r"lighttpd/([\d.]+)", re.I), "lighttpd"),
    (re.compile(r"gunicorn/([\d.]+)", re.I), "gunicorn"),
    (re.compile(r"Werkzeug/([\d.]+)", re.I), "Werkzeug"),
    (re.compile(r"Boa/([\d.]+)", re.I), "Boa httpd"),
    (re.compile(r"vsFTPd\s*([\d.]+)?", re.I), "vsftpd"),
    (re.compile(r"ProFTPD\s*([\d.]+)?", re.I), "ProFTPD"),
    (re.compile(r"Pure-FTPd", re.I), "Pure-FTPd"),
    (re.compile(r"FileZilla Server\s*(?:v)?([\d.]+)?", re.I), "FileZilla Server"),
    (re.compile(r"Postfix", re.I), "Postfix"),
    (re.compile(r"Exim\s*([\d.]+)?", re.I), "Exim"),
    (re.compile(r"Sendmail", re.I), "Sendmail"),
    (re.compile(r"Dovecot", re.I), "Dovecot"),
    (re.compile(r"MariaDB\s*([\d.]+)?", re.I), "MariaDB"),
    (re.compile(r"MySQL\s*([\d.]+)?", re.I), "MySQL"),
    (re.compile(r"PostgreSQL\s*([\d.]+)?", re.I), "PostgreSQL"),
    (re.compile(r"redis_version:([\d.]+)", re.I), "Redis"),
    (re.compile(r"-NOAUTH", re.I), "Redis"),
    (re.compile(r"MongoDB", re.I), "MongoDB"),
    (re.compile(r"RabbitMQ", re.I), "RabbitMQ"),
    (re.compile(r"Samba\s*([\d.]+)?", re.I), "Samba"),
    (re.compile(r"RouterOS", re.I), "MikroTik RouterOS"),
    (re.compile(r"\(RomPager/([\d.]+)\)", re.I), "RomPager"),
]

_GENERIC = re.compile(r"([A-Za-z][\w+.\-]{1,30})/([\d][\w.]*)")
_VERSION = re.compile(r"(\d+\.\d+(?:\.\d+)*)")


def fingerprint(port, banner):
    if not banner:
        return "", ""
    text = banner.strip()
    for pattern, product in _RULES:
        match = pattern.search(text)
        if not match:
            continue
        version = match.group(1) if match.groups() and match.group(1) else ""
        if not version:
            tail = _VERSION.search(text[match.end():match.end() + 24])
            if tail:
                version = tail.group(1)
        return product, version
    generic = _GENERIC.search(text)
    if generic:
        return generic.group(1), generic.group(2)
    return "", ""


def version_label(product, version):
    if product and version:
        return f"{product} {version}"
    return product or ""
