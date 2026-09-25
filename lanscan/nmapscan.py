import shutil
import subprocess
import xml.etree.ElementTree as ET


def nmap_available():
    return shutil.which("nmap") is not None


def deep_scan(ip, ports=None, os_detect=True, timeout=600):
    if not nmap_available():
        return None
    args = ["nmap", "-sV", "-Pn", "-T4", "-oX", "-"]
    if os_detect:
        args.append("-O")
    if ports:
        args += ["-p", ",".join(str(port) for port in ports)]
    args.append(ip)
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None
    return parse_nmap_xml(completed.stdout)


def parse_nmap_xml(xml_text):
    result = {"ports": [], "os": "", "hostname": ""}
    if not xml_text:
        return result
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return result
    host = root.find("host")
    if host is None:
        return result
    hostname = host.find("hostnames/hostname")
    if hostname is not None:
        result["hostname"] = hostname.get("name", "")
    osmatch = host.find("os/osmatch")
    if osmatch is not None:
        name = osmatch.get("name", "")
        accuracy = osmatch.get("accuracy", "")
        result["os"] = f"{name} ({accuracy}%)" if accuracy else name
    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        entry = {
            "port": int(port.get("portid")),
            "protocol": port.get("protocol", "tcp"),
            "service": service.get("name", "") if service is not None else "",
            "product": service.get("product", "") if service is not None else "",
            "version": service.get("version", "") if service is not None else "",
            "extrainfo": service.get("extrainfo", "") if service is not None else "",
        }
        result["ports"].append(entry)
    result["ports"].sort(key=lambda item: item["port"])
    return result
