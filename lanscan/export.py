import json
from datetime import datetime


def build_report(hosts, scans):
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "hosts": [
            {
                "ip": host.ip,
                "mac": host.mac,
                "vendor": host.vendor,
                "category": host.category,
                "hostname": host.hostname,
            }
            for host in hosts
        ],
        "port_scans": {
            ip: [
                {
                    "port": item.port,
                    "service": item.service,
                    "version": item.version_text,
                    "banner": item.banner,
                    "note": item.note,
                }
                for item in ports
            ]
            for ip, ports in scans.items()
        },
    }


def export_results(path, hosts, scans):
    report = build_report(hosts, scans)
    if path.lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
    else:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(_render_text(report))
    return path


def _render_text(report):
    lines = ["LAN Scanner report", f"Generated: {report['generated_at']}", "", "Hosts:"]
    if report["hosts"]:
        for host in report["hosts"]:
            lines.append(
                f"  {host['ip']:<15} {host['mac'] or '-':<17} "
                f"{host['category'] or '-':<28} {host['vendor'] or '-'}"
            )
            if host["hostname"]:
                lines.append(f"  {'':<15} hostname: {host['hostname']}")
    else:
        lines.append("  (нет данных)")
    lines.append("")
    lines.append("Port scans:")
    if report["port_scans"]:
        for ip, ports in report["port_scans"].items():
            lines.append(f"  {ip}:")
            for item in ports:
                version = f" [{item['version']}]" if item["version"] else ""
                banner = f"  {item['banner']}" if item["banner"] else ""
                lines.append(f"    {item['port']:<6} {item['service']:<16}{version}{banner}")
    else:
        lines.append("  (нет данных)")
    lines.append("")
    return "\n".join(lines)
