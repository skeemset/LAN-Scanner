import argparse

from . import __version__, discovery, export, network, ports


def build_parser():
    parser = argparse.ArgumentParser(
        prog="lanscan",
        description="LAN Scanner - разведка локальной сети (без аргументов запускается меню)",
    )
    parser.add_argument("--discover", metavar="CIDR", nargs="?", const="auto",
                        help="обнаружить устройства (по умолчанию - ваша подсеть)")
    parser.add_argument("--scan", metavar="IP", help="сканировать порты указанного хоста")
    parser.add_argument("--ports", default="top",
                        help="top | full | список, например 22,80,8000-8100")
    parser.add_argument("--timeout", type=float, default=1.0, help="таймаут на порт, сек")
    parser.add_argument("--no-banner", action="store_true", help="не захватывать баннеры")
    parser.add_argument("--json", metavar="FILE", help="сохранить результат в JSON")
    parser.add_argument("--version", action="version", version=f"LAN Scanner {__version__}")
    return parser


def resolve_ports(text):
    if text == "top":
        return list(ports.TOP_PORTS)
    if text == "full":
        return list(range(1, 65536))
    return ports.parse_ports(text)


def run(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.discover and not args.scan:
        return None

    hosts = []
    scans = {}

    if args.discover:
        target = network.detect_cidr() if args.discover == "auto" else args.discover
        targets = network.parse_target(target)
        print(f"[*] Обнаружение устройств в {target} ...")
        if network.is_root():
            try:
                hosts = discovery.arp_scan(targets)
            except Exception:
                hosts = []
            if not hosts:
                hosts = discovery.tcp_discovery(targets)
        else:
            hosts = discovery.tcp_discovery(targets)
        discovery.enrich(hosts)
        hosts.sort(key=lambda host: host.sort_key)
        _print_hosts(hosts)

    if args.scan:
        selected = resolve_ports(args.ports)
        print(f"[*] Сканирование {args.scan} ({len(selected)} портов) ...")
        results = ports.scan_ports(
            args.scan, selected, timeout=args.timeout, grab=not args.no_banner
        )
        scans[args.scan] = results
        _print_ports(args.scan, results)

    if args.json:
        export.export_results(args.json, hosts, scans)
        print(f"[+] Сохранено: {args.json}")

    return 0


def _print_hosts(hosts):
    if not hosts:
        print("    устройств не найдено")
        return
    print(f"[+] Найдено устройств: {len(hosts)}")
    print(f"    {'IP':<15} {'MAC':<18} {'Тип':<26} Вендор / хост")
    for host in hosts:
        name = f" ({host.hostname})" if host.hostname else ""
        print(
            f"    {host.ip:<15} {host.mac or '-':<18} "
            f"{host.category or '-':<26} {host.vendor or '-'}{name}"
        )


def _print_ports(ip, results):
    if not results:
        print(f"[-] На {ip} открытых портов не найдено")
        return
    print(f"[+] Открытые порты на {ip}: {len(results)}")
    for item in results:
        version = f" [{item.version_text}]" if item.version_text else ""
        banner = f"  {item.banner}" if item.banner else ""
        print(f"    {item.port:<6}/tcp {item.service:<16}{version}{banner}")
