import asyncio
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .vendors import device_category, lookup_vendor

FALLBACK_PORTS = (80, 443, 22, 445, 139, 3389, 53, 8080, 23, 62078)


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    category: str = ""
    hostname: str = ""

    @property
    def sort_key(self):
        try:
            return tuple(int(part) for part in self.ip.split("."))
        except ValueError:
            return (999, 999, 999, 999)


def arp_scan(targets, timeout=3, iface=None):
    from scapy.all import ARP, Ether, srp

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
    answered, _ = srp(packet, timeout=timeout, verbose=0, iface=iface)
    hosts = {}
    for _, response in answered:
        hosts[response.psrc] = Host(ip=response.psrc, mac=response.hwsrc.lower())
    return list(hosts.values())


def tcp_discovery(targets, ports=FALLBACK_PORTS, timeout=1.0, concurrency=256, progress_cb=None):
    alive = asyncio.run(_run_tcp_discovery(targets, ports, timeout, concurrency, progress_cb))
    hosts = [Host(ip=ip) for ip in alive]
    enrich_from_arp_cache(hosts)
    return hosts


async def _run_tcp_discovery(targets, ports, timeout, concurrency, progress_cb):
    semaphore = asyncio.Semaphore(concurrency)
    alive = []

    async def worker(ip):
        async with semaphore:
            up = await _host_alive(ip, ports, timeout)
        if progress_cb:
            progress_cb()
        if up:
            alive.append(ip)

    await asyncio.gather(*(worker(ip) for ip in targets))
    alive.sort(key=lambda ip: tuple(int(part) for part in ip.split(".")))
    return alive


async def _host_alive(ip, ports, timeout):
    for port in ports:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except ConnectionRefusedError:
            return True
        except (asyncio.TimeoutError, OSError):
            continue
    return False


def enrich(hosts, resolve_names=True):
    for host in hosts:
        if host.mac:
            host.vendor = lookup_vendor(host.mac)
            host.category = device_category(host.vendor)
    if resolve_names and hosts:
        previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)
        try:
            with ThreadPoolExecutor(max_workers=min(32, len(hosts))) as executor:
                names = list(executor.map(resolve_hostname, [host.ip for host in hosts]))
            for host, name in zip(hosts, names):
                host.hostname = name
        finally:
            socket.setdefaulttimeout(previous)
    return hosts


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def enrich_from_arp_cache(hosts):
    table = read_arp_cache()
    for host in hosts:
        if not host.mac and host.ip in table:
            host.mac = table[host.ip]
    return hosts


def read_arp_cache():
    if platform.system() == "Linux":
        return _read_proc_arp()
    return _read_arp_command()


def _read_proc_arp():
    table = {}
    try:
        with open("/proc/net/arp") as handle:
            lines = handle.read().splitlines()[1:]
    except OSError:
        return table
    for line in lines:
        parts = line.split()
        if len(parts) >= 4:
            ip, flags, mac = parts[0], parts[2], parts[3]
            if mac != "00:00:00:00:00:00" and flags != "0x0":
                table[ip] = mac.lower()
    return table


def _read_arp_command():
    table = {}
    try:
        output = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5
        ).stdout
    except Exception:
        return table
    pattern = re.compile(
        r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
    )
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            table[match.group(1)] = match.group(2).lower().replace("-", ":")
    return table
