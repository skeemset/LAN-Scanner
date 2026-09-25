from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from . import __version__, discovery, export, network, nmapscan, osdetect, ports, vendors


class App:
    def __init__(self):
        self.console = Console()
        self.hosts = []
        self.scans = {}
        self.database_ready = False

    def run(self):
        while True:
            choice = self._menu()
            if choice == "1":
                self._host_discovery()
            elif choice == "2":
                self._port_scan()
            elif choice == "3":
                self._show_hosts()
            elif choice == "4":
                self._export()
            elif choice == "0":
                self.console.clear()
                self.console.print("[dim]Работа завершена. До встречи.[/]")
                return

    def _header(self):
        self.console.clear()
        title = Text("L A N   S C A N N E R", style="bold cyan")
        subtitle = Text("Разведка локальной сети", style="dim")
        version = Text(f"v{__version__}", style="dim cyan")
        self.console.print(
            Panel(
                Align.center(Text.assemble(title, "\n", subtitle, "   ", version)),
                box=box.ROUNDED,
                border_style="cyan",
                padding=(1, 4),
            )
        )
        self.console.print()

    def _menu(self):
        self._header()
        grid = Table.grid(padding=(0, 3))
        grid.add_column(justify="right", style="bold cyan")
        grid.add_column()
        grid.add_row("1", "Host Discovery - обнаружение устройств в сети")
        grid.add_row("2", "Port Scan - сканирование портов устройства")
        grid.add_row("3", "Показать результаты последнего обнаружения")
        grid.add_row("4", "Экспорт результатов в файл")
        grid.add_row("0", "Выход")
        self.console.print(Panel(grid, title="Главное меню", border_style="cyan", box=box.ROUNDED))
        self.console.print(self._status_line())
        return Prompt.ask("\n[bold cyan]Ваш выбор[/]", choices=["1", "2", "3", "4", "0"], default="1")

    def _status_line(self):
        privilege = "root" if network.is_root() else "без root (TCP-режим)"
        nmap = "nmap: есть" if nmapscan.nmap_available() else "nmap: нет"
        if not self.hosts:
            base = "[dim]Устройств пока нет - начните с Host Discovery.[/]"
        else:
            base = (
                f"[dim]Устройств: [cyan]{len(self.hosts)}[/cyan]   "
                f"Просканировано: [cyan]{len(self.scans)}[/cyan][/]"
            )
        return f"{base}   [dim]|  {privilege}  |  {nmap}[/]"

    def _ensure_database(self):
        if self.database_ready:
            return
        with self.console.status("[cyan]Подготовка базы вендоров...[/]", spinner="dots"):
            vendors.prepare_database()
        self.database_ready = True

    def _host_discovery(self):
        self._header()
        self.console.print("[bold]Host Discovery[/] - обнаружение активных устройств\n")
        default_cidr = network.detect_cidr()
        target_text = Prompt.ask(
            "Введите диапазон для сканирования (CIDR, например 192.168.1.0/24)",
            default=default_cidr,
        )
        try:
            targets = network.parse_target(target_text)
        except Exception:
            self.console.print("\n[red]Некорректный формат цели. Пример: 192.168.1.0/24[/]")
            return self._pause()

        if len(targets) > 8192 and not Confirm.ask(
            f"\n[yellow]Цель содержит {len(targets)} адресов. Продолжить?[/]", default=False
        ):
            return

        self._ensure_database()

        if network.is_root():
            try:
                with self.console.status(f"[cyan]ARP-сканирование {target_text}...[/]", spinner="dots"):
                    found = discovery.arp_scan(targets)
            except Exception:
                found = []
            if not found:
                self.console.print("[yellow]ARP недоступен или устройств не найдено. Пробую TCP-обнаружение...[/]")
                found = self._tcp_discovery(targets)
        else:
            self.console.print(
                Panel(
                    "Запуск без прав root: ARP-скан недоступен.\n"
                    "Используется TCP-обнаружение (MAC берётся из ARP-кеша, если доступен).\n"
                    "Для полного ARP-скана запустите с [bold]sudo[/].",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )
            found = self._tcp_discovery(targets)

        with self.console.status("[cyan]Определение вендоров и имён хостов...[/]", spinner="dots"):
            discovery.enrich(found)

        found.sort(key=lambda host: host.sort_key)
        self.hosts = found
        self._render_hosts()
        self._pause()

    def _tcp_discovery(self, targets):
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]TCP-обнаружение[/]"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            task = progress.add_task("discovery", total=len(targets))
            found = discovery.tcp_discovery(targets, progress_cb=lambda: progress.advance(task))
        return found

    def _render_hosts(self):
        if not self.hosts:
            self.console.print("\n[yellow]Активных устройств не найдено.[/]")
            return
        table = Table(
            title=f"Найдено устройств: {len(self.hosts)}",
            box=box.SIMPLE_HEAVY,
            border_style="cyan",
            header_style="bold cyan",
        )
        table.add_column("№", justify="right", style="dim")
        table.add_column("IP-адрес", style="bold")
        table.add_column("MAC")
        table.add_column("Вендор")
        table.add_column("Тип устройства", style="green")
        table.add_column("Имя хоста", style="dim")
        for index, host in enumerate(self.hosts, start=1):
            table.add_row(
                str(index), host.ip, host.mac or "-", host.vendor or "-",
                host.category or "Неизвестно", host.hostname or "-",
            )
        self.console.print()
        self.console.print(table)

    def _show_hosts(self):
        self._header()
        self.console.print("[bold]Результаты последнего обнаружения[/]\n")
        self._render_hosts()
        self._pause()

    def _port_scan(self):
        self._header()
        self.console.print("[bold]Port Scan[/] - сканирование портов устройства\n")
        target_ip = self._choose_host()
        if not target_ip:
            return

        selected_ports = self._choose_ports()
        if not selected_ports:
            self.console.print("[red]Список портов пуст.[/]")
            return self._pause()

        timeout = self._ask_float("Таймаут на порт, сек", 1.0)
        grab = Confirm.ask("Захватывать баннеры и версии сервисов?", default=True)

        self.console.print(
            f"\n[dim]Цель: [cyan]{target_ip}[/cyan]   Портов: [cyan]{len(selected_ports)}[/cyan]"
            f"   Таймаут: [cyan]{timeout}s[/cyan][/]\n"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Сканирование портов[/]"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            task = progress.add_task("scan", total=len(selected_ports))
            results = ports.scan_ports(
                target_ip, selected_ports, timeout=timeout, grab=grab,
                progress_cb=lambda: progress.advance(task),
            )

        os_line = ""
        if network.is_root():
            with self.console.status("[cyan]Определение ОС (TTL)...[/]", spinner="dots"):
                os_line = osdetect.os_hint(target_ip)

        if results and nmapscan.nmap_available() and Confirm.ask(
            "\nЗапустить глубокое сканирование nmap (-sV, версии сервисов)?", default=False
        ):
            os_line = self._deep_scan(target_ip, results, os_line)

        self.scans[target_ip] = results
        self._render_ports(target_ip, results, len(selected_ports), os_line)
        self._pause()

    def _deep_scan(self, ip, results, os_line):
        open_ports = [item.port for item in results]
        with self.console.status("[cyan]nmap -sV выполняется, это может занять время...[/]", spinner="dots"):
            report = nmapscan.deep_scan(ip, open_ports, os_detect=network.is_root())
        if not report:
            self.console.print("[yellow]nmap не вернул результат.[/]")
            return os_line
        detail = {entry["port"]: entry for entry in report["ports"]}
        for item in results:
            info = detail.get(item.port)
            if not info:
                continue
            product = " ".join(part for part in (info["product"], info["version"]) if part)
            if product:
                item.product = info["product"] or item.product
                item.version = info["version"] or item.version
            if info["service"]:
                item.service = info["service"]
            if info["extrainfo"] and info["extrainfo"] not in item.banner:
                item.banner = (item.banner + " " + info["extrainfo"]).strip()
        return report["os"] or os_line

    def _render_ports(self, ip, results, total, os_line):
        if os_line:
            self.console.print(Panel(f"Предполагаемая ОС: [green]{os_line}[/]",
                                     border_style="green", box=box.ROUNDED))
        if not results:
            self.console.print(f"\n[yellow]На {ip} открытых портов не найдено (проверено {total}).[/]")
            return
        table = Table(
            title=f"Открытые порты на {ip}: {len(results)} из {total}",
            box=box.SIMPLE_HEAVY,
            border_style="green",
            header_style="bold green",
        )
        table.add_column("Порт", justify="right", style="bold")
        table.add_column("Proto", style="dim")
        table.add_column("Сервис", style="cyan")
        table.add_column("Версия", style="magenta")
        table.add_column("Баннер / Информация")
        table.add_column("Заметка", style="yellow")
        for item in results:
            table.add_row(
                str(item.port), "tcp", item.service, item.version_text or "-",
                item.banner or "-", item.note or "",
            )
        self.console.print()
        self.console.print(table)

    def _choose_host(self):
        if self.hosts:
            self._render_hosts()
            self.console.print()
            options = [str(i) for i in range(1, len(self.hosts) + 1)] + ["0"]
            choice = Prompt.ask(
                "Выберите номер устройства (0 - ввести IP вручную)",
                choices=options, default="1",
            )
            if choice != "0":
                return self.hosts[int(choice) - 1].ip
        return self._manual_ip()

    def _manual_ip(self):
        value = Prompt.ask("Введите IP-адрес цели", default=network.primary_ip())
        try:
            return network.parse_target(value)[0]
        except Exception:
            self.console.print("[red]Некорректный IP-адрес.[/]")
            return None

    def _choose_ports(self):
        self.console.print()
        mode = Prompt.ask(
            "Набор портов: [cyan]1[/] топ-порты  [cyan]2[/] полный (1-65535)  [cyan]3[/] свои",
            choices=["1", "2", "3"], default="1",
        )
        if mode == "1":
            return list(ports.TOP_PORTS)
        if mode == "2":
            return list(range(1, 65536))
        try:
            return ports.parse_ports(Prompt.ask("Введите порты (например 22,80,443,8000-8100)"))
        except Exception:
            self.console.print("[red]Не удалось разобрать список портов.[/]")
            return []

    def _export(self):
        self._header()
        self.console.print("[bold]Экспорт результатов[/]\n")
        if not self.hosts and not self.scans:
            self.console.print("[yellow]Нет данных для экспорта.[/]")
            return self._pause()
        fmt = Prompt.ask("Формат", choices=["json", "txt"], default="json")
        path = Prompt.ask("Имя файла", default=f"lan-scan.{fmt}")
        try:
            saved = export.export_results(path, self.hosts, self.scans)
            self.console.print(f"\n[green]Сохранено:[/] {saved}")
        except OSError as error:
            self.console.print(f"\n[red]Ошибка записи файла:[/] {error}")
        self._pause()

    def _ask_float(self, label, default):
        try:
            return float(Prompt.ask(label, default=str(default)))
        except ValueError:
            return default

    def _pause(self):
        Prompt.ask("\n[dim]Нажмите Enter, чтобы вернуться в меню[/]", default="")
