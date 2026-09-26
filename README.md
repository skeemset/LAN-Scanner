# LAN Scanner
<img width="921" height="368" alt="изображение" src="https://github.com/user-attachments/assets/541f8e70-cc7d-4e2d-b628-c504ed61a340" />

Инструмент для разведки локальной сети: обнаружение устройств, определение
вендора и типа устройства, сканирование портов с определением сервисов и их
версий. Терминальный интерфейс на Python.

## Возможности

- Host Discovery: ARP-скан (scapy) с TCP-фолбэком без прав root
- Определение вендора по MAC и типа устройства (телефон, ПК, роутер, IoT и т.д.)
- Сканер портов: топ-порты, полный диапазон или свой список
- Определение сервисов и версий, захват баннеров, версия TLS
- Определение ОС по TTL, опциональная интеграция с nmap
- Экспорт результатов в JSON/TXT

## Установка

### Linux

```bash
git clone https://github.com/skeemset/lan-scanner.git
cd lan-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows

Для ARP-сканирования установите [Npcap](https://npcap.com/) и запускайте
терминал от имени администратора.

```powershell
git clone https://github.com/skeemset/lan-scanner.git
cd lan-scanner
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Запуск

```bash
# Linux (root нужен для ARP-скана; python берём из venv)
sudo .venv/bin/python -m lanscan

# Windows (терминал от администратора)
python -m lanscan
```

`sudo` запускает системный Python, поэтому под root указывайте python из venv напрямую. Без прав администратора инструмент работает в TCP-режиме.

## CLI-режим

```bash
python -m lanscan --discover 192.168.1.0/24
python -m lanscan --scan 192.168.1.10 --ports top --json result.json
```

## Лицензия

MIT
