_lookup = None
_lookup_failed = False

_BUILTIN = {
    "001451": "Apple, Inc.",
    "0017F2": "Apple, Inc.",
    "0023DF": "Apple, Inc.",
    "002500": "Apple, Inc.",
    "3C0754": "Apple, Inc.",
    "6C4008": "Apple, Inc.",
    "F0DBF8": "Apple, Inc.",
    "DC2B2A": "Apple, Inc.",
    "5C0A5B": "Samsung Electronics",
    "8425DB": "Samsung Electronics",
    "E8508B": "Samsung Electronics",
    "340A33": "Samsung Electronics",
    "640980": "Xiaomi Communications",
    "7451BA": "Xiaomi Communications",
    "F48B32": "Xiaomi Communications",
    "286C07": "Xiaomi Communications",
    "00E0FC": "Huawei Technologies",
    "105172": "Huawei Technologies",
    "5CB395": "Huawei Technologies",
    "E01D3B": "Huawei Technologies",
    "F4F5D8": "Google, Inc.",
    "F88FCA": "Google, Inc.",
    "3C5AB4": "Google, Inc.",
    "44650D": "Amazon Technologies",
    "68370E": "Amazon Technologies",
    "F0272D": "Amazon Technologies",
    "001B21": "Intel Corporate",
    "3C970E": "Intel Corporate",
    "8C1645": "Intel Corporate",
    "A0A8CD": "Intel Corporate",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading",
    "28CDC1": "Raspberry Pi Trading",
    "D83ADD": "Raspberry Pi Trading",
    "240AC4": "Espressif Inc.",
    "5CCF7F": "Espressif Inc.",
    "807D3A": "Espressif Inc.",
    "A4CF12": "Espressif Inc.",
    "246F28": "Espressif Inc.",
    "005056": "VMware, Inc.",
    "000C29": "VMware, Inc.",
    "000569": "VMware, Inc.",
    "080027": "PCS Systemtechnik (VirtualBox)",
    "525400": "QEMU Virtual NIC",
    "00163E": "Xensource, Inc.",
    "00155D": "Microsoft (Hyper-V)",
    "FCECDA": "Ubiquiti Networks",
    "24A43C": "Ubiquiti Networks",
    "788A20": "Ubiquiti Networks",
    "0418D6": "Ubiquiti Networks",
    "4C5E0C": "MikroTik",
    "6C3B6B": "MikroTik",
    "CC2DE0": "MikroTik",
    "E48D8C": "MikroTik",
    "50C7BF": "TP-Link Technologies",
    "A42BB0": "TP-Link Technologies",
    "EC086B": "TP-Link Technologies",
    "20E52A": "Netgear",
    "A040A0": "Netgear",
    "C03F0E": "Netgear",
    "1CBDB9": "D-Link International",
    "340804": "D-Link International",
    "78542E": "D-Link International",
    "0009BF": "Nintendo Co., Ltd.",
    "34AF2C": "Nintendo Co., Ltd.",
    "98B6E9": "Nintendo Co., Ltd.",
    "CC9E00": "Nintendo Co., Ltd.",
    "0CFE45": "Sony Corporation",
    "FC0FE6": "Sony Interactive Entertainment",
    "000E58": "Sonos, Inc.",
    "5CAAFD": "Sonos, Inc.",
}

_CATEGORY_RULES = [
    (("hyper-v",), "Виртуальная машина (Hyper-V)"),
    (("vmware", "virtualbox", "qemu", "xensource", "xen", "parallels", "virtual"), "Виртуальная машина"),
    (("raspberry",), "Одноплатный компьютер (Raspberry Pi)"),
    (("espressif",), "IoT / микроконтроллер (ESP)"),
    (("hikvision", "dahua", "axis communications", "reolink", "amcrest"), "IP-камера"),
    (("brother", "canon", "epson", "xerox", "lexmark", "kyocera", "ricoh"), "Принтер"),
    (("apple",), "Apple (iPhone / iPad / Mac)"),
    (("samsung", "xiaomi", "huawei", "oneplus", "oppo", "vivo", "realme", "motorola",
      "google", "pixel", "nokia", "honor"), "Смартфон / планшет"),
    (("tp-link", "netgear", "d-link", "dlink", "ubiquiti", "mikrotik", "cisco", "zyxel",
      "keenetic", "tenda", "aruba", "juniper", "fortinet", "ruckus"), "Роутер / сетевое оборудование"),
    (("sonos", "nest", "amazon", "tuya", "shelly", "sonoff"), "IoT / умный дом"),
    (("nintendo", "sony", "playstation", "xbox"), "Игровая консоль / медиа"),
    (("intel", "dell", "hewlett", "hp ", "lenovo", "asustek", "asus", "micro-star", "msi",
      "gigabyte", "acer", "toshiba", "fujitsu", "clevo", "microsoft"), "ПК / ноутбук"),
]


def _get_lookup():
    global _lookup, _lookup_failed
    if _lookup is not None or _lookup_failed:
        return _lookup
    try:
        from mac_vendor_lookup import MacLookup

        _lookup = MacLookup()
    except Exception:
        _lookup_failed = True
        _lookup = None
    return _lookup


def prepare_database(force=False):
    lookup = _get_lookup()
    if lookup is None:
        return False
    try:
        if not force:
            lookup.lookup("00:1A:2B:00:00:00")
            return True
    except Exception:
        pass
    try:
        lookup.update_vendors()
        return True
    except Exception:
        return False


def lookup_vendor(mac):
    if not mac:
        return "Unknown"
    lookup = _get_lookup()
    if lookup is not None:
        try:
            return lookup.lookup(mac)
        except Exception:
            pass
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return _BUILTIN.get(prefix, "Unknown")


def device_category(vendor):
    if not vendor or vendor == "Unknown":
        return "Неизвестно"
    value = vendor.lower()
    for keywords, label in _CATEGORY_RULES:
        if any(keyword in value for keyword in keywords):
            return label
    return "Прочее устройство"
