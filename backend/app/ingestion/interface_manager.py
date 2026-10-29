import os
import sys
import ctypes
import psutil
from pathlib import Path
from ..schemas.system import InterfaceInfo

def is_admin() -> bool:
    """Check if the current process has administrative / root privileges."""
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.getuid() == 0
    except Exception:
        return False

def is_npcap_available() -> bool:
    """Check if Npcap / WinPcap is installed on Windows."""
    if sys.platform != "win32":
        return True  # Linux / macOS have native libpcap or raw sockets
    
    system32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
    npcap_files = [
        system32 / "wpcap.dll",
        system32 / "Packet.dll",
        system32 / "Npcap" / "wpcap.dll",
        system32 / "Npcap" / "Packet.dll",
    ]
    for path in npcap_files:
        if path.exists():
            return True
    return False

def get_network_interfaces() -> list[InterfaceInfo]:
    """Enumerates active physical and virtual interfaces using psutil."""
    results: list[InterfaceInfo] = []
    
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface_name, addr_list in addrs.items():
        ip_addr = None
        mac_addr = None
        
        for a in addr_list:
            if a.family == psutil.AF_LINK or getattr(a.family, 'name', '') == 'AF_LINK' or a.family == -1:
                mac_addr = a.address
            elif str(a.family).endswith("AF_INET") or a.family == 2:
                ip_addr = a.address

        stat = stats.get(iface_name)
        is_up = stat.isup if stat else True
        speed = stat.speed if stat and stat.speed > 0 else None

        results.append(InterfaceInfo(
            name=iface_name,
            description=f"{iface_name} ({ip_addr or 'No IP'})",
            ip=ip_addr,
            mac=mac_addr,
            is_up=is_up,
            speed_mbps=speed
        ))

    # Add clearly labeled synthetic virtual interface
    results.append(InterfaceInfo(
        name="Synthetic Mode",
        description="Synthetic Simulator (Safe demonstration engine)",
        ip="192.168.1.10",
        mac="00:1A:2B:3C:4D:5E",
        is_up=True,
        speed_mbps=1000
    ))

    return results

def get_default_interface_name() -> str:
    """Find the best default interface for live packet capture by querying outward route."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        default_ip = s.getsockname()[0]
        s.close()
    except Exception:
        default_ip = None

    ifaces = get_network_interfaces()
    if default_ip:
        matched = next((i for i in ifaces if i.ip == default_ip and i.name != "Synthetic Mode"), None)
        if matched:
            return matched.name

    # Fallback heuristic: Up, not synthetic, not loopback, not link-local, prefer Wi-Fi or Ethernet
    valid_ifaces = [
        i for i in ifaces
        if i.name != "Synthetic Mode"
        and i.is_up
        and i.ip
        and not i.ip.startswith("127.")
        and not i.ip.startswith("169.254.")
        and "virtual" not in i.name.lower()
        and "vbox" not in i.name.lower()
    ]
    if valid_ifaces:
        for pref in ["wi-fi", "wifi", "wlan", "eth", "ethernet"]:
            for iface in valid_ifaces:
                if pref in iface.name.lower():
                    return iface.name
        return valid_ifaces[0].name

    return "Wi-Fi"
