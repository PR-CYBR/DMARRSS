"""
Asset Inventory Module - NIST CSF 2.0 Identify Function

This module catalogs system assets and configurations to establish a baseline
and context for what is being protected, enabling risk-based prioritization of threats.

NIST CSF 2.0 Mapping: ID.AM (Asset Management)
"""

import json
import logging
import platform
import socket
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AssetInventory:
    """
    Cross-platform asset inventory collection.
    
    Implements NIST CSF 2.0 Identify function by cataloging:
    - OS version and system information
    - Installed applications
    - Running processes and services
    - Network interfaces and open ports
    - User accounts
    """

    def __init__(self, config: dict):
        """
        Initialize asset inventory collector.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.data_dir = Path(config.get("system", {}).get("data_dir", "data"))
        self.inventory_dir = self.data_dir / "inventory"
        self.inventory_dir.mkdir(parents=True, exist_ok=True)

    def collect_system_info(self) -> dict[str, Any]:
        """
        Collect OS version and system information.
        
        Returns:
            Dictionary with system information
        """
        try:
            return {
                "hostname": socket.gethostname(),
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
            }
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            return {}

    def collect_network_info(self) -> dict[str, Any]:
        """
        Collect network interfaces and configuration.
        
        Returns:
            Dictionary with network information
        """
        try:
            import psutil

            interfaces = {}
            for iface, addrs in psutil.net_if_addrs().items():
                interfaces[iface] = []
                for addr in addrs:
                    interfaces[iface].append({
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast,
                    })

            connections = psutil.net_connections(kind='inet')
            listening_ports = []
            for conn in connections:
                if conn.status == 'LISTEN':
                    listening_ports.append({
                        "port": conn.laddr.port,
                        "address": conn.laddr.ip,
                        "protocol": "tcp" if conn.type == 1 else "udp",
                    })

            return {
                "interfaces": interfaces,
                "listening_ports": listening_ports,
            }
        except ImportError:
            logger.warning("psutil not installed, skipping network info collection")
            return {}
        except Exception as e:
            logger.error(f"Error collecting network info: {e}")
            return {}

    def collect_process_info(self) -> list[dict[str, Any]]:
        """
        Collect running processes and services.
        
        Returns:
            List of running processes
        """
        try:
            import psutil

            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time']):
                try:
                    pinfo = proc.info
                    processes.append({
                        "pid": pinfo['pid'],
                        "name": pinfo['name'],
                        "username": pinfo.get('username', 'N/A'),
                        "status": pinfo.get('status', 'N/A'),
                        "create_time": pinfo.get('create_time', 0),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            return processes
        except ImportError:
            logger.warning("psutil not installed, skipping process info collection")
            return []
        except Exception as e:
            logger.error(f"Error collecting process info: {e}")
            return []

    def collect_user_accounts(self) -> list[dict[str, Any]]:
        """
        Collect user accounts information.
        
        Returns:
            List of user accounts
        """
        try:
            import psutil

            users = []
            for user in psutil.users():
                users.append({
                    "name": user.name,
                    "terminal": user.terminal,
                    "host": user.host,
                    "started": user.started,
                })

            return users
        except ImportError:
            logger.warning("psutil not installed, skipping user accounts collection")
            return []
        except Exception as e:
            logger.error(f"Error collecting user accounts: {e}")
            return []

    def collect_installed_software(self) -> list[dict[str, Any]]:
        """
        Collect installed applications (platform-specific).
        
        Returns:
            List of installed software
        """
        software = []
        system = platform.system()

        try:
            if system == "Linux":
                software = self._collect_linux_packages()
            elif system == "Windows":
                software = self._collect_windows_programs()
            elif system == "Darwin":
                software = self._collect_macos_applications()
        except Exception as e:
            logger.error(f"Error collecting installed software: {e}")

        return software

    def _collect_linux_packages(self) -> list[dict[str, Any]]:
        """Collect installed packages on Linux"""
        import subprocess

        packages = []
        try:
            # Try dpkg (Debian/Ubuntu)
            result = subprocess.run(
                ["dpkg", "-l"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n')[5:]:  # Skip header
                    if line.strip():
                        parts = line.split(None, 4)
                        if len(parts) >= 3:
                            packages.append({
                                "name": parts[1],
                                "version": parts[2],
                                "type": "deb",
                            })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if not packages:
            try:
                # Try rpm (RedHat/CentOS/Fedora)
                result = subprocess.run(
                    ["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}\\n"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            parts = line.split('\t')
                            if len(parts) >= 2:
                                packages.append({
                                    "name": parts[0],
                                    "version": parts[1],
                                    "type": "rpm",
                                })
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return packages[:100]  # Limit to first 100 for performance

    def _collect_windows_programs(self) -> list[dict[str, Any]]:
        """Collect installed programs on Windows"""
        programs = []
        try:
            import winreg

            # Check both 32-bit and 64-bit registry keys
            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            ]

            for hkey, path in registry_paths:
                try:
                    key = winreg.OpenKey(hkey, path)
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            try:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                programs.append({
                                    "name": name,
                                    "version": version,
                                    "type": "windows",
                                })
                            except FileNotFoundError:
                                pass
                            finally:
                                winreg.CloseKey(subkey)
                        except:
                            pass
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    pass

        except ImportError:
            logger.warning("winreg not available (not on Windows)")
        except Exception as e:
            logger.error(f"Error reading Windows registry: {e}")

        return programs[:100]  # Limit to first 100

    def _collect_macos_applications(self) -> list[dict[str, Any]]:
        """Collect installed applications on macOS"""
        import subprocess

        apps = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPApplicationsDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                import json
                data = json.loads(result.stdout)
                for app in data.get("SPApplicationsDataType", [])[:100]:
                    apps.append({
                        "name": app.get("_name", "Unknown"),
                        "version": app.get("version", "Unknown"),
                        "type": "macos",
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            logger.error(f"Error collecting macOS applications: {e}")

        return apps

    def collect_all(self) -> dict[str, Any]:
        """
        Collect complete asset inventory.
        
        Returns:
            Complete inventory dictionary
        """
        logger.info("Collecting asset inventory...")

        inventory = {
            "timestamp": datetime.utcnow().isoformat(),
            "csf_function": "IDENTIFY",
            "csf_category": "ID.AM - Asset Management",
            "system": self.collect_system_info(),
            "network": self.collect_network_info(),
            "processes": self.collect_process_info(),
            "users": self.collect_user_accounts(),
            "software": self.collect_installed_software(),
        }

        logger.info(
            f"Inventory collected: {len(inventory['processes'])} processes, "
            f"{len(inventory.get('software', []))} software packages"
        )

        return inventory

    def save_inventory(self, inventory: dict[str, Any] | None = None) -> Path:
        """
        Save inventory to JSON file.
        
        Args:
            inventory: Inventory data (if None, will collect fresh data)
            
        Returns:
            Path to saved inventory file
        """
        if inventory is None:
            inventory = self.collect_all()

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"inventory_{timestamp}.json"
        filepath = self.inventory_dir / filename

        with open(filepath, 'w') as f:
            json.dump(inventory, f, indent=2)

        # Also save as latest.json for easy reference
        latest_path = self.inventory_dir / "latest.json"
        with open(latest_path, 'w') as f:
            json.dump(inventory, f, indent=2)

        logger.info(f"Inventory saved to {filepath}")
        return filepath

    def load_inventory(self, filepath: str | Path | None = None) -> dict[str, Any]:
        """
        Load inventory from JSON file.
        
        Args:
            filepath: Path to inventory file (defaults to latest.json)
            
        Returns:
            Inventory dictionary
        """
        if filepath is None:
            filepath = self.inventory_dir / "latest.json"
        else:
            filepath = Path(filepath)

        if not filepath.exists():
            logger.warning(f"Inventory file not found: {filepath}")
            return {}

        with open(filepath) as f:
            return json.load(f)
