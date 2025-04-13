import scapy.all as scapy
from scapy.layers import http
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import argparse
import sys
import platform
import subprocess
from scapy.arch.windows import get_windows_if_list  # Windows-specific import


class NetworkAnalyzer:
    def __init__(self, interface=None, output_file=None, capture_time=30, filter_expression=""):
        self.interface = self._validate_interface(interface)
        self.output_file = output_file
        self.capture_time = capture_time
        self.filter = filter_expression
        self.packets = []
        self.stats = {
            'protocols': Counter(),
            'source_ips': Counter(),
            'destination_ips': Counter(),
            'source_ports': Counter(),
            'destination_ports': Counter(),
            'packet_sizes': []
        }

    def _validate_interface(self, interface):
        """Validate and select the appropriate network interface"""
        if interface:
            return interface

        # Windows specific interface handling
        if platform.system() == "Windows":
            try:
                interfaces = get_windows_if_list()
                if not interfaces:
                    print("[!] No network interfaces found. Ensure Npcap is installed.")
                    sys.exit(1)

                # Print available interfaces
                print("\nAvailable Interfaces:")
                for i, iface in enumerate(interfaces):
                    print(f"{i + 1}. {iface['name']} - {iface['description']}")

                # Try to find a non-loopback interface
                for iface in interfaces:
                    if not iface.get('isloopback', False):
                        print(f"\n[*] Selected interface: {iface['name']}")
                        return iface['name']

                # Fallback to first interface
                return interfaces[0]['name']
            except Exception as e:
                print(f"[!] Error getting interfaces: {e}")
                sys.exit(1)
        else:
            # Unix/Linux/Mac handling
            return scapy.conf.iface

    def _check_npcap_installed(self):
        """Check if Npcap is installed on Windows"""
        if platform.system() == "Windows":
            try:
                # Check registry for Npcap
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap")
                winreg.CloseKey(key)
                return True
            except WindowsError:
                print("[!] Npcap not found. Please install Npcap from https://npcap.com/")
                print("[!] During installation, select 'Install Npcap in WinPcap API-compatible mode'")
                return False
        return True

    def start_capture(self):
        """Start capturing network traffic"""
        if platform.system() == "Windows" and not self._check_npcap_installed():
            sys.exit(1)

        print(f"[*] Starting capture on interface {self.interface} for {self.capture_time} seconds...")
        try:
            # Windows requires different handling
            kwargs = {}
            if platform.system() == "Windows":
                kwargs['promisc'] = False  # Disable promiscuous mode on Windows
                kwargs['iface'] = self.interface if self.interface else None

            self.packets = scapy.sniff(
                timeout=self.capture_time,
                filter=self.filter,
                prn=self.process_packet,
                **kwargs
            )
            print(f"[*] Capture complete. {len(self.packets)} packets captured.")
        except PermissionError:
            print("[!] Permission denied. Try running as Administrator.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error during capture: {e}")
            sys.exit(1)

    # [Rest of the methods remain the same as in the previous version]
    # process_packet(), _analyze_http(), generate_report(),
    # _generate_visualizations(), save_to_pcap() methods go here...


def main():
    parser = argparse.ArgumentParser(description="Network Traffic Capture and Analysis Tool")
    parser.add_argument("-i", "--interface", help="Network interface to capture on")
    parser.add_argument("-o", "--output", help="Output pcap file to save captured packets")
    parser.add_argument("-t", "--time", type=int, default=30, help="Capture duration in seconds")
    parser.add_argument("-f", "--filter", default="", help="BPF filter expression")

    args = parser.parse_args()

    analyzer = NetworkAnalyzer(
        interface=args.interface,
        output_file=args.output,
        capture_time=args.time,
        filter_expression=args.filter
    )

    try:
        analyzer.start_capture()
        analyzer.generate_report()
        analyzer.save_to_pcap()
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user")
        analyzer.generate_report()
        analyzer.save_to_pcap()


if __name__ == "__main__":
    # On Windows, we need to ensure we're running with admin privileges
    if platform.system() == "Windows":
        import ctypes

        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] Please run this script as Administrator")
            sys.exit(1)

    main()