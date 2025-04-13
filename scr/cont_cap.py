import scapy.all as scapy
from scapy.layers import http, dns, dhcp
from scapy.layers.inet import TCP, UDP, IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.arch.windows import get_windows_if_list
import platform
from collections import defaultdict, OrderedDict
from datetime import datetime
import time
import sys
import argparse

from PyQt5 import QtWidgets, QtCore
import threading

class InterfaceAnalyzer:
    def __init__(self):
        self.interface_stats = defaultdict(lambda: {
            'packet_count': 0,
            'packets': []
        })
        self.capture_duration = 10
        self.active_interfaces = []
        self.selected_interface = None
        self.callback = None

    def set_callback(self, callback):
        self.callback = callback

    def get_active_interfaces(self):
        if platform.system() == "Windows":
            interfaces = get_windows_if_list()
            return [iface['name'] for iface in interfaces if not iface.get('isloopback', False)]
        else:
            return [iface for iface in scapy.get_if_list() if not iface.startswith('lo') and not iface.startswith('any')]

    def _get_packet_layers(self, packet):
        layers = OrderedDict()
        layers['Physical'] = {
            'timestamp': datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f'),
            'length': len(packet)
        }
        layers['Data Link'] = {}
        if Ether in packet:
            layers['Data Link']['src_mac'] = packet[Ether].src
            layers['Data Link']['dst_mac'] = packet[Ether].dst
            layers['Data Link']['type'] = f"0x{packet[Ether].type:04x}"
        layers['Network'] = {}
        if IP in packet:
            layers['Network']['version'] = 4
            layers['Network']['src_ip'] = packet[IP].src
            layers['Network']['dst_ip'] = packet[IP].dst
            layers['Network']['protocol'] = packet[IP].proto
        elif scapy.IPv6 in packet:
            layers['Network']['version'] = 6
            layers['Network']['src_ip'] = packet[scapy.IPv6].src
            layers['Network']['dst_ip'] = packet[scapy.IPv6].dst
        layers['Transport'] = {}
        if TCP in packet:
            layers['Transport']['protocol'] = 'TCP'
            layers['Transport']['src_port'] = packet[TCP].sport
            layers['Transport']['dst_port'] = packet[TCP].dport
        elif UDP in packet:
            layers['Transport']['protocol'] = 'UDP'
            layers['Transport']['src_port'] = packet[UDP].sport
            layers['Transport']['dst_port'] = packet[UDP].dport
        elif ICMP in packet:
            layers['Transport']['protocol'] = 'ICMP'
            layers['Transport']['type'] = packet[ICMP].type
            layers['Transport']['code'] = packet[ICMP].code
        layers['Application'] = {}
        if http.HTTPRequest in packet:
            layers['Application']['type'] = 'HTTP'
            layers['Application']['method'] = packet[http.HTTPRequest].Method.decode()
        elif dns.DNS in packet:
            layers['Application']['type'] = 'DNS'
        elif dhcp.DHCP in packet:
            layers['Application']['type'] = 'DHCP'
        return layers

    def packet_handler(self, packet):
        iface = packet.sniffed_on if hasattr(packet, 'sniffed_on') else 'unknown'
        packet_layers = self._get_packet_layers(packet)
        self.interface_stats[iface]['packet_count'] += 1
        self.interface_stats[iface]['packets'].append(packet_layers)
        if self.callback:
            self.callback(iface, packet_layers)

    def start_capture(self, duration):
        self.capture_duration = duration
        iface = self.selected_interface or self.get_active_interfaces()
        scapy.sniff(iface=iface, prn=self.packet_handler,
                    timeout=duration, store=False)

class PacketAnalyzerApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Packet Analyzer")
        self.setGeometry(100, 100, 800, 600)

        self.analyzer = InterfaceAnalyzer()
        self.analyzer.set_callback(self.update_output)

        self.layout = QtWidgets.QVBoxLayout()

        self.interface_dropdown = QtWidgets.QComboBox()
        self.interface_dropdown.addItems(self.analyzer.get_active_interfaces())

        self.duration_input = QtWidgets.QSpinBox()
        self.duration_input.setMinimum(1)
        self.duration_input.setValue(10)

        self.start_button = QtWidgets.QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)

        self.output = QtWidgets.QTextEdit()
        self.output.setReadOnly(True)

        self.layout.addWidget(QtWidgets.QLabel("Select Interface:"))
        self.layout.addWidget(self.interface_dropdown)
        self.layout.addWidget(QtWidgets.QLabel("Capture Duration (seconds):"))
        self.layout.addWidget(self.duration_input)
        self.layout.addWidget(self.start_button)
        self.layout.addWidget(self.output)
        self.setLayout(self.layout)

    def start_capture(self):
        self.output.clear()
        duration = self.duration_input.value()
        selected_iface = self.interface_dropdown.currentText()
        self.analyzer.selected_interface = selected_iface
        thread = threading.Thread(target=self.analyzer.start_capture, args=(duration,), daemon=True)
        thread.start()

    def update_output(self, iface, packet_layers):
        self.output.append(f"Interface: {iface}")
        for layer, info in packet_layers.items():
            if info:
                self.output.append(f"  [{layer}]")
                for key, val in info.items():
                    self.output.append(f"    {key.replace('_', ' ').title()}: {val}")
        self.output.append("\n")


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = PacketAnalyzerApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

