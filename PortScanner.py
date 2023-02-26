import sys
import nmap 
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QTextEdit


class PortScanner(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        # Interface arguments
        self.ip_label = QLabel("IP adresi:")
        self.ip_input = QLineEdit()
        self.scan_btn = QPushButton("Axtar")
        self.result_label = QLabel("Açıq portlar:")
        self.result_text = QTextEdit()

        # interface design
        vbox = QVBoxLayout()
        vbox.addWidget(self.ip_label)
        vbox.addWidget(self.ip_input)
        vbox.addWidget(self.scan_btn)
        vbox.addWidget(self.result_label)
        vbox.addWidget(self.result_text)

        self.setLayout(vbox)

        # scan edir
        self.scan_btn.clicked.connect(self.start_scan)

        self.setWindowTitle("Port Scan")
        self.show()

    def start_scan(self):
        # verilen ip adresi ve port nomrelerini alin
        target_ip = self.ip_input.text()
        target_ports = "-p-"

        # Nmap ile scan edir
        nm = nmap.PortScanner()
        nm.scan(target_ip, arguments=target_ports)

        # Açıq portları yazdır
        open_ports = []
        for port in nm[target_ip]['tcp']:
            if nm[target_ip]['tcp'][port]['state'] == 'open':
                open_ports.append(port)

        # neticeleri goster
        self.result_text.setText('\n'.join(str(port) for port in open_ports))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    scanner = PortScanner()
    sys.exit(app.exec_())

