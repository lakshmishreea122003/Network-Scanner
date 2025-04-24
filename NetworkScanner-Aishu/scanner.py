import socket
import subprocess
import platform
import threading
from queue import Queue

class NetworkScanner:
    def __init__(self, ip_range, ports=None, timeout=1):
        self.ip_range = ip_range
        self.ports = ports if ports else [22, 80, 443, 3389]
        self.timeout = timeout
        self.results = {}

    def ping(self, ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_flag = '-w' if platform.system().lower() == 'windows' else '-W'
        command = ['ping', param, '1', timeout_flag, '1', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

    def scan_port(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except Exception:
            return False

    def grab_banner(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode(errors='ignore')
                return banner.strip()
        except Exception:
            return ""

    def detect_os(self, ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        try:
            output = subprocess.check_output(['ping', param, '1', ip], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
            ttl = None
            for line in output.splitlines():
                if 'ttl=' in line.lower():
                    ttl_str = line.lower().split('ttl=')[1].split()[0]
                    ttl = int(ttl_str)
                    break
            if ttl is not None:
                if ttl >= 128:
                    return 'Windows'
                elif ttl >= 64:
                    return 'Linux/Unix'
                elif ttl >= 255:
                    return 'Network Device/Cisco'
                else:
                    return 'Unknown'
        except Exception:
            pass
        return 'Unknown'

    def scan_ip(self, ip):
        host_info = {'alive': False, 'open_ports': {}, 'os': 'Unknown'}
        if self.ping(ip):
            host_info['alive'] = True
            host_info['os'] = self.detect_os(ip)
            for port in self.ports:
                if self.scan_port(ip, port):
                    banner = self.grab_banner(ip, port)
                    host_info['open_ports'][port] = banner or 'Unknown service'
        self.results[ip] = host_info

    def run_scan(self, threads=50):
        q = Queue()
        for ip in self.ip_range:
            q.put(ip)

        def worker():
            while not q.empty():
                ip = q.get()
                try:
                    self.scan_ip(ip)
                finally:
                    q.task_done()

        for _ in range(min(threads, len(self.ip_range))):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()

        q.join()

    def print_results(self):
        for ip, info in self.results.items():
            print(f"IP: {ip}")
            if not info['alive']:
                print("  Host is down or not responding.")
            else:
                print(f"  Host is alive. OS guess: {info['os']}")
                if info['open_ports']:
                    print("  Open Ports:")
                    for port, banner in info['open_ports'].items():
                        print(f"    Port {port}: {banner}")
                else:
                    print("  No open ports found.")
            print("-" * 40)


if __name__ == '__main__':
    base_ip = '192.168.1.'
    ip_list = [base_ip + str(i) for i in range(1, 11)]

    scanner = NetworkScanner(ip_list)
    print("Starting scan...\n")
    scanner.run_scan()
    print("\nScan complete. Results:\n")
    scanner.print_results()
