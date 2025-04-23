import socket
import subprocess
import platform
import threading
from queue import Queue

class NetworkScanner:
    def __init__(self, ip_range, ports=None, timeout=1):
        """
        ip_range: list of IPs to scan (e.g. ['192.168.1.1', '192.168.1.2'])
        ports: list of TCP ports to scan
        timeout: socket timeout seconds
        """
        self.ip_range = ip_range
        self.ports = ports if ports else [22, 80, 443, 3389]
        self.timeout = timeout
        self.results = {}

    def ping(self, ip):
        """
        Ping an IP to check if host is alive.
        Returns True if alive, False otherwise.
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', '1000', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

    def scan_port(self, ip, port):
        """
        Scan a single TCP port. Return True if open, False otherwise.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    return True
        except Exception:
            pass
        return False

    def grab_banner(self, ip, port):
        """
        Attempt to grab banner from open port.
        """
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
        """
        Basic OS detection using TTL from ping.
        This is heuristic and very limited.
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', ip]
        try:
            output = subprocess.check_output(command).decode()
            ttl = None
            for line in output.splitlines():
                if 'ttl=' in line.lower():
                    # Extract TTL value
                    parts = line.lower().split('ttl=')
                    if len(parts) > 1:
                        ttl_str = parts[1].split()[0]
                        ttl = int(ttl_str)
                        break
            if ttl:
                # Common TTL values heuristic
                if ttl >= 128:
                    return 'Windows'
                elif ttl >= 64:
                    return 'Linux/Unix'
                elif ttl >= 255:
                    return 'Cisco/Network Device'
                else:
                    return 'Unknown'
            else:
                return 'Unknown'
        except Exception:
            return 'Unknown'

    def scan_ip(self, ip):
        """
        Scan a single IP: ping, ports, banner, OS detection.
        """
        host_info = {
            'alive': False,
            'open_ports': {},
            'os': 'Unknown',
        }

        if self.ping(ip):
            host_info['alive'] = True
            host_info['os'] = self.detect_os(ip)
            for port in self.ports:
                if self.scan_port(ip, port):
                    banner = self.grab_banner(ip, port)
                    host_info['open_ports'][port] = banner if banner else 'Unknown service'
        else:
            host_info['alive'] = False

        self.results[ip] = host_info

    def run_scan(self, threads=100):
        """
        Run scan on all IPs using multithreading.
        """
        q = Queue()

        for ip in self.ip_range:
            q.put(ip)

        def worker():
            while not q.empty():
                ip = q.get()
                self.scan_ip(ip)
                q.task_done()

        thread_list = []
        for _ in range(min(threads, len(self.ip_range))):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            thread_list.append(t)

        q.join()

    def print_results(self):
        """
        Nicely print the scan results.
        """
        for ip, info in self.results.items():
            print(f"IP: {ip}")
            if not info['alive']:
                print("  Host is down or not responding.")
                continue
            print(f"  Host is alive. OS guess: {info['os']}")
            if info['open_ports']:
                print("  Open Ports:")
                for port, banner in info['open_ports'].items():
                    print(f"    Port {port}: {banner}")
            else:
                print("  No open ports found.")
            print("-" * 40)


if __name__ == '__main__':
    # Example usage: scan 192.168.1.1 to 192.168.1.10
    base_ip = '192.168.1.'
    ip_list = [base_ip + str(i) for i in range(1, 11)]

    scanner = NetworkScanner(ip_list)
    print("Starting scan...")
    scanner.run_scan()
    print("Scan complete. Results:")
    scanner.print_results()
