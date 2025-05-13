import nmap

class Network_Scanner:
    def __init__(self,ip,subnet):
        self.ip= ip
        self.subnet = subnet

    # Feature 1: IP/Host Discovery
    def discover_hosts(self):
        print("################# \n IP/Host Discovery")
        print(f"Scanning subnet: {self.subnet} for active hosts...\n")
        scanner = nmap.PortScanner()
        scanner.scan(hosts=self.subnet, arguments='-sn')  # -sn = ping scan (no port scan)
        live_hosts = []
        for host in scanner.all_hosts():
            if scanner[host].state() == 'up':
                hostname = scanner[host].hostname()
                print(f"Host: {host} ({hostname}) is UP")
                live_hosts.append((host, hostname))
        if not live_hosts:
            print("No active hosts found.")
        return live_hosts
    

    # Feature 2: Port Scanning
    def scan_open_ports(self):
        print("################# \n Port Scanning")
        print(f"\nScanning {self.ip} for open ports...\n")
        scanner = nmap.PortScanner()
        scanner.scan(self.ip, arguments='-sS -T4 -Pn')
        for proto in scanner[self.ip].all_protocols():
            print(f"Protocol: {proto}")
            ports = scanner[self.ip][proto].keys()
            for port in sorted(ports):
                state = scanner[self.ip][proto][port]['state']
                print(f"Port: {port} is {state}")

    
    # Feature 3: Banner Grabbing / Service Identification.
    def grab_banners(self):
        print("################# \n Banner Grabbing / Service Identification.")
        print(f"\nPerforming service version detection on {self.ip}...\n")
        scanner = nmap.PortScanner()
        scanner.scan(self.ip, arguments='-sV -Pn')
        for proto in scanner[self.ip].all_protocols():
            print(f"\nProtocol: {proto}")
            lport = scanner[self.ip][proto].keys()
            for port in sorted(lport):
                state = scanner[self.ip][proto][port]['state']
                name = scanner[self.ip][proto][port].get('name', 'unknown')
                product = scanner[self.ip][proto][port].get('product', '')
                version = scanner[self.ip][proto][port].get('version', '')
                extrainfo = scanner[self.ip][proto][port].get('extrainfo', '')
                banner = f"{product} {version} {extrainfo}".strip()
                print(f"Port {port} is {state} - Service: {name} | Banner: {banner}")


    # Feature 4: OS Fingerprinting.
    def detect_os(self):
        print(f"\nPerforming OS detection on {self.ip}...\n")
        scanner = nmap.PortScanner()
        try:
            scanner.scan(self.ip, arguments='-O -Pn')
            if 'osmatch' in scanner[self.ip]:
                for os in scanner[self.ip]['osmatch']:
                   print(f"Detected OS: {os['name']} (Accuracy: {os['accuracy']}%)")
            else:
                print("OS detection failed or insufficient data.")
        except Exception as e:
            print(f"Error: {e}")


    # Detected vulnerabilities 
    def detect_vulnerabilities(self):
        print("################# \n Detected vulnerabilities ")
        print(f"\nScanning {self.ip} for vulnerabilities...\n")
        nm = nmap.PortScanner()
        try:
            nm.scan(self.ip, arguments='-sV --script=vuln')  # Scan services and run vulnerability scripts
            for host in nm.all_hosts():
                print(f"Host: {host}")
                if 'hostscript' in nm[host]:
                    for script in nm[host]['hostscript']:
                        print(f"  - Vulnerability: {script['id']} => {script['output']}")
                else:
                    print("No vulnerabilities detected.")
        except Exception as e:
            print(f"Error: {e}")


def main():
    ip = input("Enter IP:")
    subnet = input("Enter subnet:")
    scanner = Network_Scanner(ip,subnet)
    scanner.discover_hosts()
    scanner.scan_open_ports()
    scanner.grab_banners()
    scanner.detect_vulnerabilities()

if __name__ == "__main__":
    main()
