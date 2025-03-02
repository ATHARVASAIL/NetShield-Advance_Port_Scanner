import socket
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self, target, ports, max_threads=100):
        self.target = target
        self.ports = ports
        self.max_threads = max_threads

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    return port, "Open"
                else:
                    return port, "Closed"
        except Exception as e:
            return port, f"Error: {e}"

    def scan_ports(self, progress_callback=None):
        open_ports = []
        errors = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.scan_port, port) for port in self.ports]
            for future in futures:
                port, status = future.result()
                if status == "Open":
                    open_ports.append(port)
                elif "Error" in status:
                    errors.append(f"Port {port}: {status}")
                if progress_callback:
                    progress_callback()
        return open_ports, errors