import argparse
from socket import *
import threading

lock=threading.Lock()

def get_arguments():
    parser = argparse.ArgumentParser(prog='portscanner',
                                     description='Simple port Scanner',
                                     epilog='Created by LDD')
    parser.add_argument('-H', '--host', dest='host', help='Specify target host', type=str, required=True)
    parser.add_argument('-p', '--port', dest='port', help='Specify target port', type=str, required=True)

    args = parser.parse_args()
    return args.host, args.port

def connect(host, port):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        print(f'[+] tcp open {port}')
        banner = None
        try:
            s.send(b"Hello\r\n")
            result = s.recv(1024)
            banner = result.decode(errors="ignore").strip()
            print(f'[BANNER] {banner}')
        except:
            pass
        return True, banner
    except (ConnectionRefusedError, timeout, OSError):
        print(f'[-] tcp closed {port}')
        return False, None
    finally:
        s.close()

def scan_port(host, port, open_ports, banners):
    is_open, banner = connect(host, port)
    if is_open:
        with lock:
            open_ports.append(port)
            banners.append((port, banner))

def parse_ports(port_string):
    """
    Parse port string and return a list of ports to scan.
    Supports: single ports (80), comma-separated (80,22), and ranges (255*1000)
    """
    ports = []
    parts = port_string.split(',')

    for part in parts:
        part = part.strip()
        if '*' in part:
            # Handle range (e.g., "255*1000")
            try:
                start, end = part.split('*')
                start_port = int(start)
                end_port = int(end)

                # Validate port range
                if start_port < 1 or end_port > 65535:
                    print(f'[!] Invalid port range: {part} (ports must be 1-65535)')
                    continue
                if start_port > end_port:
                    print(f'[!] Invalid range: {part} (start > end)')
                    continue

                # Add all ports in range
                ports.extend(range(start_port, end_port + 1))
            except ValueError:
                print(f'[!] Invalid range format: {part}')
        else:
            # Handle single port
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    print(f'[!] Invalid port: {port} (must be 1-65535)')
            except ValueError:
                print(f'[!] Invalid port: {part}')

    return sorted(set(ports))

def write_result(host, ports, results):
    with open('result.txt', 'w') as f:
        f.write(f'[+] Scan completed on {host}\n')
        if len(ports)  == 1:
            f.write(f'[+] Scan result: found only {len(ports)} open port\n\n')
        else:
            f.write(f'[+] Scan result: found {len(ports)} open ports\n\n')
        for port, banner in zip(ports, results):
            f.write(f'Port {port}: OPEN\n')
            if banner:
                f.write(f'Banner: {banner}\n')
            else:
                f.write(f'Banner: No banner received\n')
            f.write('-' * 50 + '\n')


def port_scan(host, port_string):
    try:
        target_ip = gethostbyname(host)
    except:
        print(f'[-] Cannot resolve {host}: unknown host')
        return

    setdefaulttimeout(1)
    port_list = parse_ports(port_string)

    if not port_list:
        print('[!] No valid ports to scan')
        return

    print(f'[*] Scanning {len(port_list)} port(s) on {host} ({target_ip})')

    open_ports = []
    banners = []
    threads = []

    for p in port_list:
        t = threading.Thread(target=scan_port, args=(target_ip, p, open_ports, banners))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if open_ports:
        banners.sort(key=lambda x: x[0])
        sorted_ports = [p for p, _ in banners]
        sorted_banners = [b for _, b in banners]

        write_result(host, sorted_ports, sorted_banners)
        print(f'\n[*] Results saved to result.txt')
    else:
        print(f'\n[*] No open ports found')


def main():
    target_host, target_port = get_arguments()
    port_scan(target_host, target_port)


if __name__ == '__main__':
    main()
