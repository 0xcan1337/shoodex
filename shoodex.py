#!/usr/bin/env python3
"""
Shoodex
"""
import re
import time
import json
import os
import cgi
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from io import BytesIO

try:
    import requests
except ImportError:
    print("ERROR: 'requests' required. Installation: pip install requests")
    exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("ERROR: 'beautifulsoup4' required. Installation: pip install beautifulsoup4")
    exit(1)

try:
    import ipaddress
except ImportError:
    ipaddress = None

PORT = 5000
SHODAN_DELAY = 4  # delay


def is_blocked_ip(ip_str):
    ip_str = (ip_str or "").strip()
    if not ip_str:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr == ipaddress.IPv4Address("0.0.0.0"):
            return True
        if isinstance(addr, ipaddress.IPv4Address):
            return addr.is_loopback or addr.is_private
        return addr.is_loopback
    except ValueError:
        return True


def parse_shodan_ports(html_content):
   
    soup = BeautifulSoup(html_content, 'html.parser')
    ports = []

    for h6 in soup.find_all('h6', class_='grid-heading'):
        span = h6.find('span', attrs={'data-clipboard': True})
        if not span:
            continue

        span_text = span.get_text(separator=' ', strip=True)
        port_match = re.search(r'(\d+)\s*/\s*(tcp|udp)', span_text, re.IGNORECASE)
        if not port_match:
            continue

        port_num = port_match.group(1)
        protocol = port_match.group(2).lower()
        port_label = f"{port_num}/{protocol}"

        port_info = {
            'port': port_label,
            'product': None,
            'title': None,
            'http_status': None,
            'service': None,
        }

        banner_div = None
        for sibling in h6.find_next_siblings():
            if sibling.name == 'h6' and 'grid-heading' in sibling.get('class', []):
                break
            if sibling.name == 'div' and 'banner' in sibling.get('class', []):
                banner_div = sibling
                break

        if not banner_div:
            ports.append(port_info)
            continue

        product_tag = banner_div.select_one('h1.banner-title')
        if product_tag:
            port_info['product'] = product_tag.get_text(separator=' ', strip=True)

        http_title_div = banner_div.select_one('div.http-title')
        if http_title_div:
            title_link = http_title_div.find('a', class_='text-dark')
            if title_link:
                port_info['title'] = title_link.get_text(strip=True)

        pre_tag = banner_div.find('pre')
        if pre_tag:
            banner_text = pre_tag.get_text()
            http_match = re.search(r'HTTP/[\d.]+ \d{3}[^\r\n]*', banner_text)
            if http_match:
                port_info['http_status'] = http_match.group(0).strip()
            lines = [l.strip() for l in banner_text.splitlines() if l.strip()]
            port_info['service'] = '\n'.join(lines[:6])

        ports.append(port_info)

    return ports


def format_port_info(port_data):
   
    lines = []
    lines.append(f"  ┌─ {port_data['port']}")
    if port_data.get('product'):
        lines.append(f"  │  Product   : {port_data['product']}")
    if port_data.get('title'):
        lines.append(f"  │  Title : {port_data['title']}")
    if port_data.get('http_status'):
        lines.append(f"  │  HTTP   : {port_data['http_status']}")
    if port_data.get('service'):
        for service_line in port_data['service'].split('\n')[:4]:
            lines.append(f"  │  {service_line}")
    lines.append(f"  └{'─' * 40}")
    return '\n'.join(lines)


def check_ip_on_shodan(ip, delay=4):
    
    url = f"https://www.shodan.io/host/{ip}"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            return (ip, False, [], "    → 404 Not Found - No data\n")

        if "No information available" in response.text or "404: Not Found" in response.text:
            return (ip, False, [], "    → No data\n")

        if response.status_code == 200:
            ports = parse_shodan_ports(response.text)
            return (ip, True, ports, None)

        return (ip, False, [], f"    ? (Status: {response.status_code})\n")

    except requests.exceptions.RequestException as e:
        return (ip, False, [], f"    ! Error: {e}\n")

    finally:
        time.sleep(delay)


def send_line(wfile, line):
   
    if isinstance(line, bytes):
        data = line
    else:
        data = (line if line.endswith('\n') else line + '\n').encode('utf-8')
    wfile.write(data)
    wfile.flush()


def stream_scan(ip_list, wfile, delay=4):
  
    found_ips = []

    send_line(wfile, f"\n{'='*60}\n")
    send_line(wfile, f"A total of {len(ip_list)} IP addresses will be checked.\n")
    send_line(wfile, f"Delay: {delay} second\n")
    send_line(wfile, f"{'='*60}\n\n")

    for idx, ip in enumerate(ip_list, 1):
        if is_blocked_ip(ip):
            send_line(wfile, f"\n[{idx}/{len(ip_list)}] ")
            send_line(wfile, f"[*] Scanning: {ip}\n")
            send_line(wfile, f"    ! Error.\n")
            continue

        send_line(wfile, f"\n[{idx}/{len(ip_list)}] ")
        send_line(wfile, f"[*]Scanning: {ip}\n")

        ip_addr, has_info, ports, status_msg = check_ip_on_shodan(ip, delay)

        if has_info:
            if ports:
                send_line(wfile, f"    ✓ DATA FOUND! ({len(ports)} open)\n")
                for p in ports:
                    send_line(wfile, format_port_info(p) + "\n")
            else:
                send_line(wfile, f"    ✓ DATA FOUND! (Port details could not be parsed.)\n")
            found_ips.append((ip_addr, ports))
        else:
            if status_msg:
                send_line(wfile, status_msg)
            else:
                send_line(wfile, f"    → No data\n")

    # Sonuç dosyası içeriği (script ile aynı format)
    output_lines = []
    output_lines.append(f"Result: - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    output_lines.append("=" * 60 + "\n\n")

    for ip, ports in found_ips:
        output_lines.append(f"IP: {ip}\n")
        output_lines.append(f"Shodan URL: https://www.shodan.io/host/{ip}\n")
        if ports:
            output_lines.append(f"Open ports: {len(ports)}\n\n")
            for p in ports:
                output_lines.append(f"  Port      : {p['port']}\n")
                if p.get('product'):
                    output_lines.append(f"  Product      : {p['product']}\n")
                if p.get('title'):
                    output_lines.append(f"  Title    : {p['title']}\n")
                if p.get('http_status'):
                    output_lines.append(f"  HTTP status: {p['http_status']}\n")
                if p.get('service'):
                    for line in p['service'].split('\n')[:4]:
                        output_lines.append(f"  Service    : {line}\n")
                output_lines.append("  " + "-" * 40 + "\n")
        else:
            output_lines.append("  (Port details could not be parsed.)\n")
        output_lines.append("\n" + "=" * 60 + "\n\n")

    result_content = "".join(output_lines)

    send_line(wfile, f"\n{'='*60}\n")
    send_line(wfile, f"✓ COMPLETED!\n")
    send_line(wfile, f"{'='*60}\n")
    send_line(wfile, f"IPs found: {len(found_ips)}/{len(ip_list)}\n")

    send_line(wfile, "SCAN_COMPLETE\n")
    wfile.write(result_content.encode('utf-8'))
    wfile.flush()


class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/scan":
            content_type = self.headers.get('Content-Type', '')
            ip_list = []

            if 'multipart/form-data' in content_type:
                try:
                    form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={
                        'REQUEST_METHOD': 'POST',
                        'CONTENT_TYPE': self.headers['Content-Type'],
                    })
                    if 'file' in form:
                        fileitem = form['file']
                        if fileitem.file:
                            raw = fileitem.file.read()
                            try:
                                text = raw.decode('utf-8')
                            except UnicodeDecodeError:
                                text = raw.decode('latin-1')
                            ip_list = [line.strip() for line in text.splitlines() if line.strip()]
                except Exception as e:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode())
                    return
            else:
                length = int(self.headers.get('Content-Length', 0))
                if length:
                    body = self.rfile.read(length)
                    try:
                        data = json.loads(body.decode('utf-8'))
                        text = data.get('contents', data.get('ips', ''))
                    except Exception:
                        text = body.decode('utf-8', errors='replace')
                    ip_list = [line.strip() for line in text.splitlines() if line.strip()]

            if not ip_list:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "IP list is empty or invalid."}).encode())
                return

            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            try:
                stream_scan(ip_list, self.wfile, SHODAN_DELAY)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "":
            self.path = "/index.html"
        return SimpleHTTPRequestHandler.do_GET(self)


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Shoodex is running: http://127.0.0.1:{PORT}")
    print("Upload a TXT file and start the scan.")
    print("")
    server.serve_forever()


if __name__ == "__main__":
    main()
