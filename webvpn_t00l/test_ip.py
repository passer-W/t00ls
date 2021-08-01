import csv
import re

import requests
from Crypto.Cipher import AES

import ip_enc_t00l
import IPy
import threading
import argparse
import colorama

colorama.init(autoreset=False)
valid_ip_list = []



key = "wrdvpnisthebest!"
iv = "wrdvpnisthebest!"
model = AES.MODE_OFB
cookies = {
    "wengine_vpn_ticket": "e3436dc1fae3c051",
    "refresh": "1"
}
headers = {
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
"Accept-Encoding": "gzip, deflate"
}


def add_16(text, mode):
    segmentByteSize = 16 if mode == "utf-8" else 32
    if len(text) % segmentByteSize == 0:
        return text
    else:
        return text + "0" * (segmentByteSize - len(text))


def enc_ip(ip, port):
    aes = AES.new(key.encode("utf-8"), model, iv.encode("utf-8"))
    hash_ip = add_16(ip, "utf-8").encode("utf-8")
    protocal = f"http-{port}/"
    return protocal + iv.encode().hex() + aes.encrypt(hash_ip).hex()[0:len(ip) * 2]


def get_url(url, port, vpn_url):
    ip = url.replace("http://", "").split(":")[0]
    return vpn_url + enc_ip(ip, port) + "/?wrdrecordvisit=record"

def decrpt_ip(ip):
    aes = AES.new(key.encode("utf-8"), model, iv.encode("utf-8"))
    return aes.decrypt(bytes.fromhex(ip[32:]))


class Test(threading.Thread):
    def __init__(self, ip, port, vpn_url):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.url = get_url(self.ip, self.port, vpn_url)

    def run(self):
        global cookies
        try:
            resp = requests.get(self.url, timeout=2, cookies=cookies, headers=headers)
            if "fail" in resp.text or "Not Found" in resp.text or "访问出错" in resp.text:
                raise Exception
            else:
                title = re.findall("<title>(.*?)</title>", resp.text)[0]
                if "访问被拒绝" in title or "VPN登录" in title:
                    raise Exception
                print("\033[31m[+]%s:%s\033[00m - %s (%s)"%(self.ip, self.port, title, self.url))
                valid_ip_list.append([self.ip, self.port, self.url, title])
        except:
            print("[-]%s:%s"%(self.ip, self.port))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--vpn", help="input the webvpn url")
    parser.add_argument("-f", "--file", default="ip.txt", help="input the ip file to scan")
    parser.add_argument("-i", "--ip", default="", help="input the ip list to scan")
    parser.add_argument("-c", "--cookie", default=cookies["wengine_vpn_ticket"], help="input the webvpn cookie")
    parser.add_argument("-o", "--out", default="scan.txt", help="input the file to save the result")
    args = parser.parse_args()
    ip = args.ip
    ip_file = open(args.file, "r")
    scan_file = open(args.out, "ab")
    cookies["wengine_vpn_ticket"] = args.cookie
    ip_list = []
    vpn_url = args.vpn + "/" if not args.vpn[-1] == "/" else ""
    if ip != "":
        for i in IPy.IP(ip):
            ip_list.append(str(i))
    else:
        ip_file = open("ip.txt", "r")
        for i in ip_file.readlines():
            i = i.strip()
            for ip in IPy.IP(i):
                ip_list.append(str(ip))
    test_list = []
    for i in ip_list:
        for p in ["80", "81", "8080", "8081"]:
            test_list.append(Test(i, p, vpn_url))
            if len(test_list) % 100 == 0:
                for t in test_list:
                    t.start()
                for t in test_list:
                    t.join()
                test_list = []
    for t in test_list:
        t.start()
    for t in test_list:
        t.join()
    for i in valid_ip_list:
        print(str(i))
        scan_file.write(",".join(i).encode()+b"\n")
