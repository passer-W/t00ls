usage: test_ip.py [-h] [-f FILE] [-i IP] [-c COOKIE] [-o OUT]

optional arguments:
  -h, --help            show this help message and exit
  -v VPN, --vpn VPN     input the webvpn url
  -f FILE, --file FILE  input the ip file to scan
  -i IP, --ip IP        input the ip list to scan
  -c COOKIE, --cookie COOKIE
                        input the webvpn cookie
  -o OUT, --out OUT     input the file to save the result


默认扫描同目录下ip.txt文件，默认扫描80，81，8080，8081端口，可自行调整
可输入-v参数以设置webvpn地址
-i参数以扫描某一网段ip，
-f参数为扫描某一文件内ip列表，
-c参数为cookie中的wengine_vpn_ticket值，
-o为输出结果文件，默认输出至同目录下scan.txt文件，结果格式为[ip,port,webvpn_ip,title]
有时webvpn会自动退出，或访问出现502错误，可等待一会后重新测试
