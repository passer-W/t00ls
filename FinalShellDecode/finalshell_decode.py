import os
import argparse
import re
import colorama

pattern = b'"user_name":"(.*?)".*?"password":"(.*?)".*?"host":"(.*?)"'

colorama.init(autoreset=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="decode finalshell's password")
    parser.add_argument("-p", "--path", help="the finalshell's root path, example: E:\\finalshell")
    option = parser.parse_args()
    path = option.path
    if os.path.exists(os.path.join(path, "conn")):
        for r, d, fs in os.walk(os.path.join(path, "conn")):
            for f in fs:
                if "connect_config.json" in f:
                    file = open(os.path.join(r, f), "rb")
                    info = (re.findall(pattern, file.read())[0])
                    try:
                        password = (os.popen(f"java FinalShellDecodePass {info[1].decode()}").read().strip())
                        print(f"[+] Host: \033[36m{info[2].decode()}\033[00m UserName: \033[36m{info[0].decode()}\033[00m Password: \033[36m{password}\033[00m")
                    except:
                        print(f"[-]Host: {info[0].decode()} UserName: {info[1].decode()}")
