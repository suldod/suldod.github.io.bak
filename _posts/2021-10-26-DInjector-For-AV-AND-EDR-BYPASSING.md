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

```     (    (
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
