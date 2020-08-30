---
published: true
---
---
title: HackTheBox-Quick
author: a3nk17
date: 2020-08-30 
excerpt: Quick was a hard box with multiple steps requiring the use of the QUIC protocol to access one section of the website and get the customer onboarding PDF with a set of default credentials. We get to play with ESI template injection to get the initial shell, then abuse a race condition in a PHP script so we can pivot to another user then finally we priv esc to root by finding credentials in the printer configuration file.
thumbnail: /assets/img/posts/quick/info.png
categories: [HackTheBox, Retired]
tags: [HTB, sql, Linux, web, SQLi, SQLMap, image upload, php injection, path injection,]
---

![info](/assets/img/posts/quick/info.png)
