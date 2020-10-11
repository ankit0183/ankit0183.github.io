---
title: HackTheBox-BlackField
author: a3nk17
date: 2020-9-25 
excerpt: Blackfield was a fun Windows box from an open SMB share, validate that list using kerbrute, then find and crack the hash of an account with the AS-REProasting technique. After getting that first user, we'll use Bloodhound to discover that we can change another account's password, then from there access a previously locked down SMB share, retrieve an LSASS dump file and get more credentials. For the last part of the box we'll abuse the Backup Operators role to download a copy of the NTDS.dit file and recover the administrator NT hash.
thumbnail: /assets/img/posts/blackfield/info.png
categories: [HackTheBox, Retired]
tags: [ backup operators, pypykatz, usodllloader, bloodhound, ]
---


![info](/assets/img/posts/blackfield/info.png)


