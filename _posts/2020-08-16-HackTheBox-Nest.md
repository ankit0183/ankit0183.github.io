---
published: false
---
---
title: HackTheBox-Nest
author: a3nk17
date: 2020-06-11 
excerpt: Nest is an easy windows box by VbScrub.The box starts with guest SMB enumeration, where we find credentials for a user.In order to get root, we first have to get the debug password for the service running on port 4386
thumbnail: /assets/img/posts/nest/info.png
categories: [HackTheBox, Retired]
tags: [[HTB, CTF, Hack The Box, Security, SMB, VB, VisualBasic, Crypto, AES,]
---

![info](/assets/img/posts/nest/info.png)



[Nest](https://www.hackthebox.eu/home/machines/profile/225) is an easy windows box by [VbScrub](https://www.hackthebox.eu/home/users/profile/158833).

The box starts with guest `SMB enumeration`, where we find credentials for a user. Further enumerating the `smb-share` with the user, we find an encrypted password and a `VisualBasic` Project. This project can be used to decrypt the password that was encrypted using `AES`. Using the decrypted password, we can access to home folder of the user and read user.txt.

In order to get root, we first have to get the `debug password` for the service running on port `4386`, which is hidden in an `ADS` (Alternate Data Stream). The debug password allows us to use `path-traversal` and read a `config` file containing the encrypted `administrator password`. In order to decrypt the password, we have to `decompile` an exe to get the key and IV. We can then decrypt the password, which is encrypted using AES. With the administrator password we can use psexec to get a shell on the system and read root.txt.

