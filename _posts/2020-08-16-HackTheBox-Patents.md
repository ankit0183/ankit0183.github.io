---
title: HackTheBox-Patents
author: a3nk17
date: 2020-06-08 
excerpt: Patents is a hard linux box by [gbyolo](https://www.hackthebox.eu/home/users/profile/36994).
The box starts with web-enumeration, which reveals a that webpage allows docx file upload and parses the document on server-side. This allows out-of-band XXE to leak arbitrary files. After leaking a config file from the server, 
thumbnail: /assets/img/posts/patents/info.png
categories: [HackTheBox, Retired]
tags: [linux, CMS, Bludit, sudo, npm]
---

![Info](/assets/img/posts/patents/info.png)




[Patents](https://www.hackthebox.eu/home/machines/profile/224) is a hard linux box by [gbyolo](https://www.hackthebox.eu/home/users/profile/36994).


The box starts with web-enumeration, which reveals a that webpage allows docx file upload and parses the document on server-side. This allows out-of-band `XXE` to leak arbitrary files. After leaking a config file from the server, we find a webpage that is vulnerable to directory-traversal. Using the directory-traversal we can use apache log poisoning to get a shell in the context of `www-data`. Enumerating the system, we find that we are in a docker environment. After running pspy, we get the password for the root user of the container and can read user.txt.

For root, we find a git repository, which contains source code and a binary for a server. We find that this server is running on port 8888. After reversing the binary, we find that the url-decode function is vulnerable to an overflow. Exploiting the overflow in url-decode we can leak the libc-base and use a simple rop-chain to get a shell as root. After getting root, we have to enumerate the system to find an unmounted disk. After mounting the disk, we get root.txt.

