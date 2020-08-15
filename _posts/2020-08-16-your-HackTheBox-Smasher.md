---
title: HackTheBox-Smasher
author: a3nk17
date: 2019-01-11 
excerpt: Smasher is a really hard box with three challenges that require a detailed understanding of how the code you’re intereacting with works.In Beyond Root, I’ll check out the AES script, and show how I patched the checker binary.
thumbnail: /assets/img/posts/smasher/info.png
categories: [HackTheBox, Retired]
tags: [xakepru, write-up, hackthebox, machine, pwn-64, linux, masscan, tiny-web-server, path-traversal, wget-mirror, diff, code-analysis, gdb-fork, python3-pwntools, ret2shellcode, ret2bss, ssh-key-injection, linenum.sh, padding-oracle, aes-cbc, pkcs7, binary-analysis, reverse, race-condition, ghidra, cutter, strace, binary-patching, pvs-studio]
---


![info](/assets/img/posts/smasher/info.png)



Smasher is a really `hard` box with three challenges that require a detailed understanding of how the code you’re intereacting with works. It starts with an instance of shenfeng tiny-web-server running on port 1111. I’ll use a path traversal vulnerability to access to the root file system. I’ll use that to get a copy of the source and binary for the running web server. With that, I’ll write a buffer overflow exploit to get a reverse shell. Next, I’ll exploit a padding oracle vulnerability to get a copy of the smasher user’s password. From there, I’ll take advantage of a timing vulnerability in setuid binary to read the contents of root.txt. I think it’s possible to get a root shell exploiting a buffer overflow, but I wasn’t able to pull it off (yet). In Beyond Root, I’ll check out the AES script, and show how I patched the checker binary.

### Summary

- The `webserver` used is vulnerable to a path `traversal bug` and `buffer overflow` in the GET parameter
- By using the path traversal bug we can get the `Makefile` and copy of the webserver executable
- The buffer overflow can be solved by leaking libc's base address and then building a `ropchain` to `ret2libc`
- To gain user, we have to solve an `Oracle padding` challenge that gives us the user password
- Priv esc is a `race condition` in a suid root `ELF binary`, we can swap out the file with a `symlink` to /root/root.txt to get the root flag

### Tools used

- pwntools
- [https://libc.blukat.me/](https://libc.blukat.me/)
- [https://github.com/twd2/padding-oracle-attack/blob/master/attack.py](https://github.com/twd2/padding-oracle-attack/blob/master/attack.py)


