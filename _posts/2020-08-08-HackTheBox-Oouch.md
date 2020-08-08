---
title: HackTheBox-Oouch
author: a3nk17
date: 2020-08-08 
excerpt: This is relatively an insane box , It works based on Oauth2 as feom which we get account linked to qtc (admin) using a SSRF and XXS,and in This docker running and we can ssh into it.Exploiting the uwsgi to get shell and then exploiting dbus to get shell as root.
thumbnail: /assets/img/posts/oouch/info.png
categories: [HackTheBox, Retired]
tags: [linux, CMS, Bludit, sudo, npm]
---

![Info](/assets/img/posts/oouch/info.png)


Machine Information 
===================



| ID | Details | 
|-------|--------|
| Name |  Oouch| 
| Points | 40 | 
| Difficulty | Hard |
| Creator |  [QTC](https://www.hackthebox.eu/home/users/profile/103578)| 
| Out On | 14 march 2020 | 
| Retired on | 1 Aug 2020 |


The Way to Find Neo
===================


*   Finding the hidden dir `Oauth`
*   Getting the token code for the account
*   Using ssrf in Contact page linking the account with `qtc`
*   Logging in as `qtc`
*   Buy Using `BurpSuit`
*   Getting `sessionid` of `qtc` Using xss + ssrf with the application we made
*   Grab the access code
*   Find out the `ssh private keys` of user qtc on `api`
*   Logging in as `qtc`
*   `Getting User.txt`
*   Finding the docker ip running on `172.17.8.0/16` and `172.18.8.0/16`
*   exploting the `uwsgi` service running as `www-data`
*   Finding the routes.py running the dbus as root
*   Exploting the `Dbus To get a shell as root`
*   `Getting root.txt`



Enumeration 
============



```bash
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp            49 Feb 11 19:34 project.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.6
|      Logged in as ftp
|      TYPE: ASCII
|      Session bandwidth limit in byte/s is 30000
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 8d:6b:a7:2b:7a:21:9f:21:11:37:11:ed:50:4f:c6:1e (RSA)
|_  256 d2:af:55:5c:06:0b:60:db:9c:78:47:b5:ca:f4:f1:04 (ED25519)
5000/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
| http-title: Welcome to Oouch
|_Requested resource was http://10.10.10.177:5000/login?next=%2F
8000/tcp open  rtsp
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   RTSPRequest: 
|     RTSP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   SIPOptions: 
|     SIP/2.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|_    <h1>Bad Request (400)</h1>
|_http-title: Site doesn't have a title (text/html).
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.80%I=7%D=6/7%Time=5EDCB6BB%P=x86_64-pc-linux-gnu%r(Get
SF:Request,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h
SF:1>")%r(FourOhFourRequest,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nCont
SF:ent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Requ
SF:est\x20\(400\)</h1>")%r(HTTPOptions,64,"HTTP/1\.0\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1>
SF:Bad\x20Request\x20\(400\)</h1>")%r(RTSPRequest,64,"RTSP/1\.0\x20400\x20
SF:Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization\
SF:r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>")%r(SIPOptions,63,"SIP/2\.0\x
SF:20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Autho
SF:rization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%), Linux 3.5 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


Recon
======

The open ports shown are **21**, **22**, **5000** and **8000**. Nmap tells us that anonymous FTP-access is allowed. Furthermore, we can see from the nmap scan result that http is running on port 5000. Let us quickly check out the project.txt file, that nmap has shown us for FTP.


FTP
====

I did `anonymous` login and it says `qtc's development server` maybe it can be a valid user and found a `project.txt` file there. Downloaded that to my machine.


```bash
root@kali:~# ftp 10.10.10.177 
Connected to 10.10.10.177.
220 qtc's development server
Name (10.10.10.177:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            49 Feb 11 19:34 project.txt
226 Directory send OK.
ftp> get project.txt
local: project.txt remote: project.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for project.txt (49 bytes).
226 Transfer complete.
49 bytes received in 0.00 secs (1.1126 MB/s)
```

`project.txt`


```bash
root@kali:~/CTF/HTB/Boxes/Oouch# cat project.txt 
Flask -> Consumer
Django -> Authorization Server
```


