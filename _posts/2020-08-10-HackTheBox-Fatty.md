---
title: HackTheBox-Fatty@10.10.10.174
author: a3nk17
date: 2020-08-011 
excerpt: Fatty is an insane linux box by qtc. its forced me way out of my comfort zone, Decompiling the server,search for a SQL-injectionIn & Inorder to escalate our privileges to root, we have to exploit a cronjob. which running on Docker.
thumbnail: /assets/img/posts/fatty/info.png
categories: [HackTheBox, Retired]
tags: [Deserialization, Java, npm, Window, Docker,]
---


![info](/assets/img/posts/fatty/info.png)



Machine Information @~Fatty
============================



|Conten| Descripcion |
|-----------|--------------|
| OS       |  Linux |
| Dificulty    | Insane |
| Points   | 50 |
| Release      | 08-Feb-2020 |
| IP    | 10.10.10.174 |
| Retired on | 08-Aug-2020 |
| Creator Of The System: | [jkr](https://www.hackthebox.eu/home/users/profile/77141)  |



Enumaration The Machine
========================

As we always start diging into rabbit hole by using `Nmap` as we see some useless information.


```bash
root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.174
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-18 14:57 EDT
Nmap scan report for 10.10.10.174
Host is up (0.014s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
1337/tcp open  waste
1338/tcp open  wmc-log-svc
1339/tcp open  kjtsiteserver

Nmap done: 1 IP address (1 host up) scanned in 8.45 seconds
root@kali# nmap -p 21,22,1337,1338,1339 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.174
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-18 15:04 EDT
Nmap scan report for 10.10.10.174
Host is up (0.013s latency).

PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp      15426727 Oct 30 12:10 fatty-client.jar
| -rw-r--r--    1 ftp      ftp           526 Oct 30 12:10 note.txt
| -rw-r--r--    1 ftp      ftp           426 Oct 30 12:10 note2.txt
|_-rw-r--r--    1 ftp      ftp           194 Oct 30 12:10 note3.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.19
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh                OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 fd:c5:61:ba:bd:a3:e2:26:58:20:45:69:a7:58:35:08 (RSA)
|_  256 4a:a8:aa:c6:5f:10:f0:71:8a:59:c5:3e:5f:b9:32:f7 (ED25519)
1337/tcp open  ssl/waste?
|_ssl-date: 2020-03-18T19:07:18+00:00; +2m35s from scanner time.
1338/tcp open  ssl/wmc-log-svc?
|_ssl-date: 2020-03-18T19:07:18+00:00; +2m35s from scanner time.
1339/tcp open  ssl/kjtsiteserver?
|_ssl-date: 2020-03-18T19:07:18+00:00; +2m35s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2m34s, deviation: 0s, median: 2m34s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 202.43 seconds
```

Recon
------

The standard nmap scan shows that `21` and `22` are the only open ports. Furthermore, nmap tells us that anonymous `FTP-access` is `allowed`. The full port scan shows three additional ports (1337, 1338 and 1339). Let us check out FTP, we can access `FTP` through `Annoymous` user

```bash
root@kali# ftp 10.10.10.174
Connected to 10.10.10.174.
220 qtc's development server
Name (10.10.10.174:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp      15426727 Oct 30 12:10 fatty-client.jar
-rw-r--r--    1 ftp      ftp           526 Oct 30 12:10 note.txt
-rw-r--r--    1 ftp      ftp           426 Oct 30 12:10 note2.txt
-rw-r--r--    1 ftp      ftp           194 Oct 30 12:10 note3.txt
226 Directory send OK.
ftp> prompt
Interactive mode off.
ftp> mget *
```

After `FTP` login as wee see there are some notes , we download all the notes into local machine `*mget`
Nothing is intrested in Notes but, From notes we can get information about high ports that are used for `fatty-client.jar`.


