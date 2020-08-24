---
published: true
---
---
title: HackTheBox-Nest
author: a3nk17
date: 2020-06-11 
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

