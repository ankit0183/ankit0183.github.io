---
published: false
---
---
title: HackTheBox-Oouch
author: a3nk17
date: 2020-08-08 
excerpt: This is relatively an insane box , It revolves around the Oauth2 as feom which we get account linked to qtc (admin) using a SSRF and then a xss in which just gave we have to steal cookies of the user qtc and from that sesion id we logged into api and get the ssh-keys for user.There is a docker running and we can ssh into it.Exploiting the uwsgi to get shell as www-data and then exploiting dbus to get shell as root.
thumbnail: /assets/img/posts/oouch/info.png
categories: [HackTheBox, Retired]
tags: [linux, CMS, Bludit, sudo, npm]
---

![Info](/assets/img/posts/oouch/info.png)