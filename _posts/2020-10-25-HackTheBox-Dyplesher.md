---
published: true
---
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


Dyplesher, a Linux machine created by HackTheBox felamos & yuntao, was an overall insane difficulty box. The inital foothold was finding the .git folder on test.dyplesher.htb which give us the credentials for the memcache server trying rockyou we can leak few hashes from the memcache and we can crack one of that.Using the password we got from the memcache we can login to the gogs as felamos from which we see a gitlab mirror/backup. We see a repo.zip folder on the release page of the repository. After downloading that we see that is a git-bundle. After googling around i saw how unbundle that and get some information. from the repository we got we find a sqlite db looking into that we get another hash and Cracking that give another password. Trying that on the web server we are able to login and we see that we can upload Minecraft plugin. creating a plugin which write to user .ssh/authorized_keys and we can ssh to the user as MinatoTW. After getting a shell we still don’t find user.txt but checking the groups we see this user is a member of wireshark group. so i used dumpcap to capture some packets and sent that to local machine for analyses. which reveal some rabbitMQ messages containing all users password and rabbitMQ password for yunato. Su-ing to user felamos we see an interesting message which states yunato can publish message to plugin_data with an URL of cuberite plugin. so we create a bogus plugin to write to root authorized_keys and ssh-ing using that.

