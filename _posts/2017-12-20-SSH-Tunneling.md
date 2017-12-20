---
layout: post
title:  "SSH Tunneling"
categories: ssh
tags:  ssh tunneling
author: Trelis
---

* content
{:toc}

## Description
SSH's port forwarding feature can smuggle various types of Internet traffic into or out of a network. This can be used to avoid network monitoring or sniffers, or bypass badly configured routers on the Internet.




For example, from PC (10.76.20.110) it is not possible to access to my blog (lordatm.github.io) because there is a firewall blocking the connection. However, PC2 (10.76.20.108) can access to the website because it is in an other city.
So, the main objective is to send all the traffic from PC to PC2 and then to the server. This can be done using port forwarding via SSH:

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2017-12-20-SSH-Tunneling/SSH_Tunneling.png)

1. Connect PC and PC2 via SSH
2. Redirect all the traffic to the proxy
3. Configure the proxy in order to send all the traffic received via SOCKS to PC2
4. PC2 will make the requests to the server 

## Dynamic Port Forwarding SSH
Dynamic port forwarding turns your SSH client into a SOCKS proxy server. SOCKS is a little-known but widely-implemented protocol for programs to request any Internet connection through a proxy server. Each program that uses the proxy server needs to be configured specifically, and reconfigured when you stop using the proxy server. 

```
ssh -D 4444 root@10.75.20.108
```
The flag -D specifies a local “dynamic” application-level port forwarding. This works by allocating a socket to listen to port on the local side, optionally bound to the specified bind_address.  Whenever a connection is made to this port, the connection is forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine. 

Currently the SOCKS4 and SOCKS5 protocols are supported, and ssh will act as a SOCKS server.  Only root can forward privileged ports. Dynamic port forwarding can also be specified in the configuration file.

## Burp SOCKS Configuration
First of all, you need to configure your browser to redirect the traffic to Burp proxy and Burp to listen to the port 8080:

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2017-12-20-SSH-Tunneling/burp.png)

Secondly, you need to redirect all the traffic to the SSH that is listening to port 4444 in this example. In the tab "user options" you need to force Burp to use SOCKS and make the redirection to port 4444 of localhost:

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2017-12-20-SSH-Tunneling/burp_socks.png)

## Final result
In a normal connection, PC would negotiate the SSL directly with the server:

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2017-12-20-SSH-Tunneling/wireshark_normal.png)

However, in this scenario, PC negotiates the SSL handshake with the proxy and PC2 negotiates it with the server. So, the server doesn't know who made the request in first place, he thinks it was PC2:

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2017-12-20-SSH-Tunneling/wireshark_ssh.png)