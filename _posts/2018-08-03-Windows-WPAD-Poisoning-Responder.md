---
layout: post
title:  "Windows - WPAD poisoning using Responder"
categories: "Windows"
tags:  windows responder
author: Trelis
---

* content
{:toc}

In this article it will be shown how it works Microsoft Windows's name resolution services and how can it be abused.




# WPAD
## Description
Organizations allow employees to access Internet through proxy servers to increase performance, ensure security and track traffic. Users who connect to the corporate network need to know which proxy server they have to use without doing any configuration.

If a browser is configured to automatically detect proxy settings, then it will make use of WPAD protocol to locate and download the wpad.dat, Proxy Auto-Config (PAC) file. 


## Protocol details
It searches computers named as “wpad” on the local network to find this file. And then following steps are carried out:
1. If the DHCP Server is configured, the client retrieves the wpad.dat file from the DHCP Server (if successful, step 4 is taken).
2. The wpad.corpdomain.com query is sent to the DNS server to find the device that is distributing the Wpad configuration. (If successful, step 4 is taken).
3 Send LLMNR or NBNS query for WPAD (if success, go step 4 else proxy can’t be use)
4. Download wpad.dat and use it.

In the following traffic capture, the machine sends the NBNS packets in broadcast asking for the wpad.dat:
![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-08-03-Windows-WPAD-Poisoning-Responder/wireshark1.png)


# Vulnerability
## Description
When a machine has these protocols enabled, if the local network DNS is not able to resolve the name, the machine will ask to all hosts of the network. So, any host of the network, who knows its IP, can reply. Even if a host replies with an incorrect information, it will be still regarded as legitimate.

## Scenario
1. The victim will open the browser which is configured with the option "automatically detect settings" in "Local Area Network (LAN) Settings".
2. The name resolution, which will be performed with the steps we mentioned earlier, will be questioned on the victim’s computer first.
3. In step 2, because of the DNS Server does not have a corresponding record, the name of the system is sent as LLMNR or NetBIOS-NS query.
4. The attacker listens to network traffic, catches name resolution query. It tells to the victim that he has the wpad.dat the victim is look for.

According to the sequence above, if an attacker wants to be sure that the attack is successful, he must do:
1. DHCP poisoning attack
2. DNS poisoning attack
3. WPAD poisoning attack

This article is focused only in attacking the third step, making the assumption that neither DHCP nor DNS are configured.


# Exploiting
## Responder
Responder is a tool created by Laurent Gaffie used to obtain network credentials. This tool listens and answers LLMNR and NBT-NS procotols. 

Creating authentication services like SMB, MSSQL, HTTP, HTTPS, FTP, POP3, SMTP, Proxy WPAD, DNS, LDAP, etc, it will try that the victim sends its credentials to any of this services so the attacker can steal them. 

## Proof of Concept
To demonstrate the attack, Kali Linux is used to steal the credentials of a Windows 10 user. Kali has Responder pre-installed and can be found at the directory:
```
/usr/share/responder/
```

When the victim makes WPAD name resolution to the attacker WPAD fake server, it creates an authentication screen and it asks the client to enter his domain credentials. 

```
responder -I eth0 -wFb
```

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-08-03-Windows-WPAD-Poisoning-Responder/responder1.PNG)

The victim will see the following dialog box:

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-08-03-Windows-WPAD-Poisoning-Responder/authentication.PNG)


If the victim enters the credentials, the attacker will receive the username and password in clear-text:

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-08-03-Windows-WPAD-Poisoning-Responder/responder2.PNG)

With Wireshark, it can be seen how the victim tries to retrieve the wpad.dat file and it sends the password encoded with Base64:

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-08-03-Windows-WPAD-Poisoning-Responder/wireshark2.png)



Moreover, Responder is able to redirect the user to a fake webpage or serve a malicious executable.

The following changes must be done in the responder.conf file:
```
[HTTP Server]

; Set to On to replace any requested .exe with the custom EXE
Serve-Exe = On 

; Set to On to serve the custom HTML if the URL does not contain .exe
; Set to Off to inject the 'HTMLToInject' in web pages instead
Serve-Html = On
 ```

Then start Responder:
```
responder -I eth0 -I 10.7.7.31 -r On -w On -wFb
```

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-08-03-Windows-WPAD-Poisoning-Responder/responder3.PNG)


Now, when the victim tries to use the browser, he will see the following page:
![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-08-03-Windows-WPAD-Poisoning-Responder/malicious_website2.png)

If, by chance, the victim clicks the link, a reverse shell will be downloaded:
![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-08-03-Windows-WPAD-Poisoning-Responder/responder4.PNG)

Finally, if the victim executes the malicious executable, with netcat in port 140 the attacker will be able to obtain access to the victim's computer:
![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-08-03-Windows-WPAD-Poisoning-Responder/shell.png)


# Mitigation
* First solution for this attack is, create DNS entry with “WPAD” that points to the corporate proxy server. So the attacker won’t be able to manipulate the traffic.
* Second solution is disable “Autodetect Proxy Settings” on all browsers.