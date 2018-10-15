---
layout: post
title:  "Windows - LLMNR and NBT-NS poisoning using Responder"
categories: "Windows"
tags:  windows responder
author: Trelis
---

* content
{:toc}

In this article it will be shown how it works Microsoft Windows's name resolution services and how can it be abused.




# Name resolution procedure
Computers with Windows operation system communicates with each other in order to perform name resolution.

This process proceed with some steps as follows:
1. File "hosts" is checked to obtain system information and configuration
2. Check the local DNS Cache: DNS Cache can be learned with the ipconfig or displaydns command
3. Send query to DNS: if the computer doesn't find information about the device it wants to access in the configuration files, it will send a query to the DNS server on the local network.
4. Send LLMNR query
5. Send NBF-NSquery

# LLMNR
## Description
The goal of Link-Local Multicast Name Resolution (LLMNR) is to enable name resolution in scenarios in which conventional DNS name resolution is not possible. Since LLMNR only operates on the local link, it cannot be considered a substitute for DNS.


## Protocol details
It is served by the link-scope multicast address:
* IPv4 - 224.0.0.252, MAC address 01-00-5E-00-00-FC
* IPv6 - FF02:0:0:0:0:0:1:3, MAC address 33-33-00-01-00-03

It performs all operations via TCP and UDP port 5355.



# NBT-NS
## Description
NetBIOS is an API that the systems in the local network use to communicate with each other.

## Protocol details
There are three different NetBIOS services:
* Name Service: operates in 137 UDP port. Used for name registration and resolution.
* Datagram Distribution Service: operates in 138 UDP port. Used for connectionless communications.
* Session Services: operates in 139 TCP port. Used for connection-oriented communications.



# Vulnerability
## Description
When a machine has these protocols enabled, if the local network DNS is not able to resolve the name, the machine will ask to all hosts of the network. So, any host of the network, who knows its IP, can reply. Even if a host replies with an incorrect information, it will be still regarded as legitimate.

For example, if a user fails in writing the name of a shared folder, the following error will be shown:
![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-07-31-Windows-LLMNR-NBTNS-Poisoning-Responder/error.png)

Capturing the traffic with Wireshark, it can be seen how the computer asks in broadcast if anyone knows how to resolve the name:
![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-07-31-Windows-LLMNR-NBTNS-Poisoning-Responder/netbios_wireshark1.png)


## Scenario
![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-07-31-Windows-LLMNR-NBTNS-Poisoning-Responder/diagram.png)

1. The victim will try to connect to the file sharing system, named "trelis24Test", which he typed incorrectly.
2. The name resolution, which will be performed with the steps mentioned earlier, will be questioned on the victim’s computer first.
3. In step 3, because of the DNS Server does not have a corresponding record, the name of the system is sent as LLMNR or NetBIOS-NS query.
4. The attacker listens to network traffic, catches name resolution query. It tells to the victim that he is the one the victim is look for.

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

To start listening, determine the interface:
```
responder –I eth0
```

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-07-31-Windows-LLMNR-NBTNS-Poisoning-Responder/responder.PNG)


With this running, if a client now tries to resolve a name not in the DNS, the instance of Responder should poison the LLMNR and NBT-NS requests that are sent out.

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-07-31-Windows-LLMNR-NBTNS-Poisoning-Responder/responder_answer.PNG)


If a user requests a network resource that doesn't exist, Responder should say its IP knows the resource location. The victim will try to connect to the resource in the attacking machine using SMB. In the authentication process, the victim will send the username and hashed password:

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2018-07-31-Windows-LLMNR-NBTNS-Poisoning-Responder/wireshark_netbios.PNG)



# Post explotation
Responder keeps the logs and hash values it detects under:
```
/usr/share/responder/logs
```

NTLMv2 hashes can not be used directly for Pass the Hash attacks. So, a cracking attack must be used in order to obtain plain-text password. There are several tools for hash cracking: John the Ripper, Hashcat, Cain&Abel, Hydra, etc.

## John the Ripper
```
john SMB-NTLMv2-SSP.txt –wordlist=/usr/share/wordlists/rockyou.txt
```

## Hashcat
```
hashcat -m 5600 SMB-NTLMv2-Client.txt /usr/share/wordlists/rockyou.txt
```


# Mitigation
To mitigate this attack from potentially happening in a local network domain, it is best to disable LLMNR and NBT-NS.

Otherwise, host-based security software can be used to block LLMNR/NetBIOS traffic. 


# Detection
There are some detection networks that can be used to prevent a security incident:
* Monitor HKLM\Software\Policies\Microsoft\Windows NT\DNSClient for changes to the "EnableMulticast" DWORD value. A value of “0” indicates LLMNR is disabled.8
* Monitor for traffic on ports UDP 5355 and UDP 137 if LLMNR/NetBIOS is disabled by security policy.
* Deploy an LLMNR/NBT-NS spoofing detection tool.