---
layout: post
title:  "Proxy Certificates"
categories: Proxy
tags:  burp proxy
author: Trelis
---

* content
{:toc}

# Description
In this post I will explain how SSL handshake works, how the client can detect there is a proxy intercepting the communications and how to set up the proxy in order to successfully intercept the communications.




Before establishing the SSL connection, the client and the server negotiate the ciphers and exchange the keys and certificates. When there is a proxy intercepting the communications, the client will make the negotiation with the proxy instead of the server, so the proxy will be the one who sends his certificate to the client.

Sometimes, the client have some controls which allow to detect man in the middle attacks:
* Trusted CA
* Certificate Pinning


I will use this scenario as an example: 
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2017-11-27-Invisible-Proxy/draw_proxy.png)
1. Client asks for the IP of myexample.com
2. From `hosts` file it takes the IP is 1.2.3.4
3. Client makes the requests to 1.2.3.4 with port 443
4. Proxy makes the requests to the server (redirecting the traffic)
5. Server answers to the proxy
6. Proxy answers to the client

# SSL Handshake 
## No client certificate
Every SSL/TLS connection begins with a “handshake” – the negotiation between two parties that nails down the details of how they’ll proceed. The handshake determines what cipher suite will be used to encrypt their communications, verifies the server, and establishes that a secure connection is in place before beginning the actual transfer of data. 

The following image is a summary of the handshake:
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2017-12-16-Proxy-Certificates/Handshake_Server_cert.png)
1. Client requests to the server an encrypted session and sends his cipher suites.
2. Server answers with a cipher suite.
3. Server sends his certificate and public key.
4. Client verifies server certificate and they exchange the keys they will use to encrypt and decrypt the communication

In the following wireshark screenshot you can see all the hadnshake process:
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2017-12-16-Proxy-Certificates/server_certificate.png)


## Client certificate
Some webpages, usually companies internal websites, may require an extra step in the handshake. Not only the server authenticates but also the client. This allows the server to verify the certificate sent by the client making the comparative with a whitelist.

The following image is a summary of the handshake:
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2017-12-16-Proxy-Certificates/Handshake_Client_cert.png)
1. Client requests to the server an encrypted session and sends his cipher suites.
2. Server answers with a cipher suite.
3. Server sends his certificate, public key and request the certificate of the client.
4. Client verifies server certificate and server verifies client certificate
5. They exchange the keys they will use to encrypt and decrypt the communication.


In the following wireshark screenshot you can see all the hadnshake process:
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2017-12-16-Proxy-Certificates/client_certificate.png)

# Proxy detection methods
## Browser warning


## Trusted CA

## Certificate Pinning


# Certificate installation 
## Browser (HTTPS connection)

## Java

