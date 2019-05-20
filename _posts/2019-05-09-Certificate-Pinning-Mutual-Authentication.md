---
layout: post
title:  "Certificate Pinning and Mutual Authentication"
categories: Proxy
tags:  proxy MITM
author: Trelis
---

* content
{:toc}

In this post I will explain how SSL handshake works, what is certificate pinning and mutual authentication and how an attacker can bypass these controls.




# SSL Handshake 
Every SSL/TLS connection begins with a “handshake” – the negotiation between two parties that nails down the details of how they will proceed. The handshake determines what cipher suite will be used to encrypt their communications, verifies the server, and establishes that a secure connection is in place before beginning the actual transfer of data. 

The following image is a summary of the handshake:
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2019-05-09-Certificate-Pinning-Mutual-Authentication/Handshake_Server_cert.png)
1. Client requests to the server an encrypted session and sends his cipher suites.
2. Server answers with a cipher suite.
3. Server sends his certificate and public key.
4. Client verifies server certificate and they exchange the keys they will use to encrypt and decrypt the communication

In the following wireshark screenshot you can see all the hadnshake process:
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2019-05-09-Certificate-Pinning-Mutual-Authentication/server_certificate.png)

# Man-In-The-Middle Attack
By default, when making an SSL connection, the client checks that the server’s certificate:
* Has a verifiable chain of trust back to a trusted (root) certificate
* Matches the requested hostname

What it doesn't check is if the certificate in question is the expected certificate.

The main problem of only checking the chain of trust and the hostname of the certificte is that the browser trust CA or devices trust store can be easly compromised.

A MITM attack is when the attacker is able to intercept the communications between the client and the server. Before establishing the SSL connection, the client and the server negotiate the ciphers and exchange the keys and certificates. When there is a proxy intercepting the communications, the client will make the negotiation with the proxy instead of the server, so the proxy will be the one who sends his certificate to the client.


I will use this scenario as an example: 
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2017-11-27-Invisible-Proxy/draw_proxy.png)
1. Client asks for the IP of myexample.com
2. From `hosts` file it takes the IP is 1.2.3.4
3. Client makes the requests to 1.2.3.4 with port 443
4. Proxy makes the requests to the server (redirecting the traffic)
5. Server answers to the proxy
6. Proxy answers to the client

With this escenario, when the handshake is performed the certificate that the client receives (step 3 of the hanshake figure) is the proxy certificate instead of the server one. This is because the proxy is between the client and the server breaking the SSL communication. 

In order to not raise suspicions, the attacker should install the Proxy CA into the client's browsers. Otherwise, the client will receive a warning because it the browser fails to verify the chain of trust and hostname of the proxy certificat.

Once done that, the attacker will be able to see and modify any request and response between the client and the server.


# Controls
There are two different controls that make the MITM attack more difficult to perform. 

## Certificate Pinning
The client is pre-configured to know what server certificate should expect. Although the certificate has a correct chain of trust and hostname, if the certificate is not the one the client is expecting, the handshake will fail.

There are two types of certificate pinning:
* **Hard Certificate Pinning**: method implemented usually in the application, the client has the exact server certificate details stored in the code or in a file. If the certificated received does not match with any of the ones stored by the client, the communications will fail.
The main drawback of this method is that the application has to be updated each time the server certificate changes.

* **CA Pinning**: the client does not has all the certificate details but a CA certificates. So it will trust any certificate which is signed by a trusted CA.
The main drawback of this method is that if an attacker compromises the CA, it will be able to sign any fraudulent certificate and the client will trust it.

If the certificate is not valid, the application or server will return an SSL error in the handshake:
![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-05-09-Certificate-Pinning-Mutual-Authentication/Cert_error_burp.png)

If an attacker is successful and adds his certificate in the whitelist, the application will continue with the handshake and the attacker will be able to intercept all the traffic unencrypted:
![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-05-09-Certificate-Pinning-Mutual-Authentication/Cert_ok_burp.png)


Certificate pinning allows to drop the SSL connection if a invalid certificate is detected. However, this control is vulnerable if the client is compromised.


## Client Certificate Authentication
Client Certificate Authentication works the other way around. It adds an extra layer of security so the server can be sure only clients that have the certificate can communicate successfully with it. However, since apps can be decompiled without a lot of effort, this client certificate can 'easily' be obtained by a malicious user. So this isn't a silver bullet.


## Mutual Authentication
Mutual authentication control refers to not only the client validates the server certificate, but also the server validates the client certificate.

During the hanshake both, client and server, exchange their respective certificates. The handsake looks like:
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2019-05-09-Certificate-Pinning-Mutual-Authentication/Handshake_Client_cert.png)
1. Client requests to the server an encrypted session and sends his cipher suites.
2. Server answers with a cipher suite.
3. Server sends his certificate, public key and request the certificate of the client.
4. Client verifies server certificate and server verifies client certificate
5. They exchange the keys they will use to encrypt and decrypt the communication.


In the following wireshark screenshot you can see all the hadnshake process:
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2019-05-09-Certificate-Pinning-Mutual-Authentication/client_certificate.png)


With mutual authentication the server has absolute control of who is trying to connect. It drops connections either if the server or client certificate are invalid. The main improvement versus certificate pinning is that the connection will not be stablished even though the client has been compromised.
However, the server must have previously provided each client with a unique certificate. In some enviroments this can not be deployed due to the difficulty to send a personal certificate to each client.




# Platforms
The controls mentioned before are implemented differently depending on what platform the client is. 



## Java Applications
Java aplications uses keyStore and trustStore to store the client and server certificates. A keyStore is used to store individual identity or certificate while trustStore is used to store other parties certificates signed by CA.

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2019-05-09-Certificate-Pinning-Mutual-Authentication/java_app.gif)
1. A client requests access to a protected resource.
2. The web server presents its certificate to the client.
3. The client verifies the server’s certificate.
4. If successful, the client sends its certificate to the server.
5. The server verifies the client’s credentials.
6. If successful, the server grants access to the protected resource requested by the client.

### keyStores
Usually JAVA keyStores are in the following path:
```
JAVA_HOME/jre/lib/security
```

Windows and Linux have a tool called "keytool" which allows to perform certain actions, like list or store certificates, to keyStores:

* To list the certificates stored in a keyStore
```
keytool -list -keystore cacerts
```

* Store certificate into keyStore
```
keytool -import -keystore cacerts -file test.cer
```

__Note__: the default password is "changeit"


### Attacking
In order to bypass the Certificate Pinning implemented in a JAVA application, an attacker needs to store the fraudulent certificate into the keyStore used by the application.

So, the attacker should be able to:
1. Acess or command execution into the client machine
2. Know the keyStore password
3. Have writting priviledges

It is important to note that sometimes keyStore password is not changed (changeit). If it is a different password, it is worth to look for the password into configuration files because the JAVA application must have the password stored somewhere. With luck, the password can be found in clear text.

Another, more complicated, technique is to reverse enginyering the application in order to obtain any hardcoded password in clear text or to even modify the Certificate Pining functionality.
This could be almost impossible to do without the consent of the client because the attacker would need to completely compromise the client machine so he can obtain and modify the application.


If the JAVA application and the backend use Mutual Authentication, an attacker, apart of doing all mentioned above, would need to find the client certificate (usually stored in the application folder), find its password and install it into the proxy he is using.


## Android Applications
In Android mobile applications, the Certificate Pinning can be implemented in two different ways:
1. KeyStores: similar to JAVA applications, Android can also use keyStores to store the server certificates.
2. Hardcoded in the binary: the pins of the server certificates can be hardcoded in the binary of the Android application.

There are three ways and attacker can bypass the Certificate Pinning:
1. Store the fraudulent certificate into the keyStore used by the application. 
2. Reverse enginyering the binary in order to either hardcode the fraudulent certificate into the binary or to modify the Certificate Pinning check functionality so it always return true.
3. In runtime execution modify intercept the Certificate Pinning check functionality response and modify its result to always return true.

In order to perform the Certificate Pinning bypass, an attacker would need to have command execution in the client device. If the client device is rooted, it would help to the attacker due to all the security controls are disabled (sandbox, root, accessing restricted areas...).


## iOS Applications
In iOS mobile applications, the Certificate Pinning can be implemented in two different ways:
1. Stored in the application: store de certificate in the application.
2. Hardcoded in the binary: the pins of the server certificates can be hardcoded in the binary of the iOS application.

There are four ways and attacker can bypass the Certificate Pinning:
1. Replace the server certificate for the fraudulent one. 
2. Reverse enginyering the binary in order to either hardcode the fraudulent certificate into the binary or to modify the Certificate Pinning check functionality so it always return true.
3. In runtime execution modify intercept the Certificate Pinning check functionality response and modify its result to always return true.
4. Use software like KillSwitch or similar.

In order to perform the Certificate Pinning bypass, an attacker would need to have command execution in the client device. If the client device is jailbroken, it would help to the attacker due to all the security controls are disabled (sandbox, root, accessing restricted areas...).


## Web Browsers
One one hand, certificate pinning is rarely used in browsers because the website does not have any control of the client browser. However, it can be done using "HTTP Public Key Pinning (HPKP)".

Basically, the first time a web server tells a client via a special HTTP header which public keys belong to it, the client stores this information for a given period of time. When the client visits the server again, it expects at least one certificate in the certificate chain to contain a public key whose fingerprint is already known via HPKP. If the server delivers an unknown public key, the client browser should present a warning.

An attacker who successfully intercepts the first response might be able to send to the client a fraudulent pin.  


__NOTE__: Currently HPKP is only supported in Firefox and Opera. Chrome removed the support in Chrome 67.


On the other hand, it is pretty common, in internal websites, to ask and check the client certificate (Client Certificate Authentication). The server has a client certificates whitelist and everytime a new connection is performed, the server checks the client certificate is whitelisted. 