---
layout: post
title:  "OpenSSL manual check"
categories: openssl
tags:  openssl testssl
author: Trelis
---

* content
{:toc}

# Description
When analyzing the communications of a website, one of the scripts it's used is TestSSL because it's a fast way to test the cryptography and certificates of the site.
However, in the final report the results of this script should not be used as an evidence. That's why I want to do a summary of how to check manually SSL/TLS vulnerabilities.




# Protocols
## SSLv2
SSLv2 have a lot of weaknesses which could a allow an attacker to decrypt an modify communications.

To check whether SSLv2 is enabled on the remote host, the following command can be used: 
```
openssl s_client –ssl2 -connect example.com:443
```
If SSLv2 is supported, the handshake will complete and server certificate information will be returned. Otherwise, it will return a handshake failure error.

## SSLv3
It has a vulnerability called POODLE which allow decryption of communications and disclosure of session cookies if an attacker does a "padding oracle" attack against ciphers using cipher-block chaining (CBC) mode. 
Moreover, the only non-CBC cipher supported in SSLv3 is RC4, which is know as a cryptographically weak cipher.

To test whether a system supports SSLv3, the following OpenSSL command can be used:
```
openssl s_client –ssl3 -connect example.com:443

```
If SSLv3 is supported, the handshake will complete and server certificate information will be returned and the server is vulnerable to POODLE. Otherwise, it will return a handshake failure error.

## TLS > v1.0
To test whether a system supports TLS, the following OpenSSL command can be used:

```
openssl s_client -tls1_1 -connect example.com:443

```

```
openssl s_client -tls1_2 -connect example.com:443

```
If it does not connect, the server might be vulnerable because it will probably use SSLv2 or SSLv3 protocols.


# Ciphers
The cipher suite chosen specifies a set of algorithms which the client and server will use to perform key exchange, encryption, and message authentication.
A cipher suite is typically described in a format similar to this:

TLS_RSA_WITH_AES_128_CBC_SHA

where RSA is the key exchange algorithm, AES_128_CBC is the encryption cipher (AES using a 128-bit key operating in Cipher-Block Chaining mode), and SHA is the Message Authentication Code (MAC) algorithm.

The cipher suites a server is configured to support should be dictated by its security requirements. The following guidelines are generally recommended as a baseline:

    * The key exchange algorithm should be restricted to those which provide "perfect forward secrecy", such as Ephemeral Diffie-Hellman (DHE) or Ephemeral Elliptic Curve Diffie-Hellman (ECDHE).
    * The cipher should not suffer from known cryptanalytic flaws. This rules out RC4 which has been known to have flaws for many years and in the past few years has been shown to be significantly weaker than originally thought.
    * The cipher should use at least a 128 bit key (which rules out DES and Triple-DES).
    * Cipher-Block Chaining (CBC) mode is prone to padding oracle attacks and should ideally be avoided altogether, but specifically it should not be used in conjunction with SSLv3 or TLSv1.0 as this can lead to vulnerability to the BEAST attack. An alternative is Galois Counter Mode (GCM) which is not affected by these problems and offers authenticated encryption.
    * The message authentication algorithm should ideally be SHA256. MD5 is known to be cryptographically weak and should be avoided, and SHA1 (just denoted SHA in the cipher suite specifications) has its own weaknesses which place attacks within the realm of possibility.
    * For all three algorithms, the NULL / anon setting should be avoided as these provide no security at all. "Export" algorithms should also be disabled as their short key lengths make them susceptible to brute-force attacks and other attacks such as the FREAK attack.

There are two ways to test the ciphers. The first one is with openSSL:
```
openssl s_client -cipher NULL,EXPORT,LOW,3DES,aNULL -connect example.com:443
```
If some of the ciphers succeed, the server has weak ciphers.

The second option is to use Nmap, however the results should be checked with manually:
```
nmap --script ssl-enum-ciphers -p 443 example.com
```

# Server preferences
It can be seen the cipher order of the protocols available. 
If Diffie-Hellman is used as a key exchange, the key should be => 2048 bits

# Certificates
Server certificates enable the client to verify that it is connecting to the correct host. Though not usually used for HTTPS, SSL/TLS can also support mutual authentication in which the client proves its own identity through the provision of its own certificate.

To view the details of a server's certificate, the following command can be used:
```
openssl s_client -connect example.com:443 | openssl x509 -noout -text
```

The following attributes should be checked:
	* Common Name, Subject Alt Name and Issuer are congruent
	* The chain of trust is trusted
	* The certificate is not self-signed
	* The signature algorithm is strong
	* The server key size is >= 2048 bits
	* The certificate is not expired

# Vulnerabilities
## Heartbleed 
(CVE-2009-3555)
During communication, OpenSSL uses a “heartbeat” message that echoes back data to verify that it was received correctly. The problem is, in OpenSSL 1.0.1 to 1.0.1f, an attacker can trick OpenSSL by sending a single byte of information but telling the server that it sent up to 64K bytes of data that needs to be checked and echoed back. The server will respond with random data from its memory.

The following versions of OpenSSL are vulnerable:
	* OpenSSL 1.0.1 through 1.0.1f (inclusive)

The following versions of OpenSSL are not vulnerable:
	* OpenSSL 1.0.1g 
	* OpenSSL 1.0.0 branch 
	* OpenSSL 0.9.8 branch 

This vulnerability can be check using Nmap:
```
nmap -sV --script=ssl-heartbleed example.com -p 443
```
It can also be checked using the module "auxiliary/scanner/ssl/openssl_heartbleed".

Proof of concept: https://github.com/mpgn/heartbleed-PoC


## CSS
(CVE-2014-0224)
The vulnerability can only be exploited if both server and client are vulnerable to this issue. In the event that one of the two is vulnerable, there is no risk of exploitation.

This issue requires an attacker to intercept and alter network traffic in real time in order to exploit the flaw. This reduces the risk that this vulnerability can be exploited but does not make it impossible, updating should be a primary remediation focus regardless of the difficulty in leveraging the exploit.

This vulnerability can be check using Nmap:
```
nmap -sV --script=ssl-ccs-injection example.com -p 443
```


## Secure Renegotiation
(CVE-2009-3555)
The TLS protocol, and the SSL protocol 3.0 and possibly earlier, does not properly associate renegotiation handshakes with an existing connection, which allows man-in-the-middle attackers to insert data into HTTPS sessions, and possibly other types of sessions protected by TLS or SSL, by sending an unauthenticated request that is processed retroactively by a server in a post-renegotiation context, related to a "plaintext injection" attack. 

This vulnerability can be check using OpenSSL:
```
openssl s_client -connect example.com:443
```
If OpenSSL report "Secure Renegotiation IS NOT supported", the server is vulnerable.


## Secure Client-Initiated Renegotiation DoS
When a new SSL connection is being negotiated, the server will typically spend significantly more CPU resources than the client. Thus, if you are requesting many new SSL connections per second, you may end up using all of the server’s CPU.

This vulnerability can be check using OpenSSL:
```
openssl s_client -connect example.com:443
```
When the connection has started if pressing 'R' the renegotiation succeeds (HTTP response returned), the server is vulnerable.


## CRIME
(CVE-2012-4929)
The Compression Ratio Info-leak Made Easy (CRIME) attack is a side-channel attack against TLS compression. To carry out the attack, the attacker needs to exert partial control over the content of requests made by the client (e.g. by using a Cross-Site Scripting vulnerability to force the user's browser to issue requests). The attacker can then observe the compressed size of these requests on the network and from that infer the contents of the remainder of the request (e.g. session cookies) based on the level of compression achieved.

This vulnerability can be check using OpenSSL:
```
openssl s_client -connect example.com:443
```
On the servers supporting compression, a response similar to the one below will be received, containing details about the compression. The lines "Compression: zlib compression" and "Compression: 1 (zlib compression)" indicate that the remote server is vulnerable to the CRIME attack. 
Otherwise, the "Compression: NONE" shows that this server rejects usage of TLS-level compression.


## BREACH
(CVE-2013-3587)
The BREACH attack is analogous to the CRIME attack, but this time exploits the use of HTTP compression to again infer the contents of attacker-influenced requests.

This vulnerability can be check using OpenSSL:
```
openssl s_client -connect example.com:443
```
Submitting the following will allow us to see if HTTP compression is supported by the server:
```
GET / HTTP/1.1
Host: example.com
Accept-Encoding: compress, gzip
```
If the response contains encoded data, it indicates that HTTP compression is supported; therefore the remote host is vulnerable.
Otherwise, the server will respond with uncompressed data, indicating that it is not vulnerable.


## POODLE
(CVE-2013-3587)
Under certain conditions, it is possible to conduct a "padding oracle" attack against ciphers using cipher-block chaining (CBC) mode. This may allow decryption of communications and disclosure of session cookies. 

If the server supports SSLv3 is vulnerable to POODLE attack.


## TLS_FALLBACK_SCSV
(RFC 7507)
TLS agents should negotiate the highest version of the protocol supported by client and server. Clients advertise the highest version of the protocol they support. The server selects the highest version it supports, and sends the negotiated version number in the ServerHello message.
 
Many broken TLS implementations in widespread use were unable to cope with versions they did not understand. This caused  large numbers of TLS sessions to break during the TLS 1.1 rollout and allow attackers to attack older SSL versions.


## FREAK
(CVE-2015-0204)
It allows an attacker to intercept HTTPS connections between vulnerable clients and servers and force them to use weakened encryption, which the attacker can break to steal or manipulate sensitive data. This site is dedicated to tracking the impact of the attack and helping users test whether they’re vulnerable.

This vulnerability can be check using OpenSSL:
```
openssl s_client -cipher EXPORT -connect example.com:443
```
If some of the server allow EXPORT ciphers, it is vulnerable.


## DROWN
(CVE-2016-0703)
DROWN allows attackers to break the encryption and read or steal sensitive communications, including passwords, credit card numbers, trade secrets, or financial data.

This vulnerability can be check using OpenSSL:
```
openssl s_client –ssl2 -connect example.com:443

```
If SSLv2 is supported, the server is vulnerable.


## LOGJAM
(CVE-2015-4000)
The Logjam attack allows a man-in-the-middle attacker to downgrade vulnerable TLS connections to 512-bit export-grade cryptography. This allows the attacker to read and modify any data passed over the connection. The attack is reminiscent of the FREAK attack, but is due to a flaw in the TLS protocol rather than an implementation vulnerability, and attacks a Diffie-Hellman key exchange rather than an RSA key exchange. The attack affects any server that supports DHE_EXPORT ciphers

This vulnerability can be check using OpenSSL:
```
openssl s_client -cipher EXPORT -connect example.com:443
```
If some of the server allow EXPORT ciphers, it is vulnerable.


## BEAST
(CVE-2011-3389)
This vulnerability is an attack against the confidentiality of a HTTPS connection in a negligible amount of time. That is, it provides a way to extract the unencrypted plaintext from an encrypted session.
Certain configurations on TLS 1.0 encrypts data by using cipher block chaining (CBC) mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPs session. 

There are two things to check. First of all the protocol:
```
openssl s_client -[sslv3/tls1] -connect example.com:443
```
Secondly de cipher block, for example:
```
openssl s_client -cipher DES-CBC3-SHA -connect example.com:443
```
If the server allows SSLv3 or TLS1 and it is using ciphers with CBC, then the server is vulnerable to BEAST attack.


## RC4
RC4 attacks exposes weaknesses of RC4 encryption algorithm. More precisely, in most situations where RC4 is used, these weaknesses can be used to reveal information which was previously thought to be safely encrypted. 

This vulnerability can be check using OpenSSL:
```
openssl s_client -cipher RC4 -connect example.com:443
```
If it connects, the server is vulnerable.


## Lucky13
(CVE-2013-0169)
The Lucky Thirteen attack is a cryptographic timing attack against implementations of the Transport Layer Security (TLS) protocol that use the CBC cipher suite against TLS connections that does not properly consider timing side-channel attacks on a MAC check requirement during the processing of malformed padding, which allows remote attackers to conduct distinguishing attacks and plaintext-recovery attacks.

This vulnerability can be check using OpenSSL:
```
openssl s_client -cipher DES-CBC3-SHA -connect example.com:443
```
If the server supports CBC3 ciphers, it is vulnerable.


## Sweet32
(CVE-2016–2183 and CVE-2016–6329)
The use of small block sizes (64 bits) in conjunction with the CBC (cipher block chain) operation mode, such as Triple-DES and Blowfish, allows an attacker to decrypt traffic between the server and its clients. These algorithms are commonly used in several applications and protocols such as VPN, SSH, SSL and IPSec. To perform this attack, it is necessary being able to generate and capture high amounts of network traffic (typically around 78GB).

This vulnerability can be check using OpenSSL:
```
openssl s_client -cipher 3DES -connect example.com:443
```
If the server supports 3DES or Blowfish, it is vulnerable.