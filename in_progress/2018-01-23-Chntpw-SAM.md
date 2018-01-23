---
layout: post
title:  "Chntpw SAM"
categories: Windows 
tags:  windows phisical_access
author: Trelis
---

* content
{:toc}

# Description
With chntpw is possible to see and edit the information stored in SAM file, allowing an attacker to reset the password of a user or elevate its privileges.




# Chntpw
Chntpw is a software utility for resetting or blanking local passwords used by Windows. It does this by editing the SAM database where Windows stores password hashes.

# Objective
The objective is to delete the password of "Alice" and upgrade the account to administrator.

# Preconditions
* Physical access to the machine 
* Being able to boot a live CD or USB
* The hard disk must not be encrypted

# Proof of concept
In order to make the PoC a Windows 7 machine and a bootable USB with a Kali Linux have been used. The target have four users:
* Admin: password protected, administrator privilege
* Bob: password protected, user privilege
* Alice: password protected, user privilege
* Guest: no password, guest privilege
![](init)


