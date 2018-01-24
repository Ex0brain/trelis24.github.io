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
Chntpw is a software utility for resetting or blanking local passwords used by Windows. It does this by editing the SAM database where Windows stores local password hashes.

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

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2018-01-23-Chntpw-SAM/init.PNG)

First of all, you boot the computer with Kali and mount the Windows partition:
```
fdisk -l
```
```
mount /dev/sdaX MOUNT_FOLDER
```
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2018-01-23-Chntpw-SAM/fdisk.PNG)

The data base SAM is located in the following path: 
```
Windows/System32/config/SAM
```

## Information gathering
In order to have a general view of the operative system, you should try to retrieve as much information as you can before attacking. With the *flag -l* chntpw lists all the users available and the administrators:
```
chntpw -l MOUNT_FOLDER/Windows/System32/config/SAM
```
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2018-01-23-Chntpw-SAM/chntpw_list.PNG)

And with the *flag -i* and the second option, the tool will show you in which group each user is:
```
chntpw -i MOUNT_FOLDER/Windows/System32/config/SAM
```
![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2018-01-23-Chntpw-SAM/chntpw_group.PNG)

Once you know the users and its groups, you can decide what is the best attacking strategy. 

## Clear user password
Chntpw does not allow you to edit the password, but you can reset the password. When you do it, the lock column will have the value "\*BLANK\*"

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2018-01-23-Chntpw-SAM/chntpw_clearPass.PNG)

## Promote user
This functionality add the user to the Administrators group. This can also be done with the functionality number 4 explained after this one.

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2018-01-23-Chntpw-SAM/chntpw_admin.PNG)

## Add user to group
You can add or remove any user to any of the group listed by chntpw. This can be useful in order to obtain administrator privileges or adding a user into a group to do further attacks.

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2018-01-23-Chntpw-SAM/chntpw_addToGroup.PNG)

## Result
After deleting the password, promoting to administrator and adding Alice to Remote Desktop Users, all these changes can be observed with the chntpw:

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2018-01-23-Chntpw-SAM/chntpw_list2.PNG)

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2018-01-23-Chntpw-SAM/chntpw_group2.PNG)

When you try to access the user modified after restarting the computer and booting with Windows, you will be able to login without password and, in this PoC, Alice is now Administrator:

![](https://raw.githubusercontent.com/LordATM/lordatm.github.io/master/img/2018-01-23-Chntpw-SAM/aliceAdmin.PNG)
