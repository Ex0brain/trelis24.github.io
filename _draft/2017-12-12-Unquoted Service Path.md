---
layout: post
title:  "Unquoted Service Path"
categories: "Privilege Escalation"
tags:  windows
author: Trelis
---

* content
{:toc}

All Windows services have path to its executable defined in the registry editor. If this path is not double quoted, this service has the vulnerability known as "Unquoted Service Path" which could allow an attacker to make a privilege escalation.




# Unquoted Service Path
The Windows Registry is a hierarchical database that contains all of the configurations and settings used by components, services, applications, and pretty much everything in Windows.

The registry has two basic concepts to be aware of: Keys and Values. Registry Keys are objects that are basically folders, and in the interface even look exactly like folders. Values are a bit like the files in the folders, and they contain the actual settings.

When a service is started, it go to its key and executes the executable determined by the value of ImagePath. This allows software to be more dynamic because it can make changes of the values in the registry without touching the code.

The value of ImagePath is just a path to the executable. For example:
```
C:\Program Files (x86)\SoftwareFolder\Folder 1\Executable.exe
```

If the service path name is not double quoted and contains white space, Windows assumes that anything before white space is the binary location and anything after that is argument, if it fails to to locate any binary there then it moves on to next directory defined in service path name. For example:
```
C:\Program.exe
C:\Program Files.exe
C:\Program Files (x86)\SoftwareFolder\Folder.exe
C:\Program Files (x86)\SoftwareFolder\Folder 1\Executable.exe
```

So, an attacker could can execute code with the same level of privilege than the vulnerable service if he's able to copy the malicious executable to one of the path mentioned before.

# Objective
The objective is to upgrade privileges to SYSTEM.

# Preconditions
* Local access to the machine
* Write permission to the target folder

# Proof of concept
In order to make the PoC a Windows 7 machine have been used with the user Alice which has no privileges.

