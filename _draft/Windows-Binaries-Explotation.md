---
layout: post
title:  "Windows Binaries Explotation"
categories: "Binaries"
tags:  windows binaries
author: Trelis
---

* content
{:toc}

All Windows services have path to its executable defined in the registry editor. If this path is not double quoted, this service has the vulnerability known as "Unquoted Service Path" which could allow an attacker to make a privilege escalation.



Per defecte APPLocker bloqueja tots els directoris de Windows excepte el Temp. Si es pot posar un binari en aquell directori, es podrà executar correctament.



# cscript
## Description

## Path
* C:\Windows\System32\cscript.exe
* C:\Windows\SysWOW64\cscript.exe

## Detection

## Explotation

