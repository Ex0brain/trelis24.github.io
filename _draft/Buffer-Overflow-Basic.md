---
layout: post
title:  "Basic Buffer Overflow"
categories: "Windows Linux"
tags:  buffer overflow
author: Trelis
---

* content
{:toc}

TO-DO Basic Buffer Overflow




# Buffer Overflow
## Introduction
PHOTO STACK

### Registers
These are the most important registers:
* **%EIP**: it is the instruction pointer register. It stores the address of the next instruction to be executed, so it controlls the flows of the program.
* **%ESP**: it is the stack pointer register. it stores the address of the top of the stack, so it points to the last element of the stack. 
* **%EBP**: it is the base pinter register. It is designed to point to the current function so that all teh parameters and local variables would be in a fixed position, even though the %ESP register is moving. 
So the return address will be at %EBP+4, the first parameter at %EBP+8 and the first local variable at %EBP-4.

### Example
Taking as an example the following code:
```
void func(int a, int b, int c){
	int x = a + 2;
	int y = b + 10;
	return x + y + c;
}
int main() {
	func(10,20,30);
	print ("done");
}
```

Initialy we have an empty stack:

[EMPTY STACK]


1.	%EIP pointing at func in the main(). 
	It saves the paramaters in inverse order.

2.	It saves the return address (the value of %EIP) in order to know which will be the next instruction to execute after exiting the function func().

3.	%EIP now points at func().

4.	It saves %EBP in order to restore the state after the function func() is executed.

5.	%EBP = %ESP

6.	It saves the local variables.

7.	Now the computer can execute the function func() code. %EIP will point each line of code.

8.	After the execution, first it pops the local variables and moves %ESP back to where %EBP is.

9.	It pops %EBP so it can restore the state it has before entering func().

10. It pops the return address in order to restore the value %EIP had before entering func().

11. It pops the parameters sent to the funcion func().




## Attack
A buffer overflow condition exists when a program attempts to put more data in a buffer than it can hold or when a program attempts to put data in a memory area past a buffer. In this case, a buffer is a sequential section of memory allocated to contain anything from a character string to an array of integers. Writing outside the bounds of a block of allocated memory can corrupt data, crash the program, or cause the execution of malicious code.

So the main objective is to




Vulnerable functions
gets() -> fgets() - read characters
strcpy() -> strncpy() - copy content of the buffer
strcat() -> strncat() - buffer concatenation
sprintf() -> snprintf() - fill buffer with data of different types
(f)scanf() - read from STDIN
getwd() - return working directory
realpath() - return absolute (full) path


Protections
dep
aslr
?¿