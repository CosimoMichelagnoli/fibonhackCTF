# Training VM

This VM is meant to train the students of the Computer Security course at Polimi.
In particular, it is useful to understand the topics of binary analysis and binary exploitation.
Within this folder you will find 3 simple challenges. The first two are meant to be exploited,
while the third one is a reverse engineering challenge.

## Binary Exploitation

The goal of binary exploitation challenges is to hijack the flow of a binary application
to obtain a flag, which is a string such as "flag{This_is_a_flag} and it represents a 
confidential information. Usually this flag is stored within a file called "flag" that you 
cannot access directly. In the 3 directories you will have 3 files named "flag" that you cannot
read because they belong to the user "root" and you don't have the read permission over them.
You can check the owner and the permission with the command "ls -l":

ls -l
total 28
-rwsr-xr-x 1 root     root     15904 apr 11 15:17 auth
-rw-r--r-- 1 root     root       997 apr 11 15:16 auth.c
-rw-r----- 1 root     root        30 apr 11 15:20 flag
-rw-rw-r-- 1 security security   212 apr 11 16:43 README.md

Clearly, you can print the content of the files by asking super user permission, e.g.,
"sudo cat flag".
But this won't work on the official challenges of the course, so try to exploit them by 
exploiting the vulnerabilities of the binary application.
If you look at the permissions of the challenges, you will see the SUID bit set. This 
bit allow you to obtain the permission of the owner of the file during the
execution of the challenge. This means that you will obtain root permission only for the execution
of the challenge and only for the process of the challenge. Thus, if you find a way to open the flag
file and read its content, you will actually succeeed in the exploitation.
Most of the time, the goal is to execute execve("/bin/sh", NULL, NULL) which gives you a shell. In this case,
if you succeed to pop a shell, you will pop it as root(superuser) and you will have control of the entire machine.
However, there's a security measure to prevent you to open a shell as root when SUID is set. Thus, every time you pop a shell with 
a syscall, the kernel will drop the privilages and you will obtain an unprivileged shell :(
In the official challenges, this security measure is disabled so it will be easier for you to exploit them :)
On this VM, the security measure is enabled, but you don't always need to open a shell to read the content of a file ;) 

## Reverse Engineering

The goal of reverse engineering challenges is to find an input that satisfies a set of conditions.
For instance the input can be an activation key, such as XXXX-XXXX-XXXX-XXXX, where:
 - The sum of the corresponding ascii value of all the characters is x.
 - The sum of the corresponding ascii value of the first 4 characters is y.
 - and so on... 
