The goal of this challenge is to spawn a shell with a shellcode.
However, if your shellcode does execve("/bin/sh\0", NULL, NULL), the kernel will drop the privileges and you will become the user security again (hence, you won't be able to read the flag). Try to execute a shellcode with the following syscalls: open, read and write :)

NB: When you will do the challenges for the course, you will be able to execute execve("/bin/sh\0", NULL, NULL) without losing root privileges!!!
