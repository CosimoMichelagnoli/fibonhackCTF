#include <sys/mman.h>

#define HAVE_A_NICE_DAY	42

char sh3llc0d3[] =
"\xeb\x44\x8b\x44\x24\x04\x31\xdb\x31\xd2\x8a\x1c\x10\x80\xfb\x21\x74\x03\x42\xeb"
"\xf5\xc3\x8b\x44\x24\x04\x31\xdb\x31\xd2\x8a\x1c\x10\x80\xfb\x21\x74\x09\x80\xf3"
"\x2a\x88\x1c\x10\x42\xeb\xef\xc3\x8b\x4c\x24\x04\x51\xe8\xc8\xff\xff\xff\x5f\x31"
"\xc0\x31\xdb\xb0\x04\xb3\x01\xcd\x80\xc3\xeb\x2a\x8b\x4c\x24\x04\x51\xe8\xb0\xff"
"\xff\xff\x5f\x42\x31\xc0\x31\xdb\xb0\x03\xcd\x80\xc3\x31\xdb\x31\xd2\x3c\x01\x7e"
"\x0c\x0f\xb6\x7c\x01\xff\x01\xfa\x29\xc2\x48\xeb\xf0\xc3\xeb\x5c\xeb\x07\xe8\xb5"
"\xff\xff\xff\x5f\xc3\xe8\xf4\xff\xff\xff\x73\x68\x33\x6c\x6c\x63\x30\x64\x33\x3e"
"\x20\x21\x31\xc0\x31\xdb\xb0\x01\xb3\x2a\xcd\x80\xeb\x07\xe8\xa9\xff\xff\xff\x5f"
"\xc3\xe8\xf4\xff\xff\xff\x4c\x33\x33\x74\x5a\x20\x68\x34\x78\x30\x72\x20\x70\x77"
"\x6e\x33\x64\x20\x72\x30\x78\x78\x78\x20\x72\x75\x6c\x65\x7a\x20\x77\x33\x63\x68"
"\x61\x6c\x6c\x73\x20\x34\x32\x21\xeb\x4f\xeb\x0f\xe8\x3d\xff\xff\xff\xe8\x52\xff"
"\xff\xff\xe8\xab\xff\xff\xff\xe8\xec\xff\xff\xff\x69\x45\x44\x4d\x58\x4b\x5e\x5f"
"\x46\x4b\x5e\x43\x45\x44\x59\x04\x0a\x7e\x42\x4f\x0a\x5a\x4b\x59\x59\x0a\x43\x59"
"\x04\x04\x04\x0a\x5d\x4b\x43\x5e\x06\x0a\x5e\x42\x4f\x58\x4f\x0d\x59\x0a\x4b\x0a"
"\x5a\x4b\x59\x59\x0a\x15\x15\x20\x21\xe8\x4e\xff\xff\xff\xe8\x6d\xff\xff\xff\x81"
"\x39\x71\x75\x69\x74\x0f\x84\x57\xff\xff\xff\xe8\x21\xff\xff\xff\x66\x81\xfa\x39"
"\x05\x75\xde\xeb\x8d";


void cleararray(char **array)
{
	unsigned int i = 0;

	while (array[i]) {
		memset(array[i], 0, strlen(array[i]) + 1);
		i++;
	}
}

int main(int argc, char **argv, char **envp)
{
	int i;

	cleararray(argv);
	cleararray(envp);

	mprotect((unsigned long)sh3llc0d3 & (unsigned long)~0xfff, 0x2000, 7);
	(*(void (*)())sh3llc0d3)();

	return HAVE_A_NICE_DAY;
}
