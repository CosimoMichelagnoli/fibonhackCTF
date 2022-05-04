#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_SIZE    256
#define PASSFILE    "/home/basic9/flag"

char password[MAX_SIZE + 1] = {0};

void get_password(void)
{
	FILE *passfile;
	int c, i = 0;

	if ((passfile = fopen(PASSFILE, "r")) == NULL)
	{
		printf("Fail...\n");
	}
	else
	{
		printf("Reading password to the next level, can you get it ? :p\n");

		while ((c = fgetc(passfile)) != EOF && i < MAX_SIZE) {
			password[i++] = c;
		}
		fclose(passfile);
	}
}

int main(int argc, char **argv)
{
	get_password();

	if (argc > 1)
	{
		printf("Bad usage!\n");
		printf("You must call this programm without arguments, like this :\n");
		printf(argv[0]);
		printf("\n");
	}

	/* do something useful here :) */

	return 0;
}
