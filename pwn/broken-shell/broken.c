#include <stdio.h>
#include <stdlib.h>

int main(int argc, char ** argv) {
  setvbuf(stdin, NULL, _IOLBF, 0);
  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);


    char buf[0x10];
    puts("What are you gonna do now?");
    printf("%p\n", buf);
    gets(buf);
}
