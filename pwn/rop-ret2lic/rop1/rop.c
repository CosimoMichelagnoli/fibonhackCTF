#include <stdlib.h>
#include <stdio.h>


int main(){
    char name[255];
    printf("The address of main is:%p\n", main);
    fflush(stdout);
    puts("What is your name?");
    fflush(stdout);
    gets(name);
    printf("Hi %s!\n", name);
    fflush(stdout);
}