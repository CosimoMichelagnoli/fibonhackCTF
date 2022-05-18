#include<stdio.h>
#include<string.h>
#include<stdbool.h>

#define BUFFSIZE 128

int exploit_me(){
	char buffer[BUFFSIZE];
	gets(buffer);
	buffer[BUFFSIZE - 1] = '\0';

	bool nop_sled_over = false;
	int i = 0;
	for(; i < strlen(buffer) - 1; i += 2){
		if(buffer[i] != '\x90') 
			nop_sled_over = true;
		
		if(nop_sled_over){
			char following_char = buffer[i + 1];
			buffer[i + 1] = buffer[i];
			buffer[i] = following_char;
		}
	}
	
	printf("%s\n", buffer);
	return 0;
}


int main(){
	exploit_me();
	return 0;
}
