#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int aiuto(int aiuti, char* frase){
    int pos;
    
    printf("Che posizione desideri?\n");
    fflush(stdout);
    
    scanf(" %d", &pos); 
    
    printf("Il carattere in posizione %d e' -%c-\n", pos, frase[pos]);
    fflush(stdout);

    return aiuti - 1;
}

int indovina(int aiuti, char* frase){
    char buff[255];

    printf("Inserisci la frase: \n");
    fflush(stdout);

    scanf(" %[^\n]s", &buff);

    if (strcmp(buff, frase) == 0){
        printf("Congratulazioni hai vinto!\n");

        fflush(stdout);
        return -1;
    } else {
        printf("Mi dispiace la frase e' sbagliata\n");
        fflush(stdout);

        return aiuti;
    }
    
}


void gioco(){    
    int aiuti = 8;
    char frase[255] = "Con le ROP puoi far fare ad un binario quello che ti pare";
    char ans;

    printf("Benvenuto, riuscirai ad indovinare la frase segreta?\n");
    fflush(stdout);

    while(aiuti > 0){
        printf("Hai diritto a %d aiuti\n1) Chiedi aiuto\n2) Inserisci frase\n3) Esci\nCosa vuoi fare?\n", aiuti);
        fflush(stdout);

        scanf(" %c", &ans);
 
        if(ans == '1') aiuti = aiuto(aiuti, frase);
        if(ans == '2') aiuti = indovina(aiuti, frase);
        if(ans == '3') return;
    }
}


int main(){
    char ans;
    char name[255];
    do {
        gioco();

        printf("Vuoi giocare ancora? (y/n)\n");
        fflush(stdout);

        scanf(" %c", &ans);
    } while (ans == 'y');

    printf("Con chi ho avuto il piacere di giocare?\n");
    fflush(stdout);

    scanf(" %[^\n]s", &name);
    
    printf("Ciao %s!\n", name);
    fflush(stdout);
}