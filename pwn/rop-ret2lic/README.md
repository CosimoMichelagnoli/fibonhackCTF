# CyberChallenge - ROP & ret2libc

[Video lezione 2020](https://www.youtube.com/watch?v=mUOWsuLE_lI)

## Istruzioni

Clonare il repo:

```
git clone https://github.com/galatolofederico/rop-ret2libc.git && cd rop-ret2libc
```

Creare e attivare il virtualenv

```
virtualenv --python=python3 env && . ./env/bin/activate
```

Installare dipendenze

```
pip install -r requirements.txt
```

## Esercizi

Prima di compilare i binari creare il docker container con gcc (necessario per avere tutti gli stessi binari)

```
cd compiler
make
```

Ogni esercizio ha un `Makefile` da usare:

```
make <target>
```

Questi sono i target disponibili

|    target    |         Significato       | 
|:------------:|:-------------------------:|
|    binary    |       Compila binario     |
|    clean     |      Cancella binario     |
|    docker    |      Builda container     |
|    remote    |   Avvia server in docker  |
| extract-libc | Estrae libc dal container |
