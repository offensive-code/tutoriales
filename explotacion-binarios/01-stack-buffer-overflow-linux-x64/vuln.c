#include <stdio.h> 	//para printf
#include <string.h>	//para strcpy

int main(int argc, char* argv[]) {
	char nombre[200];
	strcpy(nombre,argv[1]);
	printf("Hola %s\n", nombre);
}
