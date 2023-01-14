CC = gcc

all: beacon-flood
	
beacon-flood: main.o 
	gcc -o beacon-flood main.o -lpcap 
main.o: main.c 
	gcc -c -o main.o main.c
clean:
	rm -f *.o beacon-flood