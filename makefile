
all: myELF

myELF: myELF.o 
	gcc -g -Wall -o myELF myELF.o
	
myELF.o: task2.c
	gcc -g -Wall -c -o myELF.o task2.c 


.PHONY: clean

clean: 
	rm -f *.o myELF
