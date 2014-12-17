CC = gcc

SOURCE = atomicio.c netcat.c
EXEC = wavcat

all:
	$(CC) $(SOURCE) -o $(EXEC) -Wall

clean:
	rm -rf *.o *~ $(EXEC) 
