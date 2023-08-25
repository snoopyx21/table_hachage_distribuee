CFLAGS = -g
CLIBS = -lcrypto
CC = gcc

all: server.o client.o
	$(CC) $(CFLAGS) server.o $(CLIBS) -o server
	$(CC) $(CFLAGS) client.o $(CLIBS) -o client

server.o: server.h server.c
	$(CC) $(CFLAGS) -c server.c $(CLIBS) -o server.o

client.o: client.c
	$(CC) $(CFLAGS) -c client.c $(CLIBS) -o client.o

clean:
	rm -f *.o
	rm -f server
	rm -f client
