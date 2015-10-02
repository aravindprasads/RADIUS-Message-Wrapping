CC=gcc
CFLAGS=-g 
LDFLAGS=-DWITH_SSL -lcrypto -lssl

client: radlib.c radius_dev.c radius_client.c
	$(CC) $(CFLAGS) -o client radlib.c radius_dev.c radius_client.c $(LDFLAGS)

server: server.c
	$(CC) $(CFLAGS) server.c -o server
