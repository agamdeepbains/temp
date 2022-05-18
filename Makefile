all:
	gcc client.c -o client -lcrypto
	gcc server.c -o server -lcrypto

clean:
	rm -f client server output.txt