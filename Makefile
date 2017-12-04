all: thread-diag

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

thread-diag: thread-diag.o
	$(CC) $(CFLAGS) -o $@ $^
