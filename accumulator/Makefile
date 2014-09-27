OBJS=accumulator.o debug.o ethernet.o ipv4.o transact_file.o
CC=gcc
CFLAGS=-Wall -Werror -std=c11 -O3 -D_GNU_SOURCE

accumulator: $(OBJS)
	$(CC) -o $@ $^ -lpcap

clean:
	$(RM) net-counter $(OBJS)

