OBJS=accumulator.o debug.o ethernet.o ipv4.o transact_file.o
CC=gcc
CFLAGS=-std=c11 -Wall -Wshadow -D_GNU_SOURCE -g
CFLAGS+=-O3

accumulator: $(OBJS)
	$(CC) -o $@ $^ -lpcap

clean:
	$(RM) net-counter $(OBJS)

