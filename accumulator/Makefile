OBJS=accumulator.o debug.o ethernet.o ipv4.o transact_file.o
CC=gcc
CFLAGS=-Wall -Wshadow -std=c11 -D_GNU_SOURCE
CFLAGS+=-g
CFLAGS+=-O3

accumulator: $(OBJS)
	$(CC) -o $@ $^ -lpcap

clean:
	$(RM) net-counter $(OBJS)

