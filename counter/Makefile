OBJS=net-counter.o debug.o ethernet.o ipv4.o
CC=gcc
CFLAGS=-Wall -Werror -std=c11 -O3

net-counter: $(OBJS)
	$(CC) -o $@ $^ -lpcap

clean:
	$(RM) net-counter $(OBJS)

