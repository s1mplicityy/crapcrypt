CC = gcc
CFLAGS = -Wall -Wextra -g -lssl -lcrypto
SRCS = main.c $(wildcard utils/*.c core/*.c)
OBJS = $(SRCS:.c=.o)
EXEC = main

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(EXEC)
