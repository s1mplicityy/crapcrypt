CC = gcc
CFLAGS = -Wall -Wextra -g -lssl -lcrypto
SRCS = main.c $(wildcard utils/*.c core/*.c)
OBJS = $(SRCS:.c=.o)
EXEC = main

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(OBJS) $(EXEC)