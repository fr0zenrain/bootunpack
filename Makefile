BIN=bootunpack
CC=gcc
CFLAGS=-g -Wall -O2
LIB=-lz
SRC=$(wildcard *.c)

OBJ=$(SRC:%.c=%.o)

all: $(BIN)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

$(BIN): $(OBJ) 
	$(CC) -o $@ $(OBJ) $(CFLAGS) $(LIB)

clean:
	rm -f $(BIN) $(OBJ)
