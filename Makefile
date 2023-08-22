CC = gcc
CFLAGS = -Wall -Wextra -Werror
CFLAGS += -std=c99
CFLAGS += -Os -g0
CFLAGS += -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
LDFLAGS = -static -s
LDLIBS = -lc

all: lpe.zip

lpe.zip: exploit wrapper
	zip $@ $^

exploit: main.go
	go build

wrapper: src/wrapper.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	$(RM) exploit wrapper
	$(RM) src/*.o
	$(RM) lpe.zip

.PHONY: all clean run
