CC       = cc
CFLAGS   = -std=c11 -Wall -Wextra -Wpedantic -Ivendor -Isrc
RELEASE  = -O3 -mcpu=native -flto
DEBUG    = -g -O0 -fsanitize=address -DDEBUG

SRCS     = src/main.c src/arena.c src/scanner.c src/workqueue.c src/threads.c src/safety.c src/tree.c src/report.c
TARGET   = artemis

LDFLAGS  = -framework CoreFoundation

.PHONY: all debug clean clone_test

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(RELEASE) $(LDFLAGS) -o $@ $^

debug: $(SRCS)
	$(CC) $(CFLAGS) $(DEBUG) $(LDFLAGS) -o $(TARGET) $^

clone_test: tests/clone_test.c
	$(CC) $(CFLAGS) $(DEBUG) -o $@ $<

clean:
	rm -f $(TARGET) clone_test
