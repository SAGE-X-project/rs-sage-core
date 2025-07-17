CC = cc
CFLAGS = -Wall -Wextra -I../../include
LDFLAGS = -L../../target/release -lsage_crypto_core

# Platform-specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LDFLAGS += -Wl,-rpath,../../target/release
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -Wl,-rpath,@loader_path/../../target/release
endif

all: basic

basic: basic.c
	$(CC) $(CFLAGS) -o basic basic.c $(LDFLAGS)

clean:
	rm -f basic

run: basic
	./basic

.PHONY: all clean run