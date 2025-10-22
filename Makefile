CC ?= cc
AS ?= as
CFLAGS ?= -O2 -Wall -Wextra -fno-omit-frame-pointer
LDFLAGS ?=
all: usermode_lc64_loader
usermode_lc64_loader: usermode_lc64_loader.o enter_lc64.o
	$(CC) $(CFLAGS) -o $@ usermode_lc64_loader.o enter_lc64.o $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
%.o: %.S
	$(CC) -c $< -o $@
clean:
	rm -rf *.o
.PHONY: all clean
