SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
CFLAGS=-I../../picoquic

all: $(SRC) $(OBJ)

$(OBJ): %.o

%.o: %.c
	clang-6.0 $(CFLAGS) -O2 -fno-gnu-inline-asm -emit-llvm -c $< -o - | llc -march=bpf -filetype=obj -o $@

clean:
	rm -rf *.o

.PHONY: %.o