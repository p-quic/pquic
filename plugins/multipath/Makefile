SRC=$(shell find -name "*.c")
OBJ=$(SRC:.c=.o)
CFLAGS=-I../../picoquic -DPACING -DDISABLE_PROTOOP_PRINTF -DDISABLE_QLOG
SUBDIRS=path_schedulers

all: $(SRC) $(OBJ) $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

$(OBJ): %.o

%.o: %.c
	clang-6.0 $(CFLAGS) -O2 -fno-gnu-inline-asm -emit-llvm -c $< -o - | llc-6.0 -march=bpf -filetype=obj -o $@

clean:
	rm -rf *.o

.PHONY: %.o $(SUBDIRS)
