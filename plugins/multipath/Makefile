SRC=$(shell find -name "*.c")
OBJ=$(SRC:.c=.o)
CFLAGS=-I../../picoquic -DPACING -DDISABLE_PROTOOP_PRINTF -DDISABLE_QLOG
SUBDIRS=path_schedulers
CLANG?=clang-6.0
LLC?=llc-6.0
export CLANG LLC

all: $(SRC) $(OBJ) $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

$(OBJ): %.o

%.o: %.c
	$(CLANG) $(CFLAGS) -O2 -fno-gnu-inline-asm -emit-llvm -c $< -o - | $(LLC) -march=bpf -filetype=obj -o $@

clean:
	rm -rf *.o

.PHONY: %.o $(SUBDIRS)
