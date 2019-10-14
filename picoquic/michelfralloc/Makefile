

all: sbrk.o libptmalloc3.a libmichelfralloc.a

sbrk.o: sbrk.h sbrk.c
	gcc -c sbrk.c -o sbrk.o

michelfralloc.o: michelfralloc.h michelfralloc.c
	gcc -c michelfralloc.c -o michelfralloc.o

libptmalloc3.a:
	pushd ptmalloc3 && make libptmalloc3.a && popd
	cp ptmalloc3/libptmalloc3.a ./

libmichelfralloc.a: sbrk.o michelfralloc.o
	gcc -c michelfralloc.c -o michelfralloc.o
	ar cr $@ $^

clean:
	pushd ptmalloc3 && make clean && popd
	rm -f libptmalloc3.a; rm -f libmichelfralloc.a

.PHONY: clean