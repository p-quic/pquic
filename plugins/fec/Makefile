SRC=$(wildcard *protoops/*.c)
OBJ_SIGCOMM=$(shell sh get_protoops_sigcomm19.sh)
OBJ=$(SRC:.c=.o)
CFLAGS=-I../../picoquic -DDISABLE_PROTOOP_PRINTF
CLANG?=clang-6.0
LLC?=llc-6.0

all: $(SRC) $(OBJ)

$(OBJ): %.o

%.o: %.c
	$(CLANG) $(CFLAGS) -O2 -fno-gnu-inline-asm -emit-llvm -c $< -o - | $(LLC) -march=bpf -filetype=obj -o $@

.PHONY: %.o generate_verif generate_verif_sigcomm %_full.c
.NOTPARALLEL: verif_ verif_sigcomm

%_full.c: %.c
		mkdir -p verif/"$$(dirname $@_tmp)"
		gcc $(CFLAGS) -E $< > verif/$@_tmp
		python3 ../../benchmarks/add_main_to_plugin.py verif/$@_tmp > verif/$@
		find . -name "*_tmp" | xargs rm
		docker run -ti -v $(CURDIR)/verif:/mount llvm2kittel $(basename $@)
		sed -E -i 's/\|\|\s+\(nondet\(\)/\|\| \(nondet\(\) != 0/g' verif/$(basename $@).t2
		sed -E -i 's/\&\&\s+\(nondet\(\)/\&\& \(nondet\(\) != 0/g' verif/$(basename $@).t2
		sed -E -i 's/nondet\(\)\)\s+\|\|/nondet\(\) != 0\) \|\|/g' verif/$(basename $@).t2
		sed -E -i 's/nondet\(\)\)\s+\&\&/nondet\(\) != 0\) \&\&/g' verif/$(basename $@).t2

%_full.c.verif: %_full.c
		docker run -v $(CURDIR)/verif:/mount  t2_prod --input_t2=/mount/$(basename $<).t2 --timeout=3000 --termination || true #--print_proof --log

generate_verif: $(SRC:.c=_full.c)

generate_verif_sigcomm: $(OBJ_SIGCOMM:.o=_full.c)
	echo $(OBJ_SIGCOMM:.o=_full.c)

verif: generate_verif $(SRC:.c=_full.c.verif)

verif_sigcomm: $(OBJ) generate_verif_sigcomm $(OBJ_SIGCOMM:.o=_full.c.verif)

clean:
	rm -rf $(OBJ)
	rm -rf verif
