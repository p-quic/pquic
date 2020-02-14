CLANG?=clang-6.0
LLC?=llc-6.0
export CLANG LLC
SUBDIRS := basic monitoring datagram fec multipath qlog no_pacing

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -j$(nproc) -C $@

.PHONY: all $(SUBDIRS)
