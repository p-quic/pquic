SUBDIRS := basic monitoring datagram fec multipath qlog no_pacing

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -j$(nproc) -C $@

.PHONY: all $(SUBDIRS)
