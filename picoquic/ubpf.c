#include "ubpf.h"
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <elf.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <time.h>
#include "plugin.h"
#include "memcpy.h"
#include "memory.h"
#include "tls_api.h"
#include "endianness.h"
#include "getset.h"
#include "picoquic_logger.h"

#define JIT false /* putting to false show out of memory access */

void picoquic_memory_bound_error(uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr) {
    printf("Out of bound access with val 0x%lx, start of mem is 0x%lx, top of stack is 0x%lx\n", val, mem_ptr, stack_ptr);
}

static void
register_functions(struct ubpf_vm *vm) {
    /* We only have 64 values ... (so far) */

    /* specific API related */
    ubpf_register(vm, 0x00, "plugin_run_protoop", plugin_run_protoop);
    ubpf_register(vm, 0x01, "get_opaque_data", get_opaque_data);
    ubpf_register(vm, 0x02, "reserve_frames", reserve_frames);
    ubpf_register(vm, 0x03, "get_cnx", get_cnx);
    ubpf_register(vm, 0x04, "set_cnx", set_cnx);
    ubpf_register(vm, 0x05, "get_path", get_path);
    ubpf_register(vm, 0x06, "set_path", set_path);
    ubpf_register(vm, 0x07, "get_pkt_ctx", get_pkt_ctx);
    ubpf_register(vm, 0x08, "set_pkt_ctx", set_pkt_ctx);
    ubpf_register(vm, 0x09, "get_pkt", get_pkt);
    ubpf_register(vm, 0x0a, "set_pkt", set_pkt);
    ubpf_register(vm, 0x0b, "get_sack_item", get_sack_item);
    ubpf_register(vm, 0x0c, "set_sack_item", set_sack_item);
    ubpf_register(vm, 0x0d, "get_cnxid", get_cnxid);
    ubpf_register(vm, 0x0e, "set_cnxid", set_cnxid);
    ubpf_register(vm, 0x0f, "get_stream_head", get_stream_head);
    ubpf_register(vm, 0x10, "set_stream_head", set_stream_head);
    ubpf_register(vm, 0x11, "get_crypto_context", get_crypto_context);
    ubpf_register(vm, 0x12, "set_crypto_context", set_crypto_context);
    ubpf_register(vm, 0x13, "get_ph", get_ph);
    ubpf_register(vm, 0x14, "set_ph", set_ph);
    ubpf_register(vm, 0x15, "cancel_head_reservation", cancel_head_reservation);
    /* specific to picoquic, how to remove this dependency ? */
    ubpf_register(vm, 0x18, "picoquic_reinsert_cnx_by_wake_time", picoquic_reinsert_cnx_by_wake_time);
    ubpf_register(vm, 0x19, "picoquic_current_time", picoquic_current_time);
    /* for memory */
    ubpf_register(vm, 0x1a, "my_malloc", my_malloc);
    ubpf_register(vm, 0x1b, "my_free", my_free);
    ubpf_register(vm, 0x1c, "my_realloc", my_realloc);
    ubpf_register(vm, 0x1d, "my_memcpy", my_memcpy);
    ubpf_register(vm, 0x1e, "my_memset", my_memset);

    ubpf_register(vm, 0x1f, "clock_gettime", clock_gettime);

    /* Network with linux */
    ubpf_register(vm, 0x20, "getsockopt", getsockopt);
    ubpf_register(vm, 0x21, "setsockopt", setsockopt);
    ubpf_register(vm, 0x22, "socket", socket);
    ubpf_register(vm, 0x23, "connect", connect);
    ubpf_register(vm, 0x24, "send", send);
    ubpf_register(vm, 0x25, "inet_aton", inet_aton);
    ubpf_register(vm, 0x26, "socketpair", socketpair);
    ubpf_register(vm, 0x27, "write", write);
    ubpf_register(vm, 0x28, "close", close);

    ubpf_register(vm, 0x2a, "my_htons", my_htons);
    ubpf_register(vm, 0x2b, "my_ntohs", my_ntohs);

    ubpf_register(vm, 0x2c, "strncmp", strncmp);
    ubpf_register(vm, 0x2d, "strcmp", strcmp);

    // logging func

    ubpf_register(vm, 0x2e, "picoquic_has_booked_plugin_frames", picoquic_has_booked_plugin_frames);

    /* Specific QUIC functions */
    ubpf_register(vm, 0x2f, "picoquic_decode_frames_without_current_time", picoquic_decode_frames_without_current_time);
    ubpf_register(vm, 0x30, "picoquic_varint_decode", picoquic_varint_decode);
    ubpf_register(vm, 0x31, "picoquic_varint_encode", picoquic_varint_encode);
    ubpf_register(vm, 0x32, "picoquic_create_random_cnx_id_for_cnx", picoquic_create_random_cnx_id_for_cnx);
    ubpf_register(vm, 0x33, "picoquic_create_cnxid_reset_secret_for_cnx", picoquic_create_cnxid_reset_secret_for_cnx);
    ubpf_register(vm, 0x34, "picoquic_register_cnx_id_for_cnx", picoquic_register_cnx_id_for_cnx);
    ubpf_register(vm, 0x35, "picoquic_create_path", picoquic_create_path);
    ubpf_register(vm, 0x36, "picoquic_getaddrs_v4", picoquic_getaddrs_v4);
    ubpf_register(vm, 0x37, "picoquic_compare_connection_id", picoquic_compare_connection_id);
    ubpf_register(vm, 0x38, "picoquic_create_path", picoquic_create_path);
    ubpf_register(vm, 0x39, "picoquic_compare_addr", picoquic_compare_addr);
    ubpf_register(vm, 0x3a, "picoquic_parse_stream_header", picoquic_parse_stream_header);
    ubpf_register(vm, 0x3b, "picoquic_find_stream", picoquic_find_stream);
    ubpf_register(vm, 0x3c, "picoquic_set_cnx_state", picoquic_set_cnx_state);
    ubpf_register(vm, 0x3d, "picoquic_frames_varint_decode", picoquic_frames_varint_decode);
    ubpf_register(vm, 0x3e, "picoquic_record_pn_received", picoquic_record_pn_received);
    /* This value is reserved. DO NOT OVERRIDE IT! */
    ubpf_register(vm, 0x3f, "picoquic_memory_bound_error", picoquic_memory_bound_error);

    ubpf_register(vm, 0x40, "queue_peek", queue_peek);
    /* FIXME remove this function */
    ubpf_register(vm, 0x41, "picoquic_frame_fair_reserve", picoquic_frame_fair_reserve);

    ubpf_register(vm, 0x60, "dprintf", dprintf);
    ubpf_register(vm, 0x61, "snprintf", snprintf);
    ubpf_register(vm, 0x62, "lseek", lseek);
    ubpf_register(vm, 0x63, "ftruncate", ftruncate);
    ubpf_register(vm, 0x64, "strlen", strlen);
    ubpf_register(vm, 0x65, "snprintf_bytes", snprintf_bytes);
    ubpf_register(vm, 0x66, "strncpy", strncpy);
    ubpf_register(vm, 0x67, "inet_ntop", inet_ntop);
}

static void *readfile(const char *path, size_t maxlen, size_t *len)
{
	FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    char *data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
                path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;
}

pluglet_t *load_elf(void *code, size_t code_len, uint64_t memory_ptr, uint32_t memory_size) {
    pluglet_t *pluglet = (pluglet_t *)malloc(sizeof(pluglet_t));
    if (!pluglet) {
        return NULL;
    }

    pluglet->vm = ubpf_create();
    if (!pluglet->vm) {
            fprintf(stderr, "Failed to create VM\n");
            free(pluglet);
            return NULL;
    }

    register_functions(pluglet->vm);

    bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);

    char *errmsg;
    int rv;
    if (elf) {
        rv = ubpf_load_elf(pluglet->vm, code, code_len, &errmsg, memory_ptr, memory_size);
    } else {
        rv = ubpf_load(pluglet->vm, code, code_len, &errmsg, memory_ptr, memory_size);
    }

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(pluglet->vm);
        free(pluglet);
        return NULL;
    }
	pluglet->fn = ubpf_compile(pluglet->vm, &errmsg);
	if (pluglet->fn == NULL) {
        fprintf(stderr, "Failed to compile: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(pluglet->vm);
        free(pluglet);
        return NULL;
    }

    free(errmsg);

    return pluglet;
}

pluglet_t *load_elf_file(const char *code_filename, uint64_t memory_ptr, uint32_t memory_size) {
	size_t code_len;
	void *code = readfile(code_filename, 1024*1024, &code_len);
	if (code == NULL) {
			return NULL;
	}

	pluglet_t *ret = load_elf(code, code_len, memory_ptr, memory_size);
	free(code);
	return ret;
}

int release_elf(pluglet_t *pluglet) {
    if (pluglet->vm != NULL) {
        ubpf_destroy(pluglet->vm);
        pluglet->vm = NULL;
        pluglet->fn = 0;
        free(pluglet);
    }
    return 0;
}

uint64_t exec_loaded_code(pluglet_t *pluglet, void *arg, void *mem, size_t mem_len, char **error_msg) {
    if (pluglet->vm == NULL) {
        return -1;
    }
    if (pluglet->fn == NULL) {
        return -1;
    }

    /* printf("0x%"PRIx64"\n", ret); */

    return _exec_loaded_code(pluglet, arg, mem, mem_len, error_msg, JIT);
}