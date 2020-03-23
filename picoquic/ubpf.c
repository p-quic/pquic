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
#include "red_black_tree.h"
#include "cc_common.h"

#if defined(NS3)
#define JIT false
#elif defined(__APPLE__)
#define JIT false
#else
#define JIT true  /* putting to false show out of memory access */
#endif

void picoquic_memory_bound_error(uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr) {
    printf("Out of bound access with val 0x%" PRIx64 ", start of mem is 0x%" PRIx64 ", top of stack is 0x%" PRIx64 "\n", val, mem_ptr, stack_ptr);
}

static void
register_functions(struct ubpf_vm *vm) {
    /* We only have 64 values ... (so far) */
    unsigned int current_idx = 0;
    /* specific API related */
    ubpf_register(vm, current_idx++, "plugin_run_protoop", plugin_run_protoop);
    ubpf_register(vm, current_idx++, "reserve_frames", reserve_frames);
    ubpf_register(vm, current_idx++, "get_cnx", get_cnx);
    ubpf_register(vm, current_idx++, "set_cnx", set_cnx);
    ubpf_register(vm, current_idx++, "get_cnx_metadata", get_cnx_metadata);
    ubpf_register(vm, current_idx++, "set_cnx_metadata", set_cnx_metadata);
    ubpf_register(vm, current_idx++, "get_path", get_path);
    ubpf_register(vm, current_idx++, "set_path", set_path);
    ubpf_register(vm, current_idx++, "get_path_metadata", get_path_metadata);
    ubpf_register(vm, current_idx++, "set_path_metadata", set_path_metadata);
    ubpf_register(vm, current_idx++, "get_pkt_ctx", get_pkt_ctx);
    ubpf_register(vm, current_idx++, "set_pkt_ctx", set_pkt_ctx);
    ubpf_register(vm, current_idx++, "get_pkt", get_pkt);
    ubpf_register(vm, current_idx++, "set_pkt", set_pkt);
    ubpf_register(vm, current_idx++, "get_pkt_metadata", get_pkt_metadata);
    ubpf_register(vm, current_idx++, "set_pkt_metadata", set_pkt_metadata);
    ubpf_register(vm, current_idx++, "get_sack_item", get_sack_item);
    ubpf_register(vm, current_idx++, "set_sack_item", set_sack_item);
    ubpf_register(vm, current_idx++, "get_cnxid", get_cnxid);
    ubpf_register(vm, current_idx++, "set_cnxid", set_cnxid);
    ubpf_register(vm, current_idx++, "get_stream_head", get_stream_head);
    ubpf_register(vm, current_idx++, "set_stream_head", set_stream_head);
    ubpf_register(vm, current_idx++, "get_stream_data", get_stream_data);
    ubpf_register(vm, current_idx++, "get_crypto_context", get_crypto_context);
    ubpf_register(vm, current_idx++, "set_crypto_context", set_crypto_context);
    ubpf_register(vm, current_idx++, "get_ph", get_ph);
    ubpf_register(vm, current_idx++, "set_ph", set_ph);
    ubpf_register(vm, current_idx++, "cancel_head_reservation", cancel_head_reservation);
    /* specific to picoquic, how to remove this dependency ? */
    ubpf_register(vm, current_idx++, "picoquic_reinsert_cnx_by_wake_time", picoquic_reinsert_cnx_by_wake_time);
    ubpf_register(vm, current_idx++, "picoquic_current_time", picoquic_current_time);
    /* for memory */
    ubpf_register(vm, current_idx++, "my_malloc", my_malloc);
    ubpf_register(vm, current_idx++, "my_free", my_free);
    ubpf_register(vm, current_idx++, "my_realloc", my_realloc);
    ubpf_register(vm, current_idx++, "my_memcpy", my_memcpy);
    ubpf_register(vm, current_idx++, "my_memset", my_memset);

    ubpf_register(vm, current_idx++, "clock_gettime", clock_gettime);

    /* Network with linux */
    ubpf_register(vm, current_idx++, "getsockopt", getsockopt);
    ubpf_register(vm, current_idx++, "setsockopt", setsockopt);
    ubpf_register(vm, current_idx++, "socket", socket);
    ubpf_register(vm, current_idx++, "connect", connect);
    ubpf_register(vm, current_idx++, "send", send);
    ubpf_register(vm, current_idx++, "inet_aton", inet_aton);
    ubpf_register(vm, current_idx++, "socketpair", socketpair);
    ubpf_register(vm, current_idx++, "write", write);
    ubpf_register(vm, current_idx++, "close", close);
    ubpf_register(vm, current_idx++, "get_errno", get_errno);

    ubpf_register(vm, current_idx++, "my_htons", my_htons);
    ubpf_register(vm, current_idx++, "my_ntohs", my_ntohs);

    ubpf_register(vm, current_idx++, "strncmp", strncmp);
    ubpf_register(vm, current_idx++, "strlen", strlen);

    // logging func

    ubpf_register(vm, current_idx++, "picoquic_has_booked_plugin_frames", picoquic_has_booked_plugin_frames);

    /* Specific QUIC functions */
    ubpf_register(vm, current_idx++, "picoquic_decode_frames_without_current_time", picoquic_decode_frames_without_current_time);
    ubpf_register(vm, current_idx++, "picoquic_varint_decode", picoquic_varint_decode);
    ubpf_register(vm, current_idx++, "picoquic_varint_encode", picoquic_varint_encode);
    ubpf_register(vm, current_idx++, "picoquic_varint_skip", picoquic_varint_skip);
    ubpf_register(vm, current_idx++, "picoquic_create_random_cnx_id_for_cnx", picoquic_create_random_cnx_id_for_cnx);
    ubpf_register(vm, current_idx++, "picoquic_create_cnxid_reset_secret_for_cnx", picoquic_create_cnxid_reset_secret_for_cnx);
    ubpf_register(vm, current_idx++, "picoquic_register_cnx_id_for_cnx", picoquic_register_cnx_id_for_cnx);
    ubpf_register(vm, current_idx++, "picoquic_create_path", picoquic_create_path);
    ubpf_register(vm, current_idx++, "picoquic_getaddrs", picoquic_getaddrs);
    ubpf_register(vm, current_idx++, "picoquic_compare_connection_id", picoquic_compare_connection_id);

    ubpf_register(vm, current_idx++, "picoquic_compare_addr", picoquic_compare_addr);
    ubpf_register(vm, current_idx++, "picoquic_parse_stream_header", picoquic_parse_stream_header);
    ubpf_register(vm, current_idx++, "picoquic_find_stream", picoquic_find_stream);
    ubpf_register(vm, current_idx++, "picoquic_set_cnx_state", picoquic_set_cnx_state);
    ubpf_register(vm, current_idx++, "picoquic_frames_varint_decode", picoquic_frames_varint_decode);
    ubpf_register(vm, current_idx++, "picoquic_record_pn_received", picoquic_record_pn_received);
    ubpf_register(vm, current_idx++, "picoquic_cc_get_sequence_number", picoquic_cc_get_sequence_number);
    ubpf_register(vm, current_idx++, "picoquic_cc_was_cwin_blocked", picoquic_cc_was_cwin_blocked);
    ubpf_register(vm, current_idx++, "picoquic_is_sending_authorized_by_pacing", picoquic_is_sending_authorized_by_pacing);
    ubpf_register(vm, current_idx++, "picoquic_update_pacing_data", picoquic_update_pacing_data);

    ubpf_register(vm, current_idx++, "queue_peek", queue_peek);
    /* FIXME remove this function */
    ubpf_register(vm, current_idx++, "picoquic_frame_fair_reserve", picoquic_frame_fair_reserve);
    ubpf_register(vm, current_idx++, "plugin_pluglet_exists", plugin_pluglet_exists);

    ubpf_register(vm, current_idx++, "inet_ntop", inet_ntop);
    ubpf_register(vm, current_idx++, "strerror", strerror);
    ubpf_register(vm, current_idx++, "memcmp", memcmp);
    ubpf_register(vm, current_idx++, "my_malloc_dbg", my_malloc_dbg);
    ubpf_register(vm, current_idx++, "my_malloc_ex", my_malloc);
    ubpf_register(vm, current_idx++, "my_free_dbg", my_free_dbg);
    ubpf_register(vm, current_idx++, "my_memcpy_dbg", my_memcpy_dbg);
    ubpf_register(vm, current_idx++, "my_memset_dbg", my_memset_dbg);

    ubpf_register(vm, current_idx++, "dprintf", dprintf);
    ubpf_register(vm, current_idx++, "snprintf", snprintf);
    ubpf_register(vm, current_idx++, "lseek", lseek);
    ubpf_register(vm, current_idx++, "ftruncate", ftruncate);
    ubpf_register(vm, current_idx++, "strlen", strlen);
    ubpf_register(vm, current_idx++, "snprintf_bytes", snprintf_bytes);
    ubpf_register(vm, current_idx++, "strncpy", strncpy);
    ubpf_register(vm, current_idx++, "inet_ntop", inet_ntop);
    ubpf_register(vm, current_idx++, "get_preq", get_preq);
    ubpf_register(vm, current_idx++, "set_preq", set_preq);

    ubpf_register(vm, current_idx++, "bind", bind);
    ubpf_register(vm, current_idx++, "recv", recv);

    ubpf_register(vm, current_idx++, "strcmp", strncmp);

    /* red black tree */
    ubpf_register(vm, current_idx++, "rbt_init", rbt_init);
    ubpf_register(vm, current_idx++, "rbt_is_empty", rbt_is_empty);
    ubpf_register(vm, current_idx++, "rbt_size", rbt_size);
    ubpf_register(vm, current_idx++, "rbt_put", rbt_put);
    ubpf_register(vm, current_idx++, "rbt_get", rbt_get);
    ubpf_register(vm, current_idx++, "rbt_contains", rbt_contains);
    ubpf_register(vm, current_idx++, "rbt_min_val", rbt_min_val);
    ubpf_register(vm, current_idx++, "rbt_min_key", rbt_min_key);
    ubpf_register(vm, current_idx++, "rbt_min", rbt_min);
    ubpf_register(vm, current_idx++, "rbt_max_key", rbt_max_key);
    ubpf_register(vm, current_idx++, "rbt_max_val", rbt_max_val);
    ubpf_register(vm, current_idx++, "rbt_ceiling_val", rbt_ceiling_val);
    ubpf_register(vm, current_idx++, "rbt_ceiling_key", rbt_ceiling_key);
    ubpf_register(vm, current_idx++, "rbt_ceiling", rbt_ceiling);
    ubpf_register(vm, current_idx++, "rbt_delete", rbt_delete);
    ubpf_register(vm, current_idx++, "rbt_delete_min", rbt_delete_min);
    ubpf_register(vm, current_idx++, "rbt_delete_max", rbt_delete_max);
    ubpf_register(vm, current_idx++, "rbt_delete_and_get_min", rbt_delete_and_get_min);
    ubpf_register(vm, current_idx++, "rbt_delete_and_get_max", rbt_delete_and_get_max);

    /* This value is reserved. DO NOT OVERRIDE IT! */
    ubpf_register(vm, 0x7f, "picoquic_memory_bound_error", picoquic_memory_bound_error);
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
    pluglet_t *pluglet = (pluglet_t *)calloc(1, sizeof(pluglet_t));
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

    if (JIT) {
        pluglet->fn = ubpf_compile(pluglet->vm, &errmsg);
        if (pluglet->fn == NULL) {
            fprintf(stderr, "Failed to compile: %s\n", errmsg);
            free(errmsg);
            ubpf_destroy(pluglet->vm);
            free(pluglet);
            return NULL;
        }
    } else {
        pluglet->fn = NULL;
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
    if (JIT && pluglet->fn == NULL) {
        return -1;
    }

    /* printf("0x%"PRIx64"\n", ret); */
    pluglet->count++;
#ifndef DEBUG_PLUGIN_EXECUTION_TIME
    return _exec_loaded_code(pluglet, arg, mem, mem_len, error_msg, JIT);
#else
    uint64_t before = picoquic_current_time();
    uint64_t err = _exec_loaded_code(pluglet, arg, mem, mem_len, error_msg, JIT);
    pluglet->total_execution_time += picoquic_current_time() - before;
    return err;
#endif
}
