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
#include "plugin.h"
#include "memcpy.h"
#include "memory.h"
#include "tls_api.h"

#define JIT false  /* putting to false show out of memory access */

static void
register_functions(struct ubpf_vm *vm)
{
    /* We only have 64 values ... (so far) */

    /* specific API related */
    ubpf_register(vm, 0x00, "plugin_run_protoop", plugin_run_protoop);
    ubpf_register(vm, 0x01, "get_opaque_data", get_opaque_data);
    /* specific to picoquic, how to remove this dependency ? */
    ubpf_register(vm, 0x08, "picoquic_reinsert_by_wake_time", picoquic_reinsert_by_wake_time);
    /* for memory */
    ubpf_register(vm, 0x10, "my_malloc", my_malloc);
    ubpf_register(vm, 0x11, "my_free", my_free);
    ubpf_register(vm, 0x12, "my_realloc", my_realloc);

    ubpf_register(vm, 0x18, "my_memcpy", my_memcpy);
    ubpf_register(vm, 0x19, "my_memset", my_memset);

    /* Network with linux */
    ubpf_register(vm, 0x20, "getsockopt", getsockopt);
    ubpf_register(vm, 0x21, "setsockopt", setsockopt);

    /* Specific QUIC functions */
    ubpf_register(vm, 0x30, "picoquic_varint_decode", picoquic_varint_decode);
    ubpf_register(vm, 0x31, "picoquic_varint_encode", picoquic_varint_encode);
    ubpf_register(vm, 0x32, "picoquic_create_random_cnx_id", picoquic_create_random_cnx_id);
    ubpf_register(vm, 0x33, "picoquic_create_cnxid_reset_secret", picoquic_create_cnxid_reset_secret);
    ubpf_register(vm, 0x34, "picoquic_register_cnx_id", picoquic_register_cnx_id);
    ubpf_register(vm, 0x35, "picoquic_create_path", picoquic_create_path);
    ubpf_register(vm, 0x36, "picoquic_getaddrs_v4", picoquic_getaddrs_v4);
    ubpf_register(vm, 0x37, "picoquic_compare_connection_id", picoquic_compare_connection_id);
    ubpf_register(vm, 0x38, "picoquic_create_path", picoquic_create_path);
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

    void *data = calloc(maxlen, 1);
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

plugin_t *load_elf(void *code, size_t code_len) {
    plugin_t *plugin = (plugin_t *)malloc(sizeof(plugin_t));
    if (!plugin) {
        return NULL;
    }

    plugin->vm = ubpf_create();
    if (!plugin->vm) {
            fprintf(stderr, "Failed to create VM\n");
            free(plugin);
            return NULL;
    }

    register_functions(plugin->vm);

    bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);

    char *errmsg;
    int rv;
    if (elf) {
        rv = ubpf_load_elf(plugin->vm, code, code_len, &errmsg);
    } else {
        rv = ubpf_load(plugin->vm, code, code_len, &errmsg);
    }

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(plugin->vm);
        free(plugin);
        return NULL;
    }
	plugin->fn = ubpf_compile(plugin->vm, &errmsg);
	if (plugin->fn == NULL) {
        fprintf(stderr, "Failed to compile: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(plugin->vm);
        free(plugin);
        return NULL;
    }

    free(errmsg);

    return plugin;
}

plugin_t *load_elf_file(const char *code_filename) {
	size_t code_len;
	void *code = readfile(code_filename, 1024*1024, &code_len);
	if (code == NULL) {
			return NULL;
	}

	plugin_t *ret = load_elf(code, code_len);
	free(code);
	return ret;
}

int release_elf(plugin_t *plugin) {
    if (plugin->vm != NULL) {
        ubpf_destroy(plugin->vm);
        plugin->vm = NULL;
        plugin->fn = 0;
        free(plugin);
        plugin = NULL;
    }
    return 0;
}

uint64_t exec_loaded_code(plugin_t *plugin, void *mem, size_t mem_len) {
    uint64_t ret;
    if (plugin->vm == NULL) {
        return -1;
    }
    if (plugin->fn == NULL) {
        return -1;
    }
    if (JIT) {
        /* JIT */
        ret = plugin->fn(mem, mem_len);
    } else {
        /* Interpreted */
        ret = ubpf_exec(plugin->vm, mem, mem_len);
    } 

    /* printf("0x%"PRIx64"\n", ret); */

    return ret;
}