#include "plugin.h"
#include <libgen.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int plugin_plug_elf(picoquic_cnx_t *cnx, protoop_id_t pid, plugin_type_enum pte, char *elf_fname) {
    protocol_operation_struct_t *post;
    HASH_FIND_STR(cnx->ops, pid, post);

    /* Two cases: either it exists, or not */
    if (!post) {
        int err = register_protoop(cnx, pid, NULL);
        if (err) {
            printf("Failed to allocate resources for pid %s\n", pid);
            return 1;
        }
        /* This is not optimal, but this should not be frequent */
        HASH_FIND_STR(cnx->ops, pid, post);
    }

    /* Fast track: if we want to insert a replace plugin while there is already one, it will never work! */
    if (pte == plugin_replace && post->replace) {
        printf("Replace plugin already inserted for pid %s!\n", pid);
        return 1;
    }

    /* Then check if we can load the plugin! */
    plugin_t *new_plugin = load_elf_file(elf_fname);
    if (!new_plugin) {
        printf("Failed to insert %s for proto op id %s\n", elf_fname, pid);
        return 1;
    }

    /* We cope with (nearly) all bad cases, so now insert */
    observer_node_t *new_node;
    switch (pte) {
    case plugin_replace:
        post->replace = new_plugin;
        break;
    case plugin_pre:
        new_node = malloc(sizeof(observer_node_t));
        if (!new_node) {
            printf("Cannot allocate memory to insert pre node with plugin %s for pid %s\n", elf_fname, pid);
            release_elf(new_plugin);
            return 1;
        }
        new_node->observer = new_plugin;
        new_node->next = post->pre;
        post->pre = new_node;
        break;
    case plugin_post:
        new_node = malloc(sizeof(observer_node_t));
        if (!new_node) {
            printf("Cannot allocate memory to insert pre node with plugin %s for pid %s\n", elf_fname, pid);
            release_elf(new_plugin);
            return 1;
        }
        new_node->observer = new_plugin;
        new_node->next = post->post;
        post->post = new_node;
        break;
    }

    return 0;
}

int plugin_unplug(picoquic_cnx_t *cnx, protoop_id_t pid, plugin_type_enum pte) {
    protocol_operation_struct_t *post;
    HASH_FIND_STR(cnx->ops, pid, post);

    if (!post) {
        printf("Trying to unplug plugin for non-existing proto op id %s...\n", pid);
        return 1;
    }

    /* For pre/post, it's difficult to ensure we remove the right observer right now...
     * But if we made the assumption that removal is either performed when a transaction
     * fails (when the connection is deleted, another function handles it), as the list
     * is implemented as a stack, we can simply remove the first one.
     */
    observer_node_t *to_remove;
    switch (pte) {
    case plugin_replace:
        if (!post->replace) {
            printf("Trying to unplug non-existing replace plugin for proto op id %s...\n", pid);
            return 1;
        }
        release_elf(post->replace);
        post->replace = NULL;
        break;
    case plugin_pre:
        if (!post->pre) {
            printf("Trying to unplug non-existing pre plugin for proto op id %s...\n", pid);
            return 1;
        }
        to_remove = post->pre;
        post->pre = to_remove->next;
        release_elf(to_remove->observer);
        free(to_remove);
        to_remove = NULL;
        break;
    case plugin_post:
        if (!post->post) {
            printf("Trying to unplug non-existing post plugin for proto op id %s...\n", pid);
            return 1;
        }
        to_remove = post->post;
        post->post = to_remove->next;
        release_elf(to_remove->observer);
        free(to_remove);
        to_remove = NULL;
        break;
    }

    /* Cope with a special case of a protoop without core op and with no more plugins */
    if (!post->core && !post->replace && !post->pre && !post->post) {
        HASH_DEL(cnx->ops, post);
        free(post);
        post = NULL;
    }

    return 0;
}

bool insert_plugin_from_transaction_line(picoquic_cnx_t *cnx, char *line,
    char *plugin_dirname, protoop_id_t inserted_pid, plugin_type_enum *pte)
{
    /* Part one: extract protocol operation id */
    char *token = strsep(&line, " ");
    if (token == NULL) {
        printf("No token for protocol operation id extracted!\n");
        return false;
    }
    strncpy(inserted_pid, token, strlen(token) + 1);
    /* Part two: extract plugin type */
    token = strsep(&line, " ");
    if (strncmp(token, "replace", 7) == 0) {
        *pte = plugin_replace;
    } else if (strncmp(token, "pre", 3) == 0) {
        *pte = plugin_pre;
    } else if (strncmp(token, "post", 4) == 0) {
        *pte = plugin_post;
    } else {
        printf("Cannot extract the type of the plugin: %s\n", token);
        return false;
    }

    /* Part three: insert the plugin */
    token = strsep(&line, " ");
    /* Handle end of line */
    token[strcspn(token, "\r\n")] = 0;
    if (token == NULL) {
        printf("No token for ebpf filename extracted!\n");
        return false;
    }
    char abs_path[250];
    strcpy(abs_path, plugin_dirname);
    strcat(abs_path, "/");
    strcat(abs_path, token);
    return plugin_plug_elf(cnx, inserted_pid, *pte, abs_path) == 0;
}

typedef struct pid_node {
    char pid[100];
    plugin_type_enum pte;
    struct pid_node *next;
} pid_node_t;

int plugin_insert_transaction(picoquic_cnx_t *cnx, const char *plugin_fname) {
    FILE *file = fopen(plugin_fname, "r");

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", plugin_fname, strerror(errno));
        return 1;
    }

    char buf[250];
    strcpy(buf, plugin_fname);
    char *line = NULL;
    size_t len = 0;
    ssize_t read = 0;
    bool ok = true;
    char *plugin_dirname = dirname(buf);
    char inserted_pid[100];
    plugin_type_enum pte;
    pid_node_t *pid_stack_top = NULL;
    pid_node_t *tmp = NULL;

    while (ok && (read = getline(&line, &len, file)) != -1) {
        /* Skip blank lines */
        if (len <= 1) {
            continue;
        }
        ok = insert_plugin_from_transaction_line(cnx, line, plugin_dirname, (protoop_id_t ) inserted_pid, &pte);
        if (ok) {
            /* Keep track of the inserted pids */
            tmp = (pid_node_t *) malloc(sizeof(pid_node_t));
            if (!tmp) {
                printf("No enough memory to allocate stack nodes; abort\n");
                ok = false;
                break;
            }
            strncpy(tmp->pid, inserted_pid, strlen(inserted_pid) + 1);
            tmp->pte = pte;
            tmp->next = pid_stack_top;
            pid_stack_top = tmp;
        }
    }

    while (pid_stack_top != NULL) {
        if (!ok) {
            /* Unplug previously plugged code */
            plugin_unplug(cnx, pid_stack_top->pid, pid_stack_top->pte);
        }
        tmp = pid_stack_top->next;
        free(pid_stack_top);
        pid_stack_top = tmp;
    }

    if (line) {
        free(line);
    }

    fclose(file);

    return ok ? 0 : 1;
}

void *get_opaque_data(picoquic_cnx_t *cnx, opaque_id_t oid, size_t size, int *allocated) {
    picoquic_opaque_meta_t *ometas = cnx->opaque_metas;
    if (oid >= OPAQUE_ID_MAX) {
        /* Invalid ID */
        return NULL;
    }
    if (ometas[oid].start_ptr) {
        if (ometas[oid].size != size) {
            /* The size requested is not correct */
            return NULL;
        }
        *allocated = 0;
        return ometas[oid].start_ptr;
    }
    if (ometas[oid].start_ptr == NULL && cnx->opaque_size_taken + size > OPAQUE_SIZE) {
        /* Trying to allocate space, but no enough space left */
        return NULL;
    }
    /* Allocate some space on the opaque stack and returns the pointer */
    ometas[oid].start_ptr = cnx->opaque + cnx->opaque_size_taken;
    ometas[oid].size = size;
    cnx->opaque_size_taken += size;
    *allocated = 1;
    return ometas[oid].start_ptr;
}

protoop_arg_t plugin_run_protoop(picoquic_cnx_t *cnx, protoop_id_t pid, int inputc, uint64_t *inputv, uint64_t *outputv) {
    if (inputc > PROTOOPARGS_MAX) {
        printf("Too many arguments for protocol operation with id %s : %d > %d\n",
            pid, inputc, PROTOOPARGS_MAX);
        return PICOQUIC_ERROR_PROTOCOL_OPERATION_TOO_MANY_ARGUMENTS;
    }

    /* First save previous args, and update context with new ones
     * Notice that we store ALL array of protoop_inputv and protoop_outputv.
     * With this, even if the called plugin tried to modify the input arguments,
     * they will remain unchanged at caller side.
     */
    int caller_inputc = cnx->protoop_inputc;
    int caller_outputc = cnx->protoop_outputc_callee;
    uint64_t *caller_inputv[PROTOOPARGS_MAX];
    uint64_t *caller_outputv[PROTOOPARGS_MAX];
    memcpy(caller_inputv, cnx->protoop_inputv, sizeof(uint64_t) * PROTOOPARGS_MAX);
    memcpy(caller_outputv, cnx->protoop_outputv, sizeof(uint64_t) * PROTOOPARGS_MAX);
    memcpy(cnx->protoop_inputv, inputv, sizeof(uint64_t) * inputc);
    cnx->protoop_inputc = inputc;

#ifdef DBG_PLUGIN_PRINTF
    for (int i = 0; i < inputc; i++) {
        DBG_PLUGIN_PRINTF("Arg %d: 0x%lx", i, inputv[i]);
    }
#endif

    /* Also set protoop_outputv to 0, to prevent callee to see caller state */
    memset(cnx->protoop_outputv, 0, sizeof(uint64_t) * PROTOOPARGS_MAX);
    cnx->protoop_outputc_callee = 0;

    DBG_PLUGIN_PRINTF("Running operation with id 0x%x with %d inputs", pid, inputc);

    /* Either we have a plugin, and we run it, or we stick to the default ops behaviour */
    protoop_arg_t status;
    protocol_operation_struct_t *post;
    HASH_FIND_STR(cnx->ops, pid, post);
    if (!post) {
        printf("FATAL ERROR: no protocol operation with id %s\n", pid);
        exit(-1);
    }

    /* First, is there any pre to run? */
    observer_node_t *tmp = post->pre;
    while (tmp) {
        /* TODO: restrict the memory accesible by the observers */
        exec_loaded_code(tmp->observer, (void *)cnx, sizeof(picoquic_cnx_t));
        tmp = tmp->next;
    }

    /* The actual protocol operation */
    if (post->replace) {
        DBG_PLUGIN_PRINTF("Running plugin at proto op id %s", pid);
        status = (protoop_arg_t) exec_loaded_code(post->replace, (void *)cnx, sizeof(picoquic_cnx_t));
    } else if (post->core) {
        status = post->core(cnx);
    } else {
        printf("FATAL ERROR: no replace nor core operation for protocol operation with id %s\n", pid);
        exit(-1);
    }

    /* Finally, is there any post to run? */
    tmp = post->post;
    while (tmp) {
        /* TODO: restrict the memory accesible by the observers */
        exec_loaded_code(tmp->observer, (void *)cnx, sizeof(picoquic_cnx_t));
        tmp = tmp->next;
    }

    int outputc = cnx->protoop_outputc_callee;

    DBG_PLUGIN_PRINTF("Protocol operation with id 0x%x returns 0x%lx with %d additional outputs", pid, status, outputc);

    /* Copy the output of the caller to the provided output pointer (if any)... */
    if (outputv) {
        memcpy(outputv, cnx->protoop_outputv, sizeof(uint64_t) * outputc);
#ifdef DBG_PLUGIN_PRINTF
        for (int i = 0; i < outputc; i++) {
            DBG_PLUGIN_PRINTF("Out %d: 0x%lx", i, outputv[i]);
        }
#endif
    } else if (outputc > 0) {
        printf("WARNING: no output value provided for protocol operation with id %s that returns %d additional outputs\n", pid, outputc);
        printf("HINT: this is probably not what you want, so maybe check if you called the right protocol operation...\n");
    }

    /* ... and restore ALL the previous inputs and outputs */
    memcpy(cnx->protoop_inputv, caller_inputv, sizeof(uint64_t) * PROTOOPARGS_MAX);
    memcpy(cnx->protoop_outputv, caller_outputv, sizeof(uint64_t) * PROTOOPARGS_MAX);
    cnx->protoop_inputc = caller_inputc;

    /* Also reset outputc to zero; if this protoop was called by another one that does not have any output,
     * it will likely not specify the outputc value, as it expects it to remain 0...
     */
    cnx->protoop_outputc_callee = caller_outputc;

    return status;
}