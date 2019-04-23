#include "plugin.h"
#include <libgen.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "memory.h"
#include "picoquic_internal.h"

int plugin_plug_elf_param_struct(protocol_operation_param_struct_t *popst, protoop_plugin_t *p, pluglet_type_enum pte, char *elf_fname) {
    /* Fast track: if we want to insert a replace plugin while there is already one, it will never work! */
    if ((pte == pluglet_replace || pte == pluglet_extern) && popst->replace) {
        printf("Replace pluglet already inserted!\n");
        return 1;
    }

    if (!popst->intern && (pte == pluglet_pre || pte == pluglet_post)) {
        printf("External pluglet cannot have observers!\n");
        return 1;
    }

    if (popst->intern && pte == pluglet_extern && (popst->core || popst->pre || popst->post)) {
        printf("An internal pluglet already exists!\n");
        return 1;
    }

    /* Then check if we can load the plugin! */
    /* FIXME make adjustable memory size */
    pluglet_t *new_pluglet = load_elf_file(elf_fname, (uint64_t) p->memory, PLUGIN_MEMORY);
    if (!new_pluglet) {
        printf("Failed to insert %s\n", elf_fname);
        return 1;
    }
    /* Record the plugin pluglet comes from */
    new_pluglet->p = p;

    /* We cope with (nearly) all bad cases, so now insert */
    observer_node_t *new_node;
    switch (pte) {
    case pluglet_extern:
        popst->intern = false;
        /* this falls through intentionally */
    case pluglet_replace:
        popst->replace = new_pluglet;
        break;
    case pluglet_pre:
        new_node = malloc(sizeof(observer_node_t));
        if (!new_node) {
            printf("Cannot allocate memory to insert pre node with pluglet %s for pid\n", elf_fname);
            release_elf(new_pluglet);
            return 1;
        }
        new_node->observer = new_pluglet;
        new_node->next = popst->pre;
        popst->pre = new_node;
        break;
    case pluglet_post:
        new_node = malloc(sizeof(observer_node_t));
        if (!new_node) {
            printf("Cannot allocate memory to insert pre node with pluglet %s\n", elf_fname);
            release_elf(new_pluglet);
            return 1;
        }
        new_node->observer = new_pluglet;
        new_node->next = popst->post;
        popst->post = new_node;
        break;
    }

    return 0;
}

int plugin_plug_elf_noparam(protocol_operation_struct_t *post, protoop_plugin_t *p, protoop_str_id_t pid, pluglet_type_enum pte, char *elf_fname) {
    protocol_operation_param_struct_t *popst = post->params;
    /* Sanity check */
    if (post->is_parametrable) {
        printf("Trying to insert NO_PARAM in parametrable protocol operation %s\n", pid);
        return 1;
    }

    return plugin_plug_elf_param_struct(popst, p, pte, elf_fname);
}

int plugin_plug_elf_param(protocol_operation_struct_t *post, protoop_plugin_t *p, protoop_str_id_t pid, param_id_t param, pluglet_type_enum pte, char *elf_fname) {
    protocol_operation_param_struct_t *popst;
    bool created_popst = false;
    /* Sanity check */
    if (!post->is_parametrable) {
        printf("Trying to insert parameter %u in non-parametrable protocol operation %s\n", param, pid);
        return 1;
    }
    HASH_FIND(hh, post->params, &param, sizeof(param_id_t), popst);
    /* It is possible to have a new parameter with the pluglet */
    if (!popst) {
        popst = create_protocol_operation_param(param, NULL);
        created_popst = true;
        if (!popst) {
            printf("ERROR: cannot allocate memory for param struct when pluglet...\n");
            return 1;
        }
    }

    int err = plugin_plug_elf_param_struct(popst, p, pte, elf_fname);

    if (err) {
        if (created_popst) {
            /* Remove it */
            free(popst);
        }
        printf("Failed to insert pluglet for parametrable protocol operation %s with param %u\n", pid, param);
        return 1;
    }

    if (created_popst) {
        /* Insert in hash */
        HASH_ADD(hh, post->params, param, sizeof(param_id_t), popst);
    }

    return 0;
}

int plugin_plug_elf(picoquic_cnx_t *cnx, protoop_plugin_t *p, protoop_str_id_t pid_str, param_id_t param, pluglet_type_enum pte, char *elf_fname) {
    protocol_operation_struct_t *post;
    protoop_id_t pid;
    pid.id = pid_str;
    /* And compute its hash */
    pid.hash = hash_value_str(pid.id);
    HASH_FIND_PID(cnx->ops, &(pid.hash), post);

    /* Two cases: either it exists, or not */
    if (!post) {
        int err;
        if (param != NO_PARAM) {
            err = register_param_protoop(cnx, &pid, param, NULL);
        } else {
            err = register_noparam_protoop(cnx, &pid, NULL);
        }
        if (err) {
            printf("Failed to allocate resources for pid %s\n", pid_str);
            return 1;
        }
        /* This is not optimal, but this should not be frequent */
        HASH_FIND_PID(cnx->ops, &(pid.hash), post);
    }

    /* Again, two cases: either it is parametric or not */
    return param != NO_PARAM ? plugin_plug_elf_param(post, p, pid_str, param, pte, elf_fname) :
        plugin_plug_elf_noparam(post, p, pid_str, pte, elf_fname);
}

int plugin_unplug(picoquic_cnx_t *cnx, protoop_str_id_t pid, param_id_t param, pluglet_type_enum pte) {
    protocol_operation_struct_t *post;
    HASH_FIND_STR(cnx->ops, pid, post);

    if (!post) {
        printf("Trying to unplug pluglet for non-existing proto op id %s...\n", pid);
        return 1;
    }

    protocol_operation_param_struct_t *popst;
    if (param == NO_PARAM) {
        if (post->is_parametrable) {
            printf("Trying to remove NO_PARAM from parametrable protocol operation %s\n", pid);
            return 1;
        }
        popst = post->params;
    } else {
        if (!post->is_parametrable) {
            printf("Trying to remove param %u from non-parametrable protocol operation %s\n", param, pid);
            return 1;
        }
        HASH_FIND(hh, post->params, &param, sizeof(param_id_t), popst);
        if (!popst) {
            printf("Trying to remove non-existing param %u for protocol operation %s\n", param, pid);
            return 1;
        }
    }

    /* For pre/post, it's difficult to ensure we remove the right observer right now...
     * But if we made the assumption that removal is either performed when a plugin
     * fails (when the connection is deleted, another function handles it), as the list
     * is implemented as a stack, we can simply remove the first one.
     */
    observer_node_t *to_remove;
    switch (pte) {
    case pluglet_extern:
        if (popst->intern) {
            printf("Trying to unplug non-existing external pluglet for proto op id %s\n", pid);
            return 1;
        }
        /* this falls through intentionally */
    case pluglet_replace:
        if (!popst->replace) {
            printf("Trying to unplug non-existing replace pluglet for proto op id %s...\n", pid);
            return 1;
        }
        release_elf(popst->replace);
        popst->replace = NULL;
        break;
    case pluglet_pre:
        if (!popst->pre) {
            printf("Trying to unplug non-existing pre pluglet for proto op id %s...\n", pid);
            return 1;
        }
        to_remove = popst->pre;
        popst->pre = to_remove->next;
        release_elf(to_remove->observer);
        free(to_remove);
        to_remove = NULL;
        break;
    case pluglet_post:
        if (!popst->post) {
            printf("Trying to unplug non-existing post pluglet for proto op id %s...\n", pid);
            return 1;
        }
        to_remove = popst->post;
        popst->post = to_remove->next;
        release_elf(to_remove->observer);
        free(to_remove);
        to_remove = NULL;
        break;
    }

    /* Cope with a special case of a protoop without core op and with no more plugins */
    if (!popst->core && !popst->replace && !popst->pre && !popst->post) {
        /* If it is parametrable, we just remove popst from post->params */
        if (post->is_parametrable) {
            HASH_DEL(post->params, popst);
        }
        else {
            HASH_DEL(cnx->ops, post);
            free(post);
            post = NULL;
        }
        /* And free popst */
        free(popst);
    }

    return 0;
}

bool insert_pluglet_from_plugin_line(picoquic_cnx_t *cnx, char *line, protoop_plugin_t *p,
    char *plugin_dirname, protoop_str_id_t inserted_pid, param_id_t *param, pluglet_type_enum *pte)
{
    /* Part one: extract protocol operation id */
    char *token = strsep(&line, " ");
    if (token == NULL) {
        printf("No token for protocol operation id extracted!\n");
        return false;
    }
    strcpy(inserted_pid, token);

    /* Part one bis: extract param, if any */
    token = strsep(&line, " ");

    if (token == NULL) {
        printf("No param or keyword! line: %s\n", line);
        return false;
    }

    if (strncmp(token, "param", 5) == 0) {
        char *errmsg = NULL;
        token = strsep(&line, " ");
        if (token == NULL) {
            printf("No param value!\n");
            return false;
        }
        *param = (param_id_t) strtoul(token, &errmsg, 0);
        if (errmsg != NULL && strncmp(errmsg, "", 1) != 0) {
            printf("Invalid parameter %s, num is %u!\n", token, *param);
            return false;
        }
        token = strsep(&line, " ");
        if (token == NULL) {
            printf("No keyword value!\n");
            return false;
        }
    } else {
        *param = NO_PARAM;
    }

    /* Part two: extract pluglet type */
    if (strncmp(token, "replace", 7) == 0) {
        *pte = pluglet_replace;
    } else if (strncmp(token, "pre", 3) == 0) {
        *pte = pluglet_pre;
    } else if (strncmp(token, "post", 4) == 0) {
        *pte = pluglet_post;
    } else if (strncmp(token, "extern", 6) == 0) {
        *pte = pluglet_extern;
    } else {
        printf("Cannot extract the type of the pluglet: %s\n", token);
        return false;
    }

    /* Part three: insert the plugin */
    token = strsep(&line, " ");
    if (token == NULL) {
        printf("No token for ebpf filename extracted!\n");
        return false;
    }

    /* Handle end of line */
    token[strcspn(token, "\r\n")] = 0;
    size_t max_dirname_size = 250;
    char abs_path[max_dirname_size];
    if (strlen(plugin_dirname) >= max_dirname_size){
        printf("The size of the plugin path is too large (>= %lu)\n", max_dirname_size);
        return false;
    }
    // here, we know that plugin_dirname will have a \0 at an index before max_dirname_size
    // abs_path is thus large enough
    strcpy(abs_path, plugin_dirname);
    strcat(abs_path, "/");
    strcat(abs_path, token);
    return plugin_plug_elf(cnx, p, inserted_pid, *param, *pte, abs_path) == 0;
}

protoop_plugin_t* plugin_parse_first_plugin_line(picoquic_cnx_t* cnx, char *line) {
    /* Part one: extract plugin id */
    char *token = strsep(&line, " ");
    if (token == NULL) {
        printf("No token for protocol operation id extracted!\n");
        return false;
    }

    /* Handle end of line  FIXME Move me later when parameters are present */
    token[strcspn(token, "\r\n")] = 0;

    if (strchr(token, '.') == token + strlen(token)) {
        /* No hierarchical name found, refuse it! */
        printf("The name of the plugin is not hierarchical; discard it!\n");
        return NULL;
    }

    protoop_plugin_t *p = calloc(1, sizeof(protoop_plugin_t));
    if (!p) {
        printf("Cannot allocate memory for plugin!\n");
        return NULL;
    }

    strncpy(p->name, token, PROTOOPPLUGINNAME_MAX);
    p->block_queue_cc = queue_init();
    if (!p->block_queue_cc) {
        printf("Cannot allocate memory for sending queue congestion control!\n");
        free(p);
        return NULL;
    }
    p->block_queue_non_cc = queue_init();
    if (!p->block_queue_non_cc) {
        printf("Cannot allocate memory for sending queue non congestion control!\n");
        free(p->block_queue_cc);
        free(p);
        return NULL;
    }
    /* TODO make this value configurable */
    p->bytes_in_flight = 0;
    p->bytes_total = 0;
    p->frames_total = 0;
    return p;
}

typedef struct pid_node {
    char pid[100];
    param_id_t param;
    pluglet_type_enum pte;
    struct pid_node *next;
} pid_node_t;

// FIXME: we do not handle cyclic includes
int plugin_preprocess_file(picoquic_cnx_t *cnx, char *plugin_dirname, const char *plugin_fname, char **out) {
    FILE *file = fopen(plugin_fname, "r");

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", plugin_fname, strerror(errno));
        return 1;
    }

    size_t file_len = 500;
    *out = calloc(file_len, 1);
    if (*out == NULL) {
        fprintf(stderr, "Failed to allocate memory to preprocess plugin file %s: %s\n", plugin_fname, strerror(errno));
        return 1;
    }

    size_t buffer_len = 250;
    char *buf = malloc(buffer_len);
    if (buf == NULL) {
        free(*out);
        *out = NULL;
        fprintf(stderr, "Failed to allocate memory to preprocess plugin file %s: %s\n", plugin_fname, strerror(errno));
        return 1;
    }


    char *line = NULL;
    size_t len = 0;
    ssize_t read = 0;
    const size_t max_filename_length = 150;
    char included_file[max_filename_length];
    while ((read = getline(&line, &len, file)) != -1) {
        /* Skip blank lines */
        if (len <= 1) {
            continue;
        }
        char *line_tmp = line;
        size_t line_len = strlen(line_tmp);
        if (line_len > buffer_len-1) {
            buffer_len = line_len*2;
            buf = realloc(buf, buffer_len);
            if (!buf) {
                free(*out);
                *out = NULL;
                free(buf);
                free(line);
                fprintf(stderr, "Failed to allocate memory to preprocess plugin file %s: %s\n", plugin_fname, strerror(errno));
                return 1;
            }
        }
        strcpy(buf, line_tmp);

        /* Part one: extract filename to include */
        char *token = strsep(&line_tmp, " ");
        if (token == NULL) {
            printf("No token for plugin filename!\n");
            free(*out);
            *out = NULL;
            free(buf);
            free(line);
            return 1;
        }
        if (strlen(token) > max_filename_length-1) {
            printf("Too long filename to include!\n");
            free(*out);
            *out = NULL;
            free(buf);
            free(line);
            return 1;
        }
        strncpy(included_file, token, max_filename_length);

        /* Part one bis: perform including if needed */
        token = strsep(&line_tmp, " ");
        // if token is NULL, it just means that it cannot be an include and thus cannit be interpreted by the preprocessor
        // so just don't try to interprete this line
        if (token != NULL && strncmp(token, "include", 5) == 0) {
            printf("include %s...\n", included_file);
            //  we must include the asked file
            char *subfile_content = NULL;
            char full_filename[strlen(plugin_dirname) + strlen(included_file) + 2]; // +2 due to the added / and added \0
            sprintf(full_filename, "%s/%s", plugin_dirname, included_file);
            int ret = plugin_preprocess_file(cnx, plugin_dirname, full_filename, &subfile_content);
            if(ret != 0) {
                if (subfile_content)
                    free(subfile_content);
                free(*out);
                *out = NULL;
                free(buf);
                free(line);
                return 1;
            }
            size_t content_len = strlen(subfile_content);
            size_t add_newline = subfile_content[content_len-1] == '\n' ? 0 : 1;
            if (file_len < strlen(*out) + strlen(subfile_content) + add_newline) {
                *out = realloc(*out, 2*(strlen(*out) + strlen(subfile_content) + add_newline));
            }
            strcat(*out, subfile_content);
            if (add_newline)
                strcat(*out, "\n");
            free(subfile_content);
        } else {
            if (file_len < strlen(*out) + strlen(buf)) {
                *out = realloc(*out, 2*(strlen(*out) + strlen(buf)));
            }
            strcat(*out, buf);
        }

    }

    free(buf);
    if (line)
        free(line);
    fclose(file);
    return 0;
}

int plugin_insert_plugin(picoquic_cnx_t *cnx, const char *plugin_fname) {

    /* XXX: Assume that it is always the same (combination of) plugins that are set */
    /* Fast track: do we have cached plugins? */
    if (cnx->quic->cached_plugins_queue && queue_peek(cnx->quic->cached_plugins_queue) != NULL) {
        printf("FAST TRACK!\n");
        cached_plugins_t* cache = queue_dequeue(cnx->quic->cached_plugins_queue);
        cnx->ops = cache->ops;
        cnx->plugins = cache->plugins;
        free(cache);
        return 0;
    }

    size_t max_filename_size = 250;
    char buf[max_filename_size];
    if (strlen(plugin_fname) >= max_filename_size){
        printf("The size of the plugin path is too large (>= %lu)\n", max_filename_size);
        return false;
    }
    // here, we know that plugin_fname has a \0 at an index before max_filename_size
    strcpy(buf, plugin_fname);
    char *line = NULL;
    size_t len = 0;
    ssize_t read = 0;
    bool ok = true;
    char *plugin_dirname = dirname(buf);
    char inserted_pid[100];
    param_id_t param;
    pluglet_type_enum pte;
    pid_node_t *pid_stack_top = NULL;
    pid_node_t *tmp = NULL;

    char *preprocessed = NULL;
    if (plugin_preprocess_file(cnx, plugin_dirname, plugin_fname, &preprocessed) != 0 || !preprocessed) {
        if (preprocessed) free(preprocessed);
        return -1;
    }
    FILE *file = fmemopen(preprocessed, strlen(preprocessed)+1, "r");

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", plugin_fname, strerror(errno));
        return 1;
    }

    read = getline(&line, &len, file);
    if (read == -1) {
        printf("Error in the file %s\n", plugin_fname);
        return 1;
    }

    protoop_plugin_t *p = plugin_parse_first_plugin_line(cnx, line);
    if (!p) {
        printf("Cannot extract plugin line in file %s\n", plugin_fname);
        return 1;
    }

    while (ok && (read = getline(&line, &len, file)) != -1) {
        /* Skip blank lines */
        if (read <= 1) {
            continue;
        }
        ok = insert_pluglet_from_plugin_line(cnx, line, p, plugin_dirname, (protoop_str_id_t ) inserted_pid, &param, &pte);
        if (ok) {
            /* Keep track of the inserted pids */
            tmp = (pid_node_t *) malloc(sizeof(pid_node_t));
            if (!tmp) {
                printf("No enough memory to allocate stack nodes; abort\n");
                ok = false;
                break;
            }
            if (strlen(inserted_pid) + 1 > sizeof(tmp->pid)){
                printf("No enough memory to store the plugin id\n");
                ok = false;
                break;
            }
            strcpy(tmp->pid, inserted_pid);
            tmp->param = param;
            tmp->pte = pte;
            tmp->next = pid_stack_top;
            pid_stack_top = tmp;
        }
    }

    while (pid_stack_top != NULL) {
        if (!ok) {
            /* Unplug previously plugged code */
            plugin_unplug(cnx, pid_stack_top->pid, pid_stack_top->param, pid_stack_top->pte);
        }
        tmp = pid_stack_top->next;
        free(pid_stack_top);
        pid_stack_top = tmp;
    }

    if (!ok) {
        free(p);
    } else {
        init_memory_management(p);
        HASH_ADD_STR(cnx->plugins, name, p);
    }

    free(preprocessed);

    if (line) {
        free(line);
    }

    fclose(file);

    return ok ? 0 : 1;
}

void *get_opaque_data(picoquic_cnx_t *cnx, opaque_id_t oid, size_t size, int *allocated) {
    if (!cnx->current_plugin) {
        printf("ERROR: get_opaque_data can only be called by pluglets with plugins!\n");
        return NULL;
    }
    picoquic_opaque_meta_t *ometas = cnx->current_plugin->opaque_metas;
    if (oid >= OPAQUE_ID_MAX) {
        printf("ERROR: pluglet from plugin %s ask for opaque id %u >= max opaque id %d\n", cnx->current_plugin->name, oid, OPAQUE_ID_MAX);
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
    /* Try to allocate memory with my_malloc */
    ometas[oid].start_ptr = my_malloc(cnx, size);
    if (!ometas[oid].start_ptr) {
        /* No space left... */
        return NULL;
    }

    /* Keep track of some meta data and returns the pointer */
    ometas[oid].size = size;
    *allocated = 1;
    return ometas[oid].start_ptr;
}

protoop_arg_t plugin_run_protoop_internal(picoquic_cnx_t *cnx, const protoop_params_t *pp) {
    if (pp->inputc > PROTOOPARGS_MAX) {
        printf("Too many arguments for protocol operation with id %s : %d > %d\n",
            pp->pid->id, pp->inputc, PROTOOPARGS_MAX);
        return PICOQUIC_ERROR_PROTOCOL_OPERATION_TOO_MANY_ARGUMENTS;
    }

    char *error_msg = NULL;

    /* First save previous args, and update context with new ones
     * Notice that we store ALL array of protoop_inputv and protoop_outputv.
     * With this, even if the called pluglet tried to modify the input arguments,
     * they will remain unchanged at caller side.
     */
    protoop_plugin_t *old_plugin = cnx->current_plugin;
    int caller_inputc = cnx->protoop_inputc;
    int caller_outputc = cnx->protoop_outputc_callee;
    uint64_t caller_inputv[caller_inputc];
    uint64_t caller_outputv[caller_outputc];
    memcpy(caller_inputv, cnx->protoop_inputv, sizeof(uint64_t) * caller_inputc);
    memcpy(caller_outputv, cnx->protoop_outputv, sizeof(uint64_t) * caller_outputc);
    memcpy(cnx->protoop_inputv, pp->inputv, sizeof(uint64_t) * pp->inputc);
    cnx->protoop_inputc = pp->inputc;

#ifdef DBG_PLUGIN_PRINTF
    for (int i = 0; i < pp->inputc; i++) {
        DBG_PLUGIN_PRINTF("Arg %d: 0x%lx", i, inputv[i]);
    }
#endif

    /* Also set protoop_outputv to 0, to prevent callee to see caller state */
    /* No more needed with the API */
    // memset(cnx->protoop_outputv, 0, sizeof(uint64_t) * PROTOOPARGS_MAX);
    cnx->protoop_outputc_callee = 0;

    DBG_PLUGIN_PRINTF("Running operation with id 0x%x with %d inputs", pid, inputc);

    /* Either we have a pluglet, and we run it, or we stick to the default ops behaviour */
    protoop_arg_t status;
    protocol_operation_struct_t *post;
    if (pp->pid->hash == 0) {
        pp->pid->hash = hash_value_str(pp->pid->id);
    }
    HASH_FIND_PID(cnx->ops, &(pp->pid->hash), post);
    if (!post) {
        printf("FATAL ERROR: no protocol operation with id %s and hash %lu\n", pp->pid->id, pp->pid->hash);
        exit(-1);
    }

    protocol_operation_param_struct_t *popst;
    if (post->is_parametrable) {
        HASH_FIND(hh, post->params, &pp->param, sizeof(param_id_t), popst);
        if (!popst) {
            param_id_t default_behaviour = NO_PARAM;
            HASH_FIND(hh, post->params, &default_behaviour, sizeof(param_id_t), popst);
            if (!popst) {
                printf("FATAL ERROR: no protocol operation with id %s and param %u, no default behaviour!\n", pp->pid->id, pp->param);
                exit(-1);
            }
        }
    } else {
        popst = post->params;
    }

    if (pp->caller_is_intern != popst->intern) {
        if (pp->caller_is_intern) {
            printf("FATAL ERROR: Intern caller cannot call extern protocol operation with id %s and param %u\n", pp->pid->id, pp->param);
        } else {
            printf("FATAL ERROR: Extern caller cannot call intern protocol operation with id %s and param %u\n", pp->pid->id, pp->param);
        }
        exit(-1);
    }

    if (popst->running) {
        printf("FATAL ERROR: Protocol operation call loop detected with id %s and param %u; exiting!\n", pp->pid->id, pp->param);
        exit(-1);
    }

    /* Record the protocol operation on the call stack */
    popst->running = true;

    /* First, is there any pre to run? */
    observer_node_t *tmp = popst->pre;
    while (tmp) {
        /* TODO: restrict the memory accesible by the observers */
        cnx->current_plugin = tmp->observer->p;
        exec_loaded_code(tmp->observer, (void *)cnx, (void *)cnx->current_plugin->memory, sizeof(cnx->current_plugin->memory), &error_msg);
        tmp = tmp->next;
    }

    /* The actual protocol operation */
    if (popst->replace) {
        DBG_PLUGIN_PRINTF("Running pluglet at proto op id %s", pp->pid->id);
        cnx->current_plugin = popst->replace->p;
        status = (protoop_arg_t) exec_loaded_code(popst->replace, (void *)cnx, (void *)cnx->current_plugin->memory, sizeof(cnx->current_plugin->memory), &error_msg);
        if (error_msg) {
            /* TODO fixme str_pid */
            fprintf(stderr, "Error when running %s: %s\n", pp->pid->id, error_msg);
        }
    } else if (popst->core) {
        cnx->current_plugin = NULL;
        status = popst->core(cnx);
    } else {
        /* TODO fixme str_pid */
        printf("FATAL ERROR: no replace nor core operation for protocol operation with id %s\n", pp->pid->id);
        exit(-1);
    }

    /* The previous plugin look at the last replace one */
    cnx->previous_plugin = cnx->current_plugin;

    /* Finally, is there any post to run? */
    tmp = popst->post;
    if (tmp) {
        cnx->protoop_output = status;
    }
    while (tmp) {
        /* TODO: restrict the memory accesible by the observers */
        cnx->current_plugin = tmp->observer->p;
        exec_loaded_code(tmp->observer, (void *)cnx, (void *)cnx->current_plugin->memory, sizeof(cnx->current_plugin->memory), &error_msg);
        tmp = tmp->next;
    }
    cnx->protoop_output = 0;

    int outputc = cnx->protoop_outputc_callee;

    DBG_PLUGIN_PRINTF("Protocol operation with id 0x%x returns 0x%lx with %d additional outputs", pid, status, outputc);

    /* Copy the output of the caller to the provided output pointer (if any)... */
    if (pp->outputv) {
        memcpy(pp->outputv, cnx->protoop_outputv, sizeof(uint64_t) * outputc);
#ifdef DBG_PLUGIN_PRINTF
        for (int i = 0; i < outputc; i++) {
            DBG_PLUGIN_PRINTF("Out %d: 0x%lx", i, outputv[i]);
        }
#endif
    } else if (outputc > 0) {
        printf("WARNING: no output value provided for protocol operation with id %s and param %u that returns %d additional outputs\n", pp->pid->id, pp->param, outputc);
        printf("HINT: this is probably not what you want, so maybe check if you called the right protocol operation...\n");
    }

    /* ... and restore ALL the previous inputs and outputs */
    memcpy(cnx->protoop_inputv, caller_inputv, sizeof(uint64_t) * caller_inputc);
    memcpy(cnx->protoop_outputv, caller_outputv, sizeof(uint64_t) * caller_outputc);
    cnx->protoop_inputc = caller_inputc;

    /* Remove the protocol operation from the call stack */
    popst->running = false;

    /* Also reset outputc to zero; if this protoop was called by another one that does not have any output,
     * it will likely not specify the outputc value, as it expects it to remain 0...
     */
    cnx->protoop_outputc_callee = caller_outputc;

    /* Also restore the plugin context */
    cnx->current_plugin = old_plugin;

    return status;
}

protoop_arg_t plugin_run_protoop(picoquic_cnx_t *cnx, protoop_params_t *pp, char *pid_str)
{
    protoop_id_t pid;
    pid.id = pid_str;
    pid.hash = hash_value_str(pid.id);
    pp->pid = &pid;
    return plugin_run_protoop_internal(cnx, pp);
}