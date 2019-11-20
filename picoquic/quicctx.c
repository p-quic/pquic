/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "picoquic_internal.h"
#include "picosocks.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>
#include "plugin.h"
#include "memory.h"
#include <ifaddrs.h>
#include <net/if.h>
#ifndef _WINDOWS
#include <sys/time.h>
#include <netinet/in.h>

#include <dirent.h>
#include <stdio.h>
#endif


/*
* Structures used in the hash table of connections
*/
typedef struct st_picoquic_cnx_id_t {
    picoquic_connection_id_t cnx_id;
    picoquic_cnx_t* cnx;
    struct st_picoquic_cnx_id_t* next_cnx_id;
} picoquic_cnx_id;

typedef struct st_picoquic_net_id_t {
    struct sockaddr_storage saddr;
    picoquic_cnx_t* cnx;
    struct st_picoquic_net_id_t* next_net_id;
} picoquic_net_id;

/* Hash and compare for CNX hash tables */
static uint64_t picoquic_cnx_id_hash(void* key)
{
    picoquic_cnx_id* cid = (picoquic_cnx_id*)key;

    /* TODO: should scramble the value for security and DOS protection */
    return picoquic_val64_connection_id(cid->cnx_id);
}

static int picoquic_cnx_id_compare(void* key1, void* key2)
{
    picoquic_cnx_id* cid1 = (picoquic_cnx_id*)key1;
    picoquic_cnx_id* cid2 = (picoquic_cnx_id*)key2;

    return picoquic_compare_connection_id(&cid1->cnx_id, &cid2->cnx_id);
}

static uint64_t picoquic_net_id_hash(void* key)
{
    picoquic_net_id* net = (picoquic_net_id*)key;

    return picohash_bytes((uint8_t*)&net->saddr, sizeof(net->saddr));
}

static int picoquic_net_id_compare(void* key1, void* key2)
{
    picoquic_net_id* net1 = (picoquic_net_id*)key1;
    picoquic_net_id* net2 = (picoquic_net_id*)key2;

    return memcmp(&net1->saddr, &net2->saddr, sizeof(net1->saddr));
}

#if 0
/* Not used yet, should be used in ordering connections by wake time. */
static int picoquic_compare_cnx_waketime(void * v_cnxleft, void * v_cnxright) {
    /* Example:  return *((int*)l) - *((int*)r); */
    int ret = 0;
    if (v_cnxleft != v_cnxright) {
        picoquic_cnx_t * cnx_l = (picoquic_cnx_t *)v_cnxleft;
        picoquic_cnx_t * cnx_r = (picoquic_cnx_t *)v_cnxright;

        if (cnx_l->next_wake_time > cnx_r->next_wake_time) {
            ret = 1;
        }
        else if (cnx_l->next_wake_time < cnx_r->next_wake_time) {
            ret = -1;
        }
        else {
            if (((intptr_t)v_cnxleft) > ((intptr_t)v_cnxright)) {
                ret = 1;
            }
            else {
                ret = -1;
            }
        }
    }
    return ret;
}
#endif

picoquic_packet_context_enum picoquic_context_from_epoch(int epoch)
{
    static picoquic_packet_context_enum const pc[4] = {
        picoquic_packet_context_initial,
        picoquic_packet_context_application,
        picoquic_packet_context_handshake,
        picoquic_packet_context_application
    };

    return (epoch >= 0 && epoch < 5) ? pc[epoch] : 0;
}

/*
 * Supported versions. Specific versions may mandate different processing of different
 * formats.
 * The first version in the list is the preferred version.
 * The protection of clear text packets will be a function of the version negotiation.
 */

static uint8_t picoquic_cleartext_internal_test_1_salt[] = {
    0x30, 0x67, 0x16, 0xd7, 0x63, 0x75, 0xd5, 0x55,
    0x4b, 0x2f, 0x60, 0x5e, 0xef, 0x78, 0xd8, 0x33,
    0x3d, 0xc1, 0xca, 0x36
};

static uint8_t picoquic_cleartext_draft_10_salt[] = {
    0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c,
    0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
    0xe0, 0x6d, 0x6c, 0x38
};

/* Support for draft 13! */
const picoquic_version_parameters_t picoquic_supported_versions[] = {
    { PICOQUIC_INTERNAL_TEST_VERSION_1, 0,
        picoquic_version_header_13,
        sizeof(picoquic_cleartext_internal_test_1_salt),
        picoquic_cleartext_internal_test_1_salt },
    { PICOQUIC_EIGHT_INTEROP_VERSION, 0,
        picoquic_version_header_13,
        sizeof(picoquic_cleartext_draft_10_salt),
        picoquic_cleartext_draft_10_salt },
    { PICOQUIC_SEVENTH_INTEROP_VERSION, 0,
        picoquic_version_header_13,
        sizeof(picoquic_cleartext_draft_10_salt),
        picoquic_cleartext_draft_10_salt }
};

const size_t picoquic_nb_supported_versions = sizeof(picoquic_supported_versions) / sizeof(picoquic_version_parameters_t);


int picoquic_get_plugin_stats(picoquic_cnx_t *cnx, plugin_stat_t **statsptr, int nmemb) {

    protocol_operation_struct_t *ops = (cnx->ops);
    protocol_operation_struct_t *current_post, *tmp_protoop;
    protocol_operation_param_struct_t *current_popst, *tmp_popst;
    observer_node_t *cur;
    plugin_stat_t *stats = *statsptr;
    if (!stats || nmemb == 0) {
        nmemb = 100;
        stats = malloc(nmemb*sizeof(plugin_stat_t));
        if (!stats) return -1;
    }

    int current_position = 0;



    HASH_ITER(hh, ops, current_post, tmp_protoop) {
        if (current_position == nmemb) {
            nmemb *= 2;
            stats = realloc(stats, nmemb*sizeof(plugin_stat_t));
            if (!stats) return -1;
        }

        if (current_post->is_parametrable) {
            HASH_ITER(hh, current_post->params, current_popst, tmp_popst) {
                if (current_popst->replace) {
                    stats[current_position].protoop_name = current_post->name;
                    stats[current_position].pluglet_name = current_popst->replace->p->name;
                    stats[current_position].replace = true;
                    stats[current_position].pre = false;
                    stats[current_position].post = false;
                    stats[current_position].is_param = true;
                    stats[current_position].param = current_popst->param;
                    stats[current_position].count = current_popst->replace->count;
                    stats[current_position].total_execution_time = current_popst->replace->total_execution_time;
                    current_position++;
                }

                if (current_popst->pre) {
                    cur = current_popst->pre;
                    while (cur) {
                        if (current_position == nmemb) {
                            nmemb *= 2;
                            stats = realloc(stats, nmemb*sizeof(plugin_stat_t));
                            if (!stats) return -1;
                        }
                        stats[current_position].protoop_name = current_post->name;
                        stats[current_position].pluglet_name = cur->observer->p->name;
                        stats[current_position].replace = false;
                        stats[current_position].pre = true;
                        stats[current_position].post = false;
                        stats[current_position].is_param = true;
                        stats[current_position].param = current_popst->param;
                        stats[current_position].count = cur->observer->count;
                        stats[current_position].total_execution_time = cur->observer->total_execution_time;
                        cur = cur->next;
                        current_position++;
                    }
                }
                if (current_popst->post) {
                    cur = current_popst->post;
                    while (cur) {
                        if (current_position == nmemb) {
                            nmemb *= 2;
                            stats = realloc(stats, nmemb*sizeof(plugin_stat_t));
                            if (!stats) return -1;
                        }
                        stats[current_position].protoop_name = current_post->name;
                        stats[current_position].pluglet_name = cur->observer->p->name;
                        stats[current_position].replace = false;
                        stats[current_position].pre = false;
                        stats[current_position].post = true;
                        stats[current_position].is_param = true;
                        stats[current_position].param = current_popst->param;
                        stats[current_position].count = cur->observer->count;
                        stats[current_position].total_execution_time = cur->observer->total_execution_time;
                        cur = cur->next;
                        current_position++;
                    }
                }
            }
        } else {
            current_popst = current_post->params;
            if (current_popst->replace) {
                if (current_position == nmemb) {
                    nmemb *= 2;
                    stats = realloc(stats, nmemb*sizeof(plugin_stat_t));
                    if (!stats) return -1;
                }
                stats[current_position].protoop_name = current_post->name;
                stats[current_position].pluglet_name = current_popst->replace->p->name;
                stats[current_position].replace = true;
                stats[current_position].pre = false;
                stats[current_position].post = false;
                stats[current_position].is_param = false;
                stats[current_position].count = current_popst->replace->count;
                stats[current_position].total_execution_time = current_popst->replace->total_execution_time;
                current_position++;
            }

            if (current_popst->pre) {
                cur = current_popst->pre;
                while (cur) {
                    if (current_position == nmemb) {
                        nmemb *= 2;
                        stats = realloc(stats, nmemb*sizeof(plugin_stat_t));
                        if (!stats) return -1;
                    }
                    stats[current_position].protoop_name = current_post->name;
                    stats[current_position].pluglet_name = cur->observer->p->name;
                    stats[current_position].replace = false;
                    stats[current_position].pre = true;
                    stats[current_position].post = false;
                    stats[current_position].is_param = false;
                    stats[current_position].count = cur->observer->count;
                    stats[current_position].total_execution_time = cur->observer->total_execution_time;
                    cur = cur->next;
                    current_position++;
                }
            }
            if (current_popst->post) {
                cur = current_popst->post;
                while (cur) {
                    if (current_position == nmemb) {
                        nmemb *= 2;
                        stats = realloc(stats, nmemb*sizeof(plugin_stat_t));
                        if (!stats) return -1;
                    }
                    stats[current_position].protoop_name = current_post->name;
                    stats[current_position].pluglet_name = cur->observer->p->name;
                    stats[current_position].replace = false;
                    stats[current_position].pre = false;
                    stats[current_position].post = true;
                    stats[current_position].is_param = false;
                    stats[current_position].count = cur->observer->count;
                    stats[current_position].total_execution_time = cur->observer->total_execution_time;
                    cur = cur->next;
                    current_position++;
                }
            }
        }
    }
    *statsptr = stats;
    return current_position;
}

void picoquic_free_protoops(protocol_operation_struct_t * ops)
{
    protocol_operation_struct_t *current_post, *tmp_protoop;
    protocol_operation_param_struct_t *current_popst, *tmp_popst;
    observer_node_t *cur_del, *tmp;

    HASH_ITER(hh, ops, current_post, tmp_protoop) {
        HASH_DEL(ops, current_post);

        if (current_post->is_parametrable) {
            HASH_ITER(hh, current_post->params, current_popst, tmp_popst) {
                HASH_DEL(current_post->params, current_popst);
                if (current_popst->replace) {
                    release_elf(current_popst->replace);
                }

                if (current_popst->pre) {
                    cur_del = current_popst->pre;
                    while (cur_del) {
                        tmp = cur_del->next;
                        release_elf(cur_del->observer);
                        free(cur_del);
                        cur_del = tmp;
                    }
                }
                if (current_popst->post) {
                    cur_del = current_popst->post;
                    while (cur_del) {
                        tmp = cur_del->next;
                        release_elf(cur_del->observer);
                        free(cur_del);
                        cur_del = tmp;
                    }
                }
                free(current_popst);
            }
        } else {
            current_popst = current_post->params;
            if (current_popst->replace) {
                release_elf(current_popst->replace);
            }

            if (current_popst->pre) {
                cur_del = current_popst->pre;
                while (cur_del) {
                    tmp = cur_del->next;
                    release_elf(cur_del->observer);
                    free(cur_del);
                    cur_del = tmp;
                }
            }
            if (current_popst->post) {
                cur_del = current_popst->post;
                while (cur_del) {
                    tmp = cur_del->next;
                    release_elf(cur_del->observer);
                    free(cur_del);
                    cur_del = tmp;
                }
            }
            free(current_popst);
        }

        free(current_post->pid.id);
        free(current_post);
    }
}

void picoquic_free_plugins(protoop_plugin_t *plugins)
{
    protoop_plugin_t *current_p, *tmp_p;
    HASH_ITER(hh, plugins, current_p, tmp_p) {
        HASH_DEL(plugins, current_p);
        /* This remains safe to do this, as the memory of the frame context will be freed when cnx will */
        queue_free(current_p->block_queue_cc);
        queue_free(current_p->block_queue_non_cc);
        destroy_memory_management(current_p);
        free(current_p);
    }
}

void picoquic_free_protoops_and_plugins(picoquic_cnx_t* cnx)
{
    picoquic_free_protoops(cnx->ops);
    picoquic_free_plugins(cnx->plugins);
}

void picoquic_free_cached_plugins(cached_plugins_t* cplugins)
{
    picoquic_free_protoops(cplugins->ops);
    picoquic_free_plugins(cplugins->plugins);
    free(cplugins);
}

int picoquic_get_supported_plugins(picoquic_quic_t* quic)
{
    quic->supported_plugins.size = 0;
    quic->supported_plugins.name_num_bytes = 0;

    if (quic->plugin_store_path == NULL) {
        /* No store path, so no supported plugins */
        return 0;
    }

#ifdef _WINDOWS
    DBG_PRINTF("File listing in Windows is not supported yet.\n");
    return 0;
#endif

    /* Single pass */
    DIR *d, *sub_d;
    struct dirent *dir, *sub_dir;
    const int max_plugin_fname_len = strlen(quic->plugin_store_path) + 514; /* From d_name max length, plus the separator and null char*/
    char tmp_buf[max_plugin_fname_len];
    char pid_buf[250]; /* Required plugin name size */
    size_t pid_size, path_size;
    d = opendir(quic->plugin_store_path);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            /* The first character cannot be a '.' */
            if (dir->d_name[0] != '.') {
                /* Don't forget to reinit tmp_buf... */
                memset(tmp_buf, 0, max_plugin_fname_len);
                strcpy(tmp_buf, quic->plugin_store_path);
                picoquic_string_join_path_and_fname(tmp_buf, dir->d_name);
                sub_d = opendir(tmp_buf);
                if (sub_d) {
                    while ((sub_dir = readdir(sub_d)) != NULL) {
                        if (picoquic_string_ends_with(sub_dir->d_name, ".plugin")) {
                            picoquic_string_join_path_and_fname(tmp_buf, sub_dir->d_name);
                            if (plugin_parse_plugin_id(tmp_buf, pid_buf)) {
                                fprintf(stderr, "Error when parsing PID of path %s\n", tmp_buf);
                                continue;
                            }
                            pid_size = strlen(pid_buf);
                            path_size = strlen(tmp_buf);
                            quic->supported_plugins.elems[quic->supported_plugins.size].plugin_path = malloc(sizeof(char) * (path_size + 1));
                            if (quic->supported_plugins.elems[quic->supported_plugins.size].plugin_path == NULL) {
                                fprintf(stderr, "Error when malloc'ing memory for path %s\n", tmp_buf);
                                continue;
                            }
                            quic->supported_plugins.elems[quic->supported_plugins.size].plugin_name = malloc(sizeof(char) * (pid_size + 1));
                            if (quic->supported_plugins.elems[quic->supported_plugins.size].plugin_name == NULL) {
                                fprintf(stderr, "Error when malloc'ing memory for name %s\n", pid_buf);
                                free(quic->supported_plugins.elems[quic->supported_plugins.size].plugin_path);
                                continue;
                            }
                            strcpy(quic->supported_plugins.elems[quic->supported_plugins.size].plugin_path, tmp_buf);
                            strcpy(quic->supported_plugins.elems[quic->supported_plugins.size].plugin_name, pid_buf);
                            quic->supported_plugins.name_num_bytes += pid_size;
                            quic->supported_plugins.size++;

                            if (quic->supported_plugins.size >= MAX_PLUGIN) {
                                fprintf(stderr, "WARNING: limit of supported plugins reached!\n");
                                break;
                            }
                        }
                    }
                    closedir(sub_d);
                }
            }
        }
        closedir(d);
    }

    return 0;
}


int picoquic_set_plugins_to_inject(picoquic_quic_t* quic, const char** plugin_fnames, int plugins)
{
    int err = 0;
    char buf[256];
    size_t buf_len;
    int i;
    for (i = 0; err == 0 && i < plugins; i++) {
        err = plugin_parse_plugin_id(plugin_fnames[i], buf);
        if (err != 0) {
            break;
        }
        buf_len = strlen(buf);
        quic->plugins_to_inject.elems[i].plugin_name = malloc(sizeof(char) * (buf_len + 1));
        if (quic->plugins_to_inject.elems[i].plugin_name == NULL) {
            break;
        }
        quic->plugins_to_inject.elems[i].plugin_path = malloc(sizeof(char) * (strlen(plugin_fnames[i]) + 1));
        if (quic->plugins_to_inject.elems[i].plugin_path == NULL) {
            free(quic->plugins_to_inject.elems[i].plugin_name);
            break;
        }
        strcpy(quic->plugins_to_inject.elems[i].plugin_name, buf);
        strcpy(quic->plugins_to_inject.elems[i].plugin_path, plugin_fnames[i]);
        printf("Plugin with path %s and name %s\n", quic->plugins_to_inject.elems[i].plugin_path, quic->plugins_to_inject.elems[i].plugin_name);
        quic->plugins_to_inject.name_num_bytes += buf_len;
        quic->plugins_to_inject.size++;
    }

    if (err != 0) {
        /* Free everything! */
        for (int j = 0; j < i; j++) {
            free(quic->plugins_to_inject.elems[i].plugin_name);
            free(quic->plugins_to_inject.elems[i].plugin_path);
        }
        quic->plugins_to_inject.size = 0;
        quic->plugins_to_inject.name_num_bytes = 0;
        return 1;
    }

    return 0;
}


/* QUIC context create and dispose */
picoquic_quic_t* picoquic_create(uint32_t nb_connections,
    char const* cert_file_name,
    char const* key_file_name, 
    char const * cert_root_file_name,
    char const* default_alpn,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    cnx_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_ctx,
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    uint64_t current_time,
    uint64_t* p_simulated_time,
    char const* ticket_file_name,
    const uint8_t* ticket_encryption_key,
    size_t ticket_encryption_key_length,
    char* plugin_store_path)
{
    picoquic_quic_t* quic = (picoquic_quic_t*)malloc(sizeof(picoquic_quic_t));
    int ret = 0;

    if (quic == NULL) {
        ret = -1;
    } else {
        /* TODO: winsock init */
        /* TODO: open UDP sockets - maybe */
        memset(quic, 0, sizeof(picoquic_quic_t));

        quic->default_callback_fn = default_callback_fn;
        quic->default_callback_ctx = default_callback_ctx;
        quic->default_congestion_alg = PICOQUIC_DEFAULT_CONGESTION_ALGORITHM;
        quic->default_alpn = picoquic_string_duplicate(default_alpn);
        quic->cnx_id_callback_fn = cnx_id_callback;
        quic->cnx_id_callback_ctx = cnx_id_callback_ctx;
        quic->p_simulated_time = p_simulated_time;
        quic->local_ctx_length = 8; /* TODO: should be lower on clients-only implementation */

        if (cnx_id_callback != NULL) {
            quic->flags |= picoquic_context_unconditional_cnx_id;
        }

        if (ticket_file_name != NULL) {
            quic->ticket_file_name = ticket_file_name;
            ret = picoquic_load_tickets(&quic->p_first_ticket, current_time, ticket_file_name);

            if (ret == PICOQUIC_ERROR_NO_SUCH_FILE) {
                DBG_PRINTF("Ticket file <%s> not created yet.\n", ticket_file_name);
                ret = 0;
            } else if (ret != 0) {
                DBG_PRINTF("Cannot load tickets from <%s>\n", ticket_file_name);
            }
        }
    }

    if (ret == 0) {
        quic->table_cnx_by_id = picohash_create(nb_connections * 4,
            picoquic_cnx_id_hash, picoquic_cnx_id_compare);

        quic->table_cnx_by_net = picohash_create(nb_connections * 4,
            picoquic_net_id_hash, picoquic_net_id_compare);

        if (quic->table_cnx_by_id == NULL || quic->table_cnx_by_net == NULL) {
            ret = -1;
            DBG_PRINTF("%s", "Cannot initialize hash tables\n");
        }
        else if (picoquic_master_tlscontext(quic, cert_file_name, key_file_name, cert_root_file_name, ticket_encryption_key, ticket_encryption_key_length) != 0) {
                ret = -1;
                DBG_PRINTF("%s", "Cannot create TLS context \n");     
        } else {
            /* the random generator was initialized as part of the TLS context.
             * Use it to create the seed for generating the per context stateless
             * resets. */

            if (!reset_seed)
                picoquic_crypto_random(quic, quic->reset_seed, sizeof(quic->reset_seed));
            else
                memcpy(quic->reset_seed, reset_seed, sizeof(quic->reset_seed));

            quic->cached_plugins_queue = queue_init();
            if (!quic->cached_plugins_queue) {
                ret = -1;
                DBG_PRINTF("%s", "Cannot create cached plugins queue \n");
            }
            quic->plugin_store_path = NULL;
            if (plugin_store_path != NULL) {
                if (picoquic_check_or_create_directory(plugin_store_path)) {
                    fprintf(stderr, "Cannot use plugin cache %s; continue without it.\n", plugin_store_path);
                } else {
                    quic->plugin_store_path = plugin_store_path;
                }
            }
            picoquic_get_supported_plugins(quic);
            /* If plugins should be inserted, a dedicated call will occur */
            quic->plugins_to_inject.size = 0;
            quic->plugins_to_inject.name_num_bytes = 0;
        }
    }

    if (ret != 0 && quic != NULL) {
        picoquic_free(quic);
        quic = NULL;
    }

    return quic;
}

void picoquic_free(picoquic_quic_t* quic)
{
    if (quic != NULL) {
        if (quic->aead_encrypt_ticket_ctx != NULL) {
            picoquic_aead_free(quic->aead_encrypt_ticket_ctx);
            quic->aead_encrypt_ticket_ctx = NULL;
        }

        if (quic->aead_decrypt_ticket_ctx != NULL) {
            picoquic_aead_free(quic->aead_decrypt_ticket_ctx);
            quic->aead_decrypt_ticket_ctx = NULL;
        }

        if (quic->default_alpn != NULL) {
            free((void*)quic->default_alpn);
            quic->default_alpn = NULL;
        }

        /* delete the stored tickets */
        picoquic_free_tickets(&quic->p_first_ticket);

        /* delete all pending packets */
        while (quic->pending_stateless_packet != NULL) {
            picoquic_stateless_packet_t* to_delete = quic->pending_stateless_packet;
            quic->pending_stateless_packet = to_delete->next_packet;
            free(to_delete);
        }

        /* delete all the connection contexts */
        while (quic->cnx_list != NULL) {
            picoquic_delete_cnx(quic->cnx_list);
        }

        if (quic->table_cnx_by_id != NULL) {
            picohash_delete(quic->table_cnx_by_id, 1);
        }

        if (quic->table_cnx_by_net != NULL) {
            picohash_delete(quic->table_cnx_by_net, 1);
        }

        if (quic->verify_certificate_ctx != NULL &&
            quic->free_verify_certificate_callback_fn != NULL) {
            (quic->free_verify_certificate_callback_fn)(quic->verify_certificate_ctx);
            quic->verify_certificate_ctx = NULL;
        }

        if (quic->verify_certificate_callback_fn != NULL) {
            picoquic_dispose_verify_certificate_callback(quic, 1);
        }

        /* Delete the picotls context */
        if (quic->tls_master_ctx != NULL) {
            picoquic_master_tlscontext_free(quic);

            free(quic->tls_master_ctx);
            quic->tls_master_ctx = NULL;
        }

        if (quic->cached_plugins_queue != NULL) {
            cached_plugins_t* tmp;
            while(queue_peek(quic->cached_plugins_queue) != NULL) {
                tmp = queue_dequeue(quic->cached_plugins_queue);
                picoquic_free_cached_plugins(tmp);
            }
            queue_free(quic->cached_plugins_queue);
        }

        if (quic->supported_plugins.size > 0) {
            for (int i = 0; i < quic->supported_plugins.size; i++) {
                free(quic->supported_plugins.elems[i].plugin_name);
                free(quic->supported_plugins.elems[i].plugin_path);
            }
        }

        if (quic->plugins_to_inject.size > 0) {
            for (int i = 0; i < quic->plugins_to_inject.size; i++) {
                free(quic->plugins_to_inject.elems[i].plugin_name);
                free(quic->plugins_to_inject.elems[i].plugin_path);
            }
        }

        free(quic);
    }
}

void picoquic_set_null_verifier(picoquic_quic_t* quic) {
    picoquic_dispose_verify_certificate_callback(quic, 1);
}

void picoquic_set_cookie_mode(picoquic_quic_t* quic, int cookie_mode)
{
    if (cookie_mode) {
        quic->flags |= picoquic_context_check_token;
        picoquic_crypto_random(quic, quic->retry_seed, PICOQUIC_RETRY_SECRET_SIZE);
    } else {
        quic->flags &= ~picoquic_context_check_token;
    }
}

picoquic_stateless_packet_t* picoquic_create_stateless_packet(picoquic_quic_t* quic)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(quic);
#endif
    return (picoquic_stateless_packet_t*)malloc(sizeof(picoquic_stateless_packet_t));
}

void picoquic_delete_stateless_packet(picoquic_stateless_packet_t* sp)
{
    free(sp);
}

void picoquic_queue_stateless_packet(picoquic_quic_t* quic, picoquic_stateless_packet_t* sp)
{
    picoquic_stateless_packet_t** pnext = &quic->pending_stateless_packet;

    while ((*pnext) != NULL) {
        pnext = &(*pnext)->next_packet;
    }

    *pnext = sp;
    sp->next_packet = NULL;
}

picoquic_stateless_packet_t* picoquic_dequeue_stateless_packet(picoquic_quic_t* quic)
{
    picoquic_stateless_packet_t* sp = quic->pending_stateless_packet;

    if (sp != NULL) {
        quic->pending_stateless_packet = sp->next_packet;
        sp->next_packet = NULL;
    }

    return sp;
}

/* Connection context creation and registration */
int picoquic_register_cnx_id(picoquic_quic_t* quic, picoquic_cnx_t* cnx, const picoquic_connection_id_t* cnx_id)
{
    int ret = 0;
    picoquic_cnx_id* key = (picoquic_cnx_id*)malloc(sizeof(picoquic_cnx_id));

    if (key == NULL) {
        ret = -1;
    } else {
        picohash_item* item;
        key->cnx_id = *cnx_id;
        key->cnx = cnx;
        key->next_cnx_id = NULL;

        item = picohash_retrieve(quic->table_cnx_by_id, key);

        if (item != NULL) {
            ret = -1;
        } else {
            ret = picohash_insert(quic->table_cnx_by_id, key);

            if (ret == 0) {
                key->next_cnx_id = cnx->first_cnx_id;
                cnx->first_cnx_id = key;
            }
        }
    }

    return ret;
}

int picoquic_register_cnx_id_for_cnx(picoquic_cnx_t* cnx, const picoquic_connection_id_t* cnx_id)
{
    return picoquic_register_cnx_id(cnx->quic, cnx, cnx_id);
}

static void picoquic_set_hash_key_by_address(picoquic_net_id * key, struct sockaddr* addr)
{
    memset(&key->saddr, 0, sizeof(struct sockaddr_storage));

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in * key4 = (struct sockaddr_in *) &key->saddr;
        struct sockaddr_in * s4 = (struct sockaddr_in *) addr;

#ifdef _WINDOWS
        key4->sin_addr.S_un.S_addr = s4->sin_addr.S_un.S_addr;
#else
        key4->sin_addr.s_addr = s4->sin_addr.s_addr;
#endif
        key4->sin_family = s4->sin_family;
        key4->sin_port = s4->sin_port;
    }
    else {
        struct sockaddr_in6 * key6 = (struct sockaddr_in6 *) &key->saddr;
        struct sockaddr_in6 * s6 = (struct sockaddr_in6 *) addr;
        memcpy(&key6->sin6_addr, &s6->sin6_addr, sizeof(struct in6_addr));
        key6->sin6_family = s6->sin6_family;
        key6->sin6_port = s6->sin6_port;
        /* TODO: special code for local addresses may be needed if scope is specified */
    }
}

int picoquic_register_net_id(picoquic_quic_t* quic, picoquic_cnx_t* cnx, struct sockaddr* addr)
{
    int ret = 0;
    picoquic_net_id* key = (picoquic_net_id*)malloc(sizeof(picoquic_net_id));

    if (key == NULL) {
        ret = -1;
    } else {
        picohash_item* item;
        picoquic_set_hash_key_by_address(key, addr);

        key->cnx = cnx;

        item = picohash_retrieve(quic->table_cnx_by_net, key);

        if (item != NULL) {
            ret = -1;
        } else {
            ret = picohash_insert(quic->table_cnx_by_net, key);

            if (ret == 0) {
                key->next_net_id = cnx->first_net_id;
                cnx->first_net_id = key;
            }
        }
    }

    if (key != NULL && ret != 0) {
        free(key);
    }

    return ret;
}

void picoquic_init_transport_parameters(picoquic_tp_t* tp, int client_mode)
{
    tp->initial_max_stream_data_bidi_local = 0x200000;
    tp->initial_max_stream_data_bidi_remote = 65635;
    tp->initial_max_stream_data_uni = 65535;
    tp->initial_max_data = 0x100000;
    if (client_mode) {
        tp->initial_max_stream_id_bidir = 65533;
        tp->initial_max_stream_id_unidir = 65535;
    } else {
        tp->initial_max_stream_id_bidir = 65532;
        tp->initial_max_stream_id_unidir = 65534;
    }
    tp->idle_timeout = PICOQUIC_MICROSEC_HANDSHAKE_MAX/1000000;
    tp->max_packet_size = PICOQUIC_PRACTICAL_MAX_MTU;
    tp->ack_delay_exponent = 3;
    tp->supported_plugins = NULL;
    tp->plugins_to_inject = NULL;
}


/* management of the list of connections in context */

picoquic_cnx_t* picoquic_get_first_cnx(picoquic_quic_t* quic)
{
    return quic->cnx_list;
}

picoquic_cnx_t* picoquic_get_next_cnx(picoquic_cnx_t* cnx)
{
    return cnx->next_in_table;
}

static void picoquic_insert_cnx_in_list(picoquic_quic_t* quic, picoquic_cnx_t* cnx)
{
    if (quic->cnx_list != NULL) {
        quic->cnx_list->previous_in_table = cnx;
        cnx->next_in_table = quic->cnx_list;
    } else {
        quic->cnx_last = cnx;
        cnx->next_in_table = NULL;
    }
    quic->cnx_list = cnx;
    cnx->previous_in_table = NULL;
}

static void picoquic_remove_cnx_from_list(picoquic_cnx_t* cnx)
{
    if (cnx->next_in_table == NULL) {
        cnx->quic->cnx_last = cnx->previous_in_table;
    } else {
        cnx->next_in_table->previous_in_table = cnx->previous_in_table;
    }

    if (cnx->previous_in_table == NULL) {
        cnx->quic->cnx_list = cnx->next_in_table;
    }
    else {
        cnx->previous_in_table->next_in_table = cnx->next_in_table;
    }
}

/* Management of the list of connections, sorted by wake time */

static void picoquic_remove_cnx_from_wake_list(picoquic_cnx_t* cnx)
{
    if (cnx->next_by_wake_time == NULL) {
        cnx->quic->cnx_wake_last = cnx->previous_by_wake_time;
    } else {
        cnx->next_by_wake_time->previous_by_wake_time = cnx->previous_by_wake_time;
    }
    
    if (cnx->previous_by_wake_time == NULL) {
        cnx->quic->cnx_wake_first = cnx->next_by_wake_time;
    } else {
        cnx->previous_by_wake_time->next_by_wake_time = cnx->next_by_wake_time;
    }
}

static void picoquic_insert_cnx_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx)
{
    picoquic_cnx_t * cnx_next = quic->cnx_wake_first;
    picoquic_cnx_t * previous = NULL;
    while (cnx_next != NULL && cnx_next->next_wake_time <= cnx->next_wake_time) {
        previous = cnx_next;
        cnx_next = cnx_next->next_by_wake_time;
    }
    
    cnx->previous_by_wake_time = previous;
    if (previous == NULL) {
        quic->cnx_wake_first = cnx;

    } else {
        previous->next_by_wake_time = cnx;
    }
    
    cnx->next_by_wake_time = cnx_next;

    if (cnx_next == NULL) {
        quic->cnx_wake_last = cnx;
    } else { 
        cnx_next->previous_by_wake_time = cnx;
    }
}

void picoquic_reinsert_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t next_time)
{
    picoquic_remove_cnx_from_wake_list(cnx);
    cnx->next_wake_time = next_time;
    picoquic_insert_cnx_by_wake_time(quic, cnx);
}

void picoquic_reinsert_cnx_by_wake_time(picoquic_cnx_t* cnx, uint64_t next_time)
{
    picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_time);
}

picoquic_cnx_t* picoquic_get_earliest_cnx_to_wake(picoquic_quic_t* quic, uint64_t max_wake_time)
{
    picoquic_cnx_t * cnx = quic->cnx_wake_first;
    if (cnx != NULL && max_wake_time != 0 && cnx->next_wake_time > max_wake_time)
    {
        cnx = NULL;
    }

    return cnx;
}


int64_t picoquic_get_next_wake_delay(picoquic_quic_t* quic,
    uint64_t current_time, int64_t delay_max)
{
    int64_t wake_delay = delay_max;

    if (quic->cnx_wake_first != NULL) {
        if (quic->cnx_wake_first->next_wake_time > current_time) {
            wake_delay = quic->cnx_wake_first->next_wake_time - current_time;
            
            if (wake_delay > delay_max) {
                wake_delay = delay_max;
            }
        }
        else {
            wake_delay = 0;
        }
    } else {
        wake_delay = delay_max;
    }

    return wake_delay;
}

/* Other context management functions */

int picoquic_get_version_index(uint32_t proposed_version)
{
    int ret = -1;

    for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
        if (picoquic_supported_versions[i].version == proposed_version) {
            ret = (int)i;
            break;
        }
    }

    return ret;
}

int picoquic_create_path(picoquic_cnx_t* cnx, uint64_t start_time, struct sockaddr* addr)
{
    int ret = -1;

    if (cnx->nb_paths >= cnx->nb_path_alloc)
    {
        int new_alloc = (cnx->nb_path_alloc == 0) ? 1 : 2 * cnx->nb_path_alloc;
        picoquic_path_t ** new_path = (picoquic_path_t **)malloc(new_alloc * sizeof(picoquic_path_t *));

        if (new_path != NULL)
        {
            if (cnx->path != NULL)
            {
                if (cnx->nb_paths > 0)
                {
                    memcpy(new_path, cnx->path, cnx->nb_paths * sizeof(picoquic_path_t *));
                }
                free(cnx->path);
            }
            cnx->path = new_path;
            cnx->nb_path_alloc = new_alloc;
        }
    }

    if (cnx->nb_paths < cnx->nb_path_alloc)
    {
        picoquic_path_t * path_x = (picoquic_path_t *)malloc(sizeof(picoquic_path_t));

        if (path_x != NULL)
        {
            memset(path_x, 0, sizeof(picoquic_path_t));

            /* Set the peer address */
            path_x->peer_addr_len = (int)((addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            memcpy(&path_x->peer_addr, addr, path_x->peer_addr_len);

            /* Set the challenge used for this path */
            path_x->challenge = picoquic_public_random_64();

            /* Initialize per path time measurement */
            path_x->smoothed_rtt = PICOQUIC_INITIAL_RTT;
            path_x->rtt_variant = 0;
            path_x->retransmit_timer = PICOQUIC_INITIAL_RETRANSMIT_TIMER;
            path_x->rtt_min = 0;

            /* Initialize per path congestion control state */
            path_x->cwin = PICOQUIC_CWIN_INITIAL;
            path_x->bytes_in_transit = 0;
            path_x->congestion_alg_state = NULL;

            /* Initialize per path pacing state */
            path_x->packet_time_nano_sec = 0;
            path_x->pacing_reminder_nano_sec = 0;
            path_x->pacing_margin_micros = 1000;
            path_x->next_pacing_time = start_time;

            /* Initialize the MTU */
            path_x->send_mtu = addr->sa_family == AF_INET ? PICOQUIC_INITIAL_MTU_IPV4 : PICOQUIC_INITIAL_MTU_IPV6;

            /* Initialize the connection IDs */
            if (cnx->quic) {
                picoquic_create_random_cnx_id(cnx->quic, &path_x->local_cnxid, cnx->quic->local_ctx_length);
            }

            path_x->remote_cnxid = picoquic_null_connection_id;
            /* Initialize the reset secret to a random value. This
			 * will prevent spurious matches to an all zero value, for example.
			 * The real value will be set when receiving the transport parameters. 
			 */
            picoquic_public_random(path_x->reset_secret, PICOQUIC_RESET_SECRET_SIZE);

            path_x->nb_pkt_sent = 0;

            /* Initialize packet contexts */
            for (picoquic_packet_context_enum pc = 0;
                pc < picoquic_nb_packet_context; pc++) {
                path_x->pkt_ctx[pc].first_sack_item.start_of_sack_range = (uint64_t)((int64_t)-1);
                path_x->pkt_ctx[pc].first_sack_item.end_of_sack_range = 0;
                path_x->pkt_ctx[pc].first_sack_item.next_sack = NULL;
                path_x->pkt_ctx[pc].highest_ack_sent = 0;
                path_x->pkt_ctx[pc].highest_ack_time = start_time;
                path_x->pkt_ctx[pc].time_stamp_largest_received = (uint64_t)((int64_t)-1);
                path_x->pkt_ctx[pc].send_sequence = 0;
                path_x->pkt_ctx[pc].nb_retransmit = 0;
                path_x->pkt_ctx[pc].latest_retransmit_time = 0;
                path_x->pkt_ctx[pc].latest_retransmit_cc_notification_time = 0;
                path_x->pkt_ctx[pc].retransmit_newest = NULL;
                path_x->pkt_ctx[pc].retransmit_oldest = NULL;
                path_x->pkt_ctx[pc].highest_acknowledged = path_x->pkt_ctx[pc].send_sequence - 1;
                path_x->pkt_ctx[pc].latest_time_acknowledged = start_time;
                path_x->pkt_ctx[pc].latest_progress_time = start_time;
                path_x->pkt_ctx[pc].ack_needed = 0;
                path_x->pkt_ctx[pc].ack_delay_local = 10000;
            }

            /* And start the congestion algorithm */
            if (cnx->congestion_alg != NULL) {
                cnx->congestion_alg->alg_init(cnx, path_x);
            }

            /* Record the path */
            cnx->path[cnx->nb_paths] = path_x;
            ret = cnx->nb_paths++;

            if (cnx->nb_paths > 1) LOG {
                char local_id_str[(path_x->local_cnxid.id_len * 2) + 1];
                snprintf_bytes(local_id_str, sizeof(local_id_str), path_x->local_cnxid.id, path_x->local_cnxid.id_len);

                char peer_addr_str[250];
                inet_ntop(path_x->peer_addr_len == sizeof(struct sockaddr_in) ? AF_INET : AF_INET6, path_x->peer_addr_len == sizeof(struct sockaddr_in) ? (void *) &((struct sockaddr_in *)&path_x->peer_addr)->sin_addr : (void *) &((struct sockaddr_in6 *)&path_x->peer_addr)->sin6_addr, peer_addr_str, sizeof(peer_addr_str));
                LOG_EVENT(cnx, "CONNECTION", "PATH_CREATED", "", "{\"path\": \"%p\", \"peer_addr\": \"%s\", \"scid\": \"%s\"}", path_x, peer_addr_str, local_id_str);
            }
        }
    }

    return ret;
}

void picoquic_create_random_cnx_id(picoquic_quic_t* quic, picoquic_connection_id_t * cnx_id, uint8_t id_length)
{
    if (id_length > 0) {
        picoquic_crypto_random(quic, cnx_id->id, id_length);
    }
    if (id_length < sizeof(cnx_id->id)) {
        memset(cnx_id->id + 8, 0, sizeof(cnx_id->id) - id_length);
    }
    cnx_id->id_len = id_length;
}

void picoquic_create_random_cnx_id_for_cnx(picoquic_cnx_t* cnx, picoquic_connection_id_t *cnx_id, uint8_t id_length)
{
    picoquic_create_random_cnx_id(cnx->quic, cnx_id, id_length);
}


picoquic_cnx_t* picoquic_create_cnx(picoquic_quic_t* quic,
    picoquic_connection_id_t initial_cnx_id, picoquic_connection_id_t remote_cnx_id, 
    struct sockaddr* addr, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn, char client_mode)
{
    picoquic_cnx_t* cnx = (picoquic_cnx_t*)malloc(sizeof(picoquic_cnx_t));

    if (cnx != NULL) {
        int ret;

        memset(cnx, 0, sizeof(picoquic_cnx_t));

        cnx->quic = quic;
        cnx->client_mode = client_mode;
        /* Should return 0, since this is the first path */
        ret = picoquic_create_path(cnx, start_time, addr);

        if (ret != 0) {
            free(cnx);
            cnx = NULL;
        } else {
            cnx->next_wake_time = start_time;
            cnx->start_time = start_time;

            picoquic_insert_cnx_in_list(quic, cnx);
            picoquic_insert_cnx_by_wake_time(quic, cnx);
            /* Do not require verification for default path */
            cnx->path[0]->challenge_verified = 1;
        }
    }

    if (cnx != NULL) {
        picoquic_init_transport_parameters(&cnx->local_parameters, cnx->client_mode);
        if (cnx->quic->mtu_max > 0)
        {
            cnx->local_parameters.max_packet_size = cnx->quic->mtu_max;
        }

        /* Initialize local flow control variables to advertised values */

        cnx->maxdata_local = ((uint64_t)cnx->local_parameters.initial_max_data);
        cnx->max_stream_id_bidir_local = cnx->local_parameters.initial_max_stream_id_bidir;
        cnx->max_stream_id_unidir_local = cnx->local_parameters.initial_max_stream_id_unidir;

        /* Initialize remote variables to some plausible value. 
		 * Hopefully, this will be overwritten by the parameters received in
		 * the TLS transport parameter extension */
        cnx->maxdata_remote = PICOQUIC_DEFAULT_0RTT_WINDOW;
        cnx->remote_parameters.initial_max_stream_data_bidi_remote = PICOQUIC_DEFAULT_0RTT_WINDOW;
        cnx->remote_parameters.initial_max_stream_data_uni = PICOQUIC_DEFAULT_0RTT_WINDOW;
        cnx->max_stream_id_bidir_remote = (cnx->client_mode)?4:0;
        cnx->max_stream_id_unidir_remote = 0;

        if (sni != NULL) {
            cnx->sni = picoquic_string_duplicate(sni);
        }

        if (alpn != NULL) {
            cnx->alpn = picoquic_string_duplicate(alpn);
        }

        cnx->callback_fn = quic->default_callback_fn;
        cnx->callback_ctx = quic->default_callback_ctx;
        cnx->congestion_alg = quic->default_congestion_alg;

        if (cnx->client_mode) {
            if (preferred_version == 0) {
                cnx->proposed_version = picoquic_supported_versions[0].version;
                cnx->version_index = 0;
            } else {
                cnx->version_index = picoquic_get_version_index(preferred_version);
                if (cnx->version_index < 0) {
                    cnx->version_index = PICOQUIC_INTEROP_VERSION_INDEX;
                    if ((preferred_version & 0x0A0A0A0A) == 0x0A0A0A0A) {
                        /* This is a hack, to allow greasing the cnx ID */
                        cnx->proposed_version = preferred_version;

                    } else {
                        cnx->proposed_version = picoquic_supported_versions[PICOQUIC_INTEROP_VERSION_INDEX].version;
                    }
                } else {
                    cnx->proposed_version = preferred_version;
                }
            }

            cnx->cnx_state = picoquic_state_client_init;
            if (picoquic_is_connection_id_null(initial_cnx_id)) {
                picoquic_create_random_cnx_id(quic, &initial_cnx_id, 8);
            }

            if (quic->cnx_id_callback_fn) {
                quic->cnx_id_callback_fn(cnx->path[0]->local_cnxid, picoquic_null_connection_id, quic->cnx_id_callback_ctx, &cnx->path[0]->local_cnxid);
            }

            cnx->initial_cnxid = initial_cnx_id;
        } else {
            for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
                cnx->tls_stream[epoch].send_queue = NULL;
            }
            cnx->cnx_state = picoquic_state_server_init;
            cnx->initial_cnxid = initial_cnx_id;
            cnx->path[0]->remote_cnxid = remote_cnx_id;

            if (quic->cnx_id_callback_fn)
                quic->cnx_id_callback_fn(cnx->path[0]->local_cnxid, cnx->initial_cnxid,
                    quic->cnx_id_callback_ctx, &cnx->path[0]->local_cnxid);

            (void)picoquic_create_cnxid_reset_secret(quic, &cnx->path[0]->local_cnxid,
                cnx->path[0]->reset_secret);

            cnx->version_index = picoquic_get_version_index(preferred_version);
            if (cnx->version_index < 0) {
                /* TODO: this is an internal error condition, should not happen */
                cnx->version_index = 0;
                cnx->proposed_version = picoquic_supported_versions[0].version;
            } else {
                cnx->proposed_version = preferred_version;
            }
        }

        if (cnx != NULL) {
            /* Moved packet context initialization into path creation */

            cnx->latest_progress_time = start_time;

            for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
                cnx->tls_stream[epoch].stream_id = 0;
                cnx->tls_stream[epoch].consumed_offset = 0;
                cnx->tls_stream[epoch].stream_flags = 0;
                cnx->tls_stream[epoch].fin_offset = 0;
                cnx->tls_stream[epoch].next_stream = NULL;
                cnx->tls_stream[epoch].stream_data = NULL;
                cnx->tls_stream[epoch].sent_offset = 0;
                cnx->tls_stream[epoch].local_error = 0;
                cnx->tls_stream[epoch].remote_error = 0;
                cnx->tls_stream[epoch].maxdata_local = (uint64_t)((int64_t)-1);
                cnx->tls_stream[epoch].maxdata_remote = (uint64_t)((int64_t)-1);
            }

            cnx->congestion_alg = cnx->quic->default_congestion_alg;
            if (cnx->congestion_alg != NULL) {
                cnx->congestion_alg->alg_init(cnx, cnx->path[0]);
            }
        }
    }

    /* Only initialize TLS after all parameters have been set */

    if (picoquic_tlscontext_create(quic, cnx, start_time) != 0) {
        /* Cannot just do partial creation! */
        picoquic_delete_cnx(cnx);
        cnx = NULL;
    }

    if (cnx != NULL) {
        if (picoquic_setup_initial_traffic_keys(cnx)) {
            /* Cannot initialize aead for initial packets */
            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }
    }

    if (cnx != NULL) {
        if (!picoquic_is_connection_id_null(cnx->path[0]->local_cnxid)) {
            (void)picoquic_register_cnx_id(quic, cnx, &cnx->path[0]->local_cnxid);
        }

        if (addr != NULL) {
            (void)picoquic_register_net_id(quic, cnx, addr);
        }
    }

    if (cnx) {
        register_protocol_operations(cnx);
        /* Also initialize reserve queue */
        cnx->reserved_frames = queue_init();
        /* And the retry queue */
        cnx->retry_frames = queue_init();
        for (int pc = 0; pc < picoquic_nb_packet_context; pc++) {
            cnx->rtx_frames[pc] = queue_init();
        }
        /* TODO change this arbitrary value */
        cnx->core_rate = 500;
    }

    return cnx;
}

picoquic_cnx_t* picoquic_create_client_cnx(picoquic_quic_t* quic,
    struct sockaddr* addr, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn, picoquic_stream_data_cb_fn callback_fn, void* callback_ctx)
{
    picoquic_cnx_t* cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id, addr, start_time, preferred_version, sni, alpn, 1);

    if (cnx != NULL) {
        int ret;

        if (callback_fn != NULL)
            cnx->callback_fn = callback_fn;
        if (callback_ctx != NULL)
            cnx->callback_ctx = callback_ctx;
        ret = picoquic_initialize_tls_stream(cnx);
        if (ret != 0) {
            /* Cannot just do partial initialization! */
            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }
    }

    return cnx;
}

void register_protocol_operations(picoquic_cnx_t *cnx)
{
    /* First ensure that ops is set to NULL, required by uthash.h */
    cnx->ops = NULL;
    cnx->plugins = NULL;
    cnx->current_plugin = NULL;
    cnx->previous_plugin_in_replace = NULL;
    packet_register_noparam_protoops(cnx);
    frames_register_noparam_protoops(cnx);
    sender_register_noparam_protoops(cnx);
    quicctx_register_noparam_protoops(cnx);
}

int picoquic_start_client_cnx(picoquic_cnx_t * cnx)
{
    int ret = picoquic_initialize_tls_stream(cnx);

    picoquic_cnx_set_next_wake_time(cnx, picoquic_get_quic_time(cnx->quic), 1);

    return ret;
}

void picoquic_set_transport_parameters(picoquic_cnx_t * cnx, picoquic_tp_t * tp)
{
    cnx->local_parameters = *tp;

    if (cnx->quic->mtu_max > 0)
    {
        cnx->local_parameters.max_packet_size = cnx->quic->mtu_max;
    }

    /* Initialize local flow control variables to advertised values */

    cnx->maxdata_local = ((uint64_t)cnx->local_parameters.initial_max_data);
    cnx->max_stream_id_bidir_local = cnx->local_parameters.initial_max_stream_id_bidir;
    cnx->max_stream_id_unidir_local = cnx->local_parameters.initial_max_stream_id_unidir;
}

void picoquic_get_peer_addr(picoquic_path_t* path_x, struct sockaddr** addr, int* addr_len)
{
    *addr = (struct sockaddr*)&path_x->peer_addr;
    *addr_len = path_x->peer_addr_len;
}

void picoquic_get_local_addr(picoquic_path_t* path_x, struct sockaddr** addr, int* addr_len)
{
    *addr = (struct sockaddr*)&path_x->local_addr;
    *addr_len = path_x->local_addr_len;
}

unsigned long picoquic_get_local_if_index(picoquic_path_t* path_x)
{
    return path_x->if_index_local;
}

picoquic_connection_id_t picoquic_get_local_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->local_cnxid;
}

picoquic_connection_id_t picoquic_get_remote_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->remote_cnxid;
}

picoquic_connection_id_t picoquic_get_initial_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->initial_cnxid;
}

picoquic_connection_id_t picoquic_get_client_cnxid(picoquic_cnx_t* cnx)
{
    return (cnx->client_mode)?cnx->path[0]->local_cnxid: cnx->path[0]->remote_cnxid;
}

picoquic_connection_id_t picoquic_get_server_cnxid(picoquic_cnx_t* cnx)
{
    return (cnx->client_mode) ? cnx->path[0]->remote_cnxid : cnx->path[0]->local_cnxid;
}

picoquic_connection_id_t picoquic_get_logging_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->initial_cnxid;
}

uint64_t picoquic_get_cnx_start_time(picoquic_cnx_t* cnx)
{
    return cnx->start_time;
}

picoquic_state_enum picoquic_get_cnx_state(picoquic_cnx_t* cnx)
{
    return cnx->cnx_state;
}

void picoquic_set_cnx_state(picoquic_cnx_t* cnx, picoquic_state_enum state)
{
    picoquic_state_enum previous_state = cnx->cnx_state;
    cnx->cnx_state = state;
    if(previous_state != cnx->cnx_state) {
        LOG_EVENT(cnx, "CONNECTION", "NEW_STATE", "", "{\"state\": \"%s\"}", picoquic_log_state_name(cnx->cnx_state));
        protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_CONNECTION_STATE_CHANGED, NULL,
            previous_state, state);
    }
}

uint64_t picoquic_is_0rtt_available(picoquic_cnx_t* cnx)
{
    return (cnx->crypto_context[1].aead_encrypt == NULL) ? 0 : 1;
}

/* Return the index in the list of pid, or the size of the list otherwise */
int picoquic_pid_index(plugin_list_t* list, char* pid)
{
    for (int j = 0; j < list->size; j++) {
        if (strcmp(list->elems[j].plugin_name, pid) == 0) {
            return j;
        }
    }
    return list->size;
}

int picoquic_handle_plugin_negotiation_client(picoquic_cnx_t* cnx)
{
    /* If there is no plugins_to_inject remote parameter, stop now */
    if (!cnx->remote_parameters.plugins_to_inject) {
        return 0;
    }
    /* The client can inject all plugins required that it already supports. */
    char **pids_to_inject = picoquic_string_split(cnx->remote_parameters.plugins_to_inject, ',');
    char *pid_to_inject;
    int index;
    plugin_list_t* supported_plugins = &cnx->quic->supported_plugins;
    if (pids_to_inject) {
        plugin_fname_t plugins[supported_plugins->size];
        uint8_t nb_plugins = 0;

        for (int i = 0; (pid_to_inject = pids_to_inject[i]) != NULL; i++) {
            /* Search in the supported plugins */
            index = picoquic_pid_index(supported_plugins, pid_to_inject);

            if (index < supported_plugins->size) {
                plugins[nb_plugins] = supported_plugins->elems[index];
                nb_plugins++;
            } else {
                fprintf(stderr, "Client does not support plugin %s, request it.\n", pid_to_inject);
                size_t pid_len = strlen(pid_to_inject) + 1;
                cnx->pids_to_request.elems[cnx->pids_to_request.size].plugin_name = malloc(sizeof(char) * (pid_len));
                if (cnx->pids_to_request.elems[cnx->pids_to_request.size].plugin_name == NULL) {
                    fprintf(stderr, "Client cannot allocate memory to request %s!\n", pid_to_inject);
                } else {
                    cnx->pids_to_request.elems[cnx->pids_to_request.size].data = malloc(sizeof(uint8_t) * MAX_PLUGIN_DATA_LEN);
                    if (cnx->pids_to_request.elems[cnx->pids_to_request.size].data == NULL) {
                        fprintf(stderr, "Client cannot allocate memory to request %s!\n", pid_to_inject);
                        free(cnx->pids_to_request.elems[cnx->pids_to_request.size].plugin_name);
                        cnx->pids_to_request.elems[cnx->pids_to_request.size].plugin_name = NULL;
                    } else {
                        memcpy(cnx->pids_to_request.elems[cnx->pids_to_request.size].plugin_name, pid_to_inject, pid_len);
                        cnx->pids_to_request.elems[cnx->pids_to_request.size].pid_id = cnx->pids_to_request.size;
                        cnx->pids_to_request.size++;
                    }
                }
            }
        }

        /* TODO plugin loading optimisation */
        int nb_plugins_failed = plugin_insert_plugins(cnx, nb_plugins, plugins);
        if (nb_plugins_failed == 0) {
            fprintf(stderr, "Client successfully inserted %u plugins\n", nb_plugins);
        } else {
            fprintf(stderr, "Client failed to insert %d plugins\n", nb_plugins_failed);
        }
        free(pids_to_inject);
    }

    return 0;
}

int picoquic_handle_plugin_negotiation_server(picoquic_cnx_t* cnx)
{
    /* If there is no supported_plugins remote parameter, stop now */
    if (!cnx->remote_parameters.supported_plugins) {
        return 0;
    }
    char **supported_pids = picoquic_string_split(cnx->remote_parameters.supported_plugins, ',');
    char *supported_pid;
    int index;
    plugin_list_t* plugins_to_inject = &cnx->quic->plugins_to_inject;
    if (supported_pids) {
        plugin_fname_t plugins[plugins_to_inject->size];
        uint8_t nb_plugins = 0;

        for (int i = 0; (supported_pid = supported_pids[i]) != NULL; i++) {
            /* Search in the plugins to inject */
            index = picoquic_pid_index(plugins_to_inject, supported_pid);

            if (index < plugins_to_inject->size) {
                plugins[nb_plugins] = plugins_to_inject->elems[index];
                nb_plugins++;
            }
        }
        /* TODO plugin loading optimisation */
        int nb_plugins_failed = plugin_insert_plugins(cnx, nb_plugins, plugins);
        if (nb_plugins_failed == 0) {
            fprintf(stderr, "Server successfully inserted %u plugins\n", nb_plugins);
        } else {
            fprintf(stderr, "Server failed to insert %d plugins\n", nb_plugins_failed);
        }
        free(supported_pids);
    }

    return 0;
}

/* Handle plugin negotiation */
int picoquic_handle_plugin_negotiation(picoquic_cnx_t* cnx)
{
    /* This function should be called once transport parameters have been exchanged */
    if (!cnx->remote_parameters_received) {
        DBG_PRINTF("Trying to handle plugin negotiation before having received remote transport parameters!\n");
        return 1;
    }

    int err;

    /* XXX So far, we only allow remote injection from server to client */
    if (picoquic_is_client(cnx)) {
        err = picoquic_handle_plugin_negotiation_client(cnx);
    } else {
        err = picoquic_handle_plugin_negotiation_server(cnx);
    }

    return err;
}

/*
 * Provide clock time
 */
uint64_t picoquic_current_time()
{
    uint64_t now;
#ifdef _WINDOWS
    FILETIME ft;
    /*
    * The GetSystemTimeAsFileTime API returns  the number
    * of 100-nanosecond intervals since January 1, 1601 (UTC),
    * in FILETIME format.
    */
    GetSystemTimeAsFileTime(&ft);

    /*
    * Convert to plain 64 bit format, without making
    * assumptions about the FILETIME structure alignment.
    */
    now = ft.dwHighDateTime;
    now <<= 32;
    now |= ft.dwLowDateTime;
    /*
    * Convert units from 100ns to 1us
    */
    now /= 10;
    /*
    * Account for microseconds elapsed between 1601 and 1970.
    */
    now -= 11644473600000000ULL;
#else
    struct timeval tv;
    (void)gettimeofday(&tv, NULL);
    now = (tv.tv_sec * 1000000ull) + tv.tv_usec;
#endif
    return now;
}

/*
* Get the same time simulation as used for TLS
*/

uint64_t picoquic_get_quic_time(picoquic_quic_t* quic)
{
    uint64_t now;
    if (quic->p_simulated_time == NULL) {
        now = picoquic_current_time();
    }
    else {
        now = *quic->p_simulated_time;
    }

    return now;
}

void picoquic_set_fuzz(picoquic_quic_t * quic, picoquic_fuzz_fn fuzz_fn, void * fuzz_ctx)
{
    quic->fuzz_fn = fuzz_fn;
    quic->fuzz_ctx = fuzz_ctx;
}



void picoquic_set_callback(picoquic_cnx_t* cnx,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx)
{
    cnx->callback_fn = callback_fn;
    cnx->callback_ctx = callback_ctx;
}

void * picoquic_get_callback_context(picoquic_cnx_t * cnx)
{
    return cnx->callback_ctx;
}

picoquic_misc_frame_header_t* picoquic_create_misc_frame(picoquic_cnx_t *cnx, const uint8_t* bytes, size_t length) {
    uint8_t* misc_frame = (uint8_t*)malloc(sizeof(picoquic_misc_frame_header_t) + length);

    if (misc_frame == NULL) {
        return NULL;
    } else {
        picoquic_misc_frame_header_t* head = (picoquic_misc_frame_header_t*)misc_frame;
        head->length = length;
        memcpy(misc_frame + sizeof(picoquic_misc_frame_header_t), bytes, length);

        return head;
    }
}

int picoquic_queue_misc_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t length)
{
    int ret = 0;
    picoquic_misc_frame_header_t* misc_frame = picoquic_create_misc_frame(cnx, bytes, length);

    if (misc_frame == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    } else {
        misc_frame->next_misc_frame = cnx->first_misc_frame;
        cnx->first_misc_frame = misc_frame;
    }

    picoquic_cnx_set_next_wake_time(cnx, picoquic_get_quic_time(cnx->quic), 1);

    return ret;
}

void picoquic_clear_stream(picoquic_stream_head* stream)
{
    picoquic_stream_data** pdata[2];
    pdata[0] = &stream->stream_data;
    pdata[1] = &stream->send_queue;

    for (int i = 0; i < 2; i++) {
        picoquic_stream_data* next;

        while ((next = *pdata[i]) != NULL) {
            *pdata[i] = next->next_stream_data;

            if (next->bytes != NULL) {
                free(next->bytes);
            }
            free(next);
        }
    }
}

void picoquic_reset_packet_context(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc, picoquic_path_t* path_x)
{
    /* TODO: special case for 0-RTT packets! */
    picoquic_packet_context_t * pkt_ctx = &path_x->pkt_ctx[pc];

    while (pkt_ctx->retransmit_newest != NULL) {
        picoquic_dequeue_retransmit_packet(cnx, pkt_ctx->retransmit_newest, 1);
    }
    
    while (pkt_ctx->retransmitted_newest != NULL) {
        picoquic_dequeue_retransmitted_packet(cnx, pkt_ctx->retransmitted_newest);
    }

    pkt_ctx->retransmitted_oldest = NULL;

    while (pkt_ctx->first_sack_item.next_sack != NULL) {
        picoquic_sack_item_t * next = pkt_ctx->first_sack_item.next_sack;
        pkt_ctx->first_sack_item.next_sack = next->next_sack;
        free(next);
    }

    pkt_ctx->first_sack_item.start_of_sack_range = (uint64_t)((int64_t)-1);
    pkt_ctx->first_sack_item.end_of_sack_range = 0;
}

/*
* Reset the version to a new supported value.
*
* Can only happen after sending the client init packet.
* Result of reset:
*
* - connection ID is not changed.
* - sequence number is not changed.
* - all queued 0-RTT retransmission will be considered lost (to do with 0-RTT)
* - Client Initial packet is considered lost, free. A new one will have to be formatted.
* - Stream 0 is reset, all data is freed.
* - TLS API is called again.
* - State changes.
*/

int picoquic_reset_cnx(picoquic_cnx_t* cnx, uint64_t current_time)
{
    int ret = 0;

    /* Delete the packets queued for retransmission */
    for (picoquic_packet_context_enum pc = 0;
        pc < picoquic_nb_packet_context; pc++) {
        /* Do not reset the application context, in order to keep the 0-RTT
         * packets, and to keep using the same sequence number space in
         * the new connection */
        if (pc != picoquic_packet_context_application) {
            picoquic_reset_packet_context(cnx, pc, cnx->path[0]);
        }
    }

    /* Reset the crypto stream */
    for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
        picoquic_clear_stream(&cnx->tls_stream[epoch]);
        cnx->tls_stream[epoch].consumed_offset = 0;
        cnx->tls_stream[epoch].stream_flags = 0;
        cnx->tls_stream[epoch].fin_offset = 0;
        cnx->tls_stream[epoch].sent_offset = 0;
    }

    /* Reset the ECN data */
    cnx->ecn_ect0_total_local = 0;
    cnx->ecn_ect1_total_local = 0;
    cnx->ecn_ce_total_local = 0;
    cnx->ecn_ect0_total_remote = 0;
    cnx->ecn_ect1_total_remote = 0;
    cnx->ecn_ce_total_remote = 0;

    for (int k = 0; k < 4; k++) {
        picoquic_crypto_context_free(&cnx->crypto_context[k]);
    }

    if (ret == 0) {
        ret = picoquic_setup_initial_traffic_keys(cnx);
    }

    /* Reset the TLS context, Re-initialize the tls connection */
    if (cnx->tls_ctx != NULL) {
        picoquic_tlscontext_free(cnx, cnx->tls_ctx);
        cnx->tls_ctx = NULL;
    }
    if (ret == 0) {
        ret = picoquic_tlscontext_create(cnx->quic, cnx, current_time);
    }
    if (ret == 0) {
        ret = picoquic_initialize_tls_stream(cnx);
    }

    return ret;
}

int picoquic_reset_cnx_version(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length, uint64_t current_time)
{
    /* First parse the incoming connection negotiation to choose the
	* new version. If none is available, return an error */
    int ret = -1;

    if (cnx->cnx_state == picoquic_state_client_init || cnx->cnx_state == picoquic_state_client_init_sent) {
        size_t byte_index = 0;
        while (cnx->cnx_state != picoquic_state_client_renegotiate && byte_index + 4 <= length) {
            uint32_t proposed_version = 0;
            /* parsing the list of proposed versions encoded in renegotiation packet */
            proposed_version = PICOPARSE_32(bytes + byte_index);
            byte_index += 4;

            for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
                if (proposed_version == picoquic_supported_versions[i].version) {
                    cnx->version_index = (int)i;
                    picoquic_set_cnx_state(cnx, picoquic_state_client_renegotiate);

                    break;
                }
            }
        }

        if (cnx->cnx_state != picoquic_state_client_renegotiate) {
            /* No acceptable version */
            ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
        } else {
            ret = picoquic_reset_cnx(cnx, current_time);
        }
    }
    else {
        /* Not in a state for negotiation */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return ret;
}

/**
 * See PROTOOP_NOPARAM_CONNECTION_ERROR
 */
protoop_arg_t connection_error(picoquic_cnx_t* cnx)
{
    uint16_t local_error = (uint16_t) cnx->protoop_inputv[0];
    uint64_t frame_type = (uint64_t) cnx->protoop_inputv[1];

    if (cnx->cnx_state == picoquic_state_client_ready || cnx->cnx_state == picoquic_state_server_ready) {
        cnx->local_error = local_error;
        picoquic_set_cnx_state(cnx, picoquic_state_disconnecting);

        DBG_PRINTF("Protocol error (%x)", local_error);
    } else if (cnx->cnx_state < picoquic_state_client_ready) {
        cnx->local_error = local_error;
        picoquic_set_cnx_state(cnx, picoquic_state_handshake_failure);

        DBG_PRINTF("Protocol error %x", local_error);
    }

    cnx->offending_frame_type = frame_type;

    LOG_EVENT(cnx, "CONNECTION", "ERROR", "", "{\"local_error\": %d, \"frame_type\": %lu}", local_error, frame_type);

    return (protoop_arg_t) PICOQUIC_ERROR_DETECTED;
}

int picoquic_connection_error(picoquic_cnx_t* cnx, uint16_t local_error, uint64_t frame_type)
{
    return (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_CONNECTION_ERROR, NULL,
        local_error, frame_type);
}

void picoquic_delete_cnx(picoquic_cnx_t* cnx)
{
    picoquic_stream_head* stream;
    picoquic_misc_frame_header_t* misc_frame;

    if (cnx != NULL) {
        if (cnx->cnx_state < picoquic_state_disconnected) {
            /* Give the application a chance to clean up its state */
            picoquic_set_cnx_state(cnx, picoquic_state_disconnected);
            if (cnx->callback_fn) {
                (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
            }
        }

        if (cnx->alpn != NULL) {
            free((void*)cnx->alpn);
            cnx->alpn = NULL;
        }

        if (cnx->sni != NULL) {
            free((void*)cnx->sni);
            cnx->sni = NULL;
        }

        while (cnx->first_cnx_id != NULL) {
            picohash_item* item;
            picoquic_cnx_id* cnx_id_key = cnx->first_cnx_id;
            cnx->first_cnx_id = cnx_id_key->next_cnx_id;
            cnx_id_key->next_cnx_id = NULL;

            item = picohash_retrieve(cnx->quic->table_cnx_by_id, cnx_id_key);
            if (item != NULL) {
                picohash_item_delete(cnx->quic->table_cnx_by_id, item, 1);
            }
        }

        while (cnx->first_net_id != NULL) {
            picohash_item* item;
            picoquic_net_id* net_id_key = cnx->first_net_id;
            cnx->first_net_id = net_id_key->next_net_id;
            net_id_key->next_net_id = NULL;

            item = picohash_retrieve(cnx->quic->table_cnx_by_net, net_id_key);
            if (item != NULL) {
                picohash_item_delete(cnx->quic->table_cnx_by_net, item, 1);
            }
        }
        
        picoquic_remove_cnx_from_list(cnx);
        picoquic_remove_cnx_from_wake_list(cnx);

        for (int i = 0; i < 4; i++) {
            picoquic_crypto_context_free(&cnx->crypto_context[i]);
        }

        for (picoquic_packet_context_enum pc = 0;
            pc < picoquic_nb_packet_context; pc++) {
            for (int i = 0; i < cnx->nb_paths; i++) {
                picoquic_reset_packet_context(cnx, pc, cnx->path[i]);
            }
        }

        while ((misc_frame = cnx->first_misc_frame) != NULL) {
            cnx->first_misc_frame = misc_frame->next_misc_frame;
            free(misc_frame);
        }
        for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
            picoquic_clear_stream(&cnx->tls_stream[epoch]);
        }

        while ((stream = cnx->first_stream) != NULL) {
            cnx->first_stream = stream->next_stream;
            picoquic_clear_stream(stream);
            free(stream);
        }

        while ((stream = cnx->first_plugin_stream) != NULL) {
            cnx->first_plugin_stream = stream->next_stream;
            picoquic_clear_stream(stream);
            free(stream);
        }

        if (cnx->tls_ctx != NULL) {
            picoquic_tlscontext_free(cnx, cnx->tls_ctx);
            cnx->tls_ctx = NULL;
        }

        if (cnx->path != NULL)
        {
            for (int i = 0; i < cnx->nb_paths; i++) {

                if (cnx->congestion_alg != NULL) {
                    cnx->congestion_alg->alg_delete(cnx, cnx->path[i]);
                }

                free(cnx->path[i]);
                cnx->path[i] = NULL;
            }

            free(cnx->path);
            cnx->path = NULL;
        }

        /* If we are the server, keep the protocol operations in the cache */
        /* First condition is needed for tests */
        if (cnx->quic && !picoquic_is_client(cnx)) {
            cached_plugins_t* cached = malloc(sizeof(cached_plugins_t));
            if (!cached) {
                DBG_PRINTF("%s", "Cannot allocate memory to cache plugins; free them.\n");
                picoquic_free_protoops_and_plugins(cnx);
            } else {
                cached->ops = cnx->ops;
                cached->plugins = cnx->plugins;
                cached->nb_plugins = 0;
                protoop_plugin_t *current_p, *tmp_p;
                HASH_ITER(hh, cached->plugins, current_p, tmp_p) {
                    /* This remains safe to do this, as the memory of the frame context will be freed when cnx will */
                    while(queue_peek(current_p->block_queue_cc) != NULL) {queue_dequeue(current_p->block_queue_cc);}
                    while(queue_peek(current_p->block_queue_non_cc) != NULL) {queue_dequeue(current_p->block_queue_non_cc);}
                    /* The additional critical data that should be reset is the opaque data in plugins */
                    memset(current_p->opaque_metas, 0, sizeof(current_p->opaque_metas));
                    /* First destroy the memory */
                    destroy_memory_management(current_p);
                    /* And reinit the memory */
                    init_memory_management(current_p);
                    /* And copy the name of the plugin */
                    strcpy(cached->plugin_names[cached->nb_plugins], current_p->name);
                    /* We found one plugin, so count it! */
                    cached->nb_plugins++;
                }
                int err = queue_enqueue(cnx->quic->cached_plugins_queue, cached);
                if (err) {
                    DBG_PRINTF("%s", "Cannot insert cached plugins; free them.\n");
                    picoquic_free_protoops_and_plugins(cnx);
                    free(cached);
                }
            }
        } else {
            /* Free protocol operations and plugins */
            picoquic_free_protoops_and_plugins(cnx);
        }

        /* Free possibly allocated memory in pids to request */
        for (int i = 0; i < cnx->pids_to_request.size; i++) {
            if (cnx->pids_to_request.elems[i].plugin_name != NULL) {
                free(cnx->pids_to_request.elems[i].plugin_name);
                cnx->pids_to_request.elems[i].plugin_name = NULL;
            }
            if (cnx->pids_to_request.elems[i].data != NULL) {
                free(cnx->pids_to_request.elems[i].data);
                cnx->pids_to_request.elems[i].data = NULL;
            }
        }

        /* Free the plugin name pointers */
        if (cnx->local_parameters.supported_plugins != NULL) {
            free(cnx->local_parameters.supported_plugins);
        }
        if (cnx->remote_parameters.supported_plugins != NULL) {
            free(cnx->local_parameters.supported_plugins);
        }
        if (cnx->local_parameters.plugins_to_inject != NULL) {
            free(cnx->local_parameters.plugins_to_inject);
        }
        if (cnx->remote_parameters.plugins_to_inject != NULL) {
            free(cnx->local_parameters.plugins_to_inject);
        }

        /* Delete pending reserved frames, if any */
        queue_free(cnx->reserved_frames);
        /* And also the retry frames */
        queue_free(cnx->retry_frames);

        free(cnx);
    }
}

int picoquic_is_handshake_error(uint16_t error_code)
{
    return ((error_code & 0xFF00) == PICOQUIC_TRANSPORT_CRYPTO_ERROR(0) ||
        error_code == PICOQUIC_TLS_HANDSHAKE_FAILED);
}

/* Context retrieval functions */
picoquic_cnx_t* picoquic_cnx_by_id(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id)
{
    picoquic_cnx_t* ret = NULL;
    picohash_item* item;
    picoquic_cnx_id key;

    memset(&key, 0, sizeof(key));
    key.cnx_id = cnx_id;

    item = picohash_retrieve(quic->table_cnx_by_id, &key);

    if (item != NULL) {
        ret = ((picoquic_cnx_id*)item->key)->cnx;
    }
    return ret;
}

picoquic_cnx_t* picoquic_cnx_by_net(picoquic_quic_t* quic, struct sockaddr* addr)
{
    picoquic_cnx_t* ret = NULL;
    picohash_item* item;
    picoquic_net_id key;

    picoquic_set_hash_key_by_address(&key, addr);

    item = picohash_retrieve(quic->table_cnx_by_net, &key);

    if (item != NULL) {
        ret = ((picoquic_net_id*)item->key)->cnx;
    }
    return ret;
}

/*
 * Set or reset the congestion control algorithm
 */

void picoquic_set_default_congestion_algorithm(picoquic_quic_t* quic, picoquic_congestion_algorithm_t const* alg)
{
    quic->default_congestion_alg = alg;
}

void picoquic_set_congestion_algorithm(picoquic_cnx_t* cnx, picoquic_congestion_algorithm_t const* alg)
{
    if (cnx->congestion_alg != NULL) {
        if (cnx->path != NULL) {
            for (int i = 0; i < cnx->nb_paths; i++) {
                cnx->congestion_alg->alg_delete(cnx, cnx->path[i]);
            }
        }
    }

    cnx->congestion_alg = alg;

    if (cnx->congestion_alg != NULL) {
        if (cnx->path != NULL) {
            for (int i = 0; i < cnx->nb_paths; i++) {
                cnx->congestion_alg->alg_init(cnx, cnx->path[i]);
            }
        }
    }
}

/**
 * See PROTOOP_NOPARAM_CONGESTION_ALGORITHM_NOTIFY
 */
protoop_arg_t congestion_algorithm_notify(picoquic_cnx_t *cnx)
{
    picoquic_path_t* path_x = (picoquic_path_t*) cnx->protoop_inputv[0];
    picoquic_congestion_notification_t notification = (picoquic_congestion_notification_t) cnx->protoop_inputv[1];
    uint64_t rtt_measurement = (uint64_t) cnx->protoop_inputv[2];
    uint64_t nb_bytes_acknowledged = (uint64_t) cnx->protoop_inputv[3];
    uint64_t lost_packet_number = (uint64_t) cnx->protoop_inputv[4];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[5];

    if (cnx->congestion_alg != NULL) {
        cnx->congestion_alg->alg_notify(path_x, notification, rtt_measurement,
            nb_bytes_acknowledged, lost_packet_number, current_time);
    }
    return 0;
}


void picoquic_congestion_algorithm_notify_func(picoquic_cnx_t *cnx, picoquic_path_t* path_x, picoquic_congestion_notification_t notification, uint64_t rtt_measurement,
                                 uint64_t nb_bytes_acknowledged, uint64_t lost_packet_number, uint64_t current_time) {
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_CONGESTION_ALGORITHM_NOTIFY, NULL, path_x, notification, rtt_measurement, nb_bytes_acknowledged,
            lost_packet_number, current_time);
}

/**
 * See PROTOOP_NOPARAM_CALLBACK_FUNCTION
 */
protoop_arg_t callback_function(picoquic_cnx_t *cnx)
{
    uint64_t stream_id = (uint64_t) cnx->protoop_inputv[0];
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[1];
    size_t length = (size_t) cnx->protoop_inputv[2];
    picoquic_call_back_event_t fin_or_event = (picoquic_call_back_event_t) cnx->protoop_inputv[3];

    if (cnx->callback_fn) {
        (cnx->callback_fn)(cnx, stream_id, bytes, length, fin_or_event, cnx->callback_ctx);
    }

    return 0;
}

void picoquic_enable_keep_alive(picoquic_cnx_t* cnx, uint64_t interval)
{
    if (interval == 0) {
        /* Examine the transport parameters */
        uint64_t idle_timeout = cnx->local_parameters.idle_timeout;

        if (cnx->cnx_state >= picoquic_state_client_ready && idle_timeout > cnx->remote_parameters.idle_timeout) {
            idle_timeout = cnx->remote_parameters.idle_timeout;
        }
        /* convert to microseconds */
        idle_timeout *= 1000000;
        /* set interval to half that value */
        cnx->keep_alive_interval = idle_timeout / 2;
    } else {
        cnx->keep_alive_interval = interval;
    }
}

void picoquic_disable_keep_alive(picoquic_cnx_t* cnx)
{
    cnx->keep_alive_interval = 0;
}

int picoquic_set_verify_certificate_callback(picoquic_quic_t* quic, picoquic_verify_certificate_cb_fn cb, void* ctx,
                                             picoquic_free_verify_certificate_ctx free_fn) {
    picoquic_dispose_verify_certificate_callback(quic, quic->verify_certificate_callback_fn != NULL);

    quic->verify_certificate_callback_fn = cb;
    quic->free_verify_certificate_callback_fn = free_fn;
    quic->verify_certificate_ctx = ctx;

    return picoquic_enable_custom_verify_certificate_callback(quic);
}

int picoquic_is_client(picoquic_cnx_t* cnx)
{
    return cnx->client_mode;
}

int picoquic_get_local_error(picoquic_cnx_t* cnx)
{
    return cnx->local_error;
}

int picoquic_get_remote_error(picoquic_cnx_t* cnx)
{
    return cnx->remote_error;
}

void picoquic_set_client_authentication(picoquic_quic_t* quic, int client_authentication) {
    picoquic_tls_set_client_authentication(quic, client_authentication);
}

void picoquic_received_packet(picoquic_cnx_t *cnx, SOCKET_TYPE socket) {
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_RECEIVED_PACKET, NULL,
        socket);
}

void picoquic_before_sending_packet(picoquic_cnx_t *cnx, SOCKET_TYPE socket) {
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_BEFORE_SENDING_PACKET, NULL,
        socket);
}

void picoquic_received_segment(picoquic_cnx_t *cnx, picoquic_packet_header *ph, picoquic_path_t* path, size_t length) {
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_RECEIVED_SEGMENT, NULL, ph, path, length);
}

void picoquic_before_sending_segment(picoquic_cnx_t *cnx, picoquic_packet_header *ph, picoquic_path_t *path, picoquic_packet_t *packet, size_t length) {
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_BEFORE_SENDING_SEGMENT, NULL, ph, path, packet, length);
}

/*
bool is_private(in_addr_t t) {
    bool ret = false;
    in_addr_t a = t & (in_addr_t) 0xff;
    if( a == (in_addr_t) 0x7f ) ret = true;
    if( a == (in_addr_t) 0x0a ) ret = true;
    in_addr_t b = t & (in_addr_t) 0xe0ff;
    if( b == (in_addr_t) 0xac ) ret = true;
    in_addr_t c = t & (in_addr_t) 0xffff;
    if( c == (in_addr_t) 0xa8c0 ) ret = true;
    return ret;
}
*/

int picoquic_getaddrs(struct sockaddr_storage *sas, uint32_t *if_indexes, int sas_length)
{
    int family;
    struct ifaddrs *ifaddr, *ifa;
    int count = 0;
    struct sockaddr_storage *start_ptr = sas;
    unsigned int if_index;

    if (getifaddrs(&ifaddr) == -1) {
        return 0;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (strncmp("docker", ifa->ifa_name, 6) == 0 ||
            strncmp("lo", ifa->ifa_name, 2) == 0 ||
            strncmp("tun", ifa->ifa_name, 3) == 0)
        {
            /* Do not consider those addresses */
            continue;
        }
        /* What if an interface has no IP address? */
        if (ifa->ifa_addr) {
            family = ifa->ifa_addr->sa_family;
            if (family == AF_INET || family == AF_INET6) {
                struct sockaddr_storage *sai = (struct sockaddr_storage *) ifa->ifa_addr;
                if (family == AF_INET6) {
                    struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *) ifa->ifa_addr;
                    if (sai6->sin6_addr.__in6_u.__u6_addr16[0] == 0x80fe) {
                        continue;
                    }
                }
                if (count < sas_length) {
                    if_index = if_nametoindex(ifa->ifa_name);
                    memcpy(&if_indexes[count], &if_index, sizeof(uint32_t));
                    size_t sockaddr_size = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
                    memcpy(&start_ptr[count++], sai, sockaddr_size);
                }
            }
        }   
    }

    freeifaddrs(ifaddr);

    return count;
}

/**
 * See PROTOOP_NOPARAM_PRINTF
 */
protoop_arg_t protoop_printf(picoquic_cnx_t *cnx)
{
    protoop_arg_t *fmt_args = (protoop_arg_t *) cnx->protoop_inputv[1];
    switch (cnx->protoop_inputv[2]) {
        case 0: printf("%s", (const char *) cnx->protoop_inputv[0]); break;
        case 1: printf((const char *) cnx->protoop_inputv[0], fmt_args[0]); break;
        case 2: printf((const char *) cnx->protoop_inputv[0], fmt_args[0], fmt_args[1]); break;
        case 3: printf((const char *) cnx->protoop_inputv[0], fmt_args[0], fmt_args[1], fmt_args[2]); break;
        case 4: printf((const char *) cnx->protoop_inputv[0], fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3]); break;
        case 5: printf((const char *) cnx->protoop_inputv[0], fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4]); break;
        case 6: printf((const char *) cnx->protoop_inputv[0], fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4], fmt_args[5]); break;
        case 7: printf((const char *) cnx->protoop_inputv[0], fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4], fmt_args[5], fmt_args[6]); break;
        case 8: printf((const char *) cnx->protoop_inputv[0], fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4], fmt_args[5], fmt_args[6], fmt_args[7]); break;
        case 9: printf((const char *) cnx->protoop_inputv[0], fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4], fmt_args[5], fmt_args[6], fmt_args[7], fmt_args[8]); break;
        case 10: printf((const char *) cnx->protoop_inputv[0], fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4], fmt_args[5], fmt_args[6], fmt_args[7], fmt_args[8], fmt_args[9]); break;
        default:
            printf("protoop printf cannot handle more than 10 arguments, %lu were given\n", (unsigned long) cnx->protoop_inputv[2]);
    }
    fflush(stdout);
    return 0;
}

protoop_arg_t protoop_snprintf(picoquic_cnx_t *cnx)
{
    char *buf = (char *) cnx->protoop_inputv[0];
    size_t buf_len = (size_t) cnx->protoop_inputv[1];
    char *fmt = (char *) cnx->protoop_inputv[2];
    protoop_arg_t *fmt_args = (protoop_arg_t *) cnx->protoop_inputv[3];
    switch (cnx->protoop_inputv[4]) {
        case 0: return snprintf(buf, buf_len, "%s", fmt);
        case 1: return snprintf(buf, buf_len, fmt, fmt_args[0]);
        case 2: return snprintf(buf, buf_len, fmt, fmt_args[0], fmt_args[1]);
        case 3: return snprintf(buf, buf_len, fmt, fmt_args[0], fmt_args[1], fmt_args[2]);
        case 4: return snprintf(buf, buf_len, fmt, fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3]);
        case 5: return snprintf(buf, buf_len, fmt, fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4]);
        case 6: return snprintf(buf, buf_len, fmt, fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4], fmt_args[5]);
        case 7: return snprintf(buf, buf_len, fmt, fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4], fmt_args[5], fmt_args[6]);
        case 8: return snprintf(buf, buf_len, fmt, fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4], fmt_args[5], fmt_args[6], fmt_args[7]);
        case 9: return snprintf(buf, buf_len, fmt, fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4], fmt_args[5], fmt_args[6], fmt_args[7], fmt_args[8]);
        case 10: return snprintf(buf, buf_len, fmt, fmt_args[0], fmt_args[1], fmt_args[2], fmt_args[3], fmt_args[4], fmt_args[5], fmt_args[6], fmt_args[7], fmt_args[8], fmt_args[9]);
        default:
            printf("protoop snprintf cannot handle more than 10 arguments, %lu were given\n", cnx->protoop_inputv[4]);
    }
    fflush(stdout);
    return 0;
}

/* A simple no-op */
protoop_arg_t protoop_noop(picoquic_cnx_t *cnx)
{
    /* Do nothing! */
    return 0;
}

/* Always return true */
protoop_arg_t protoop_true(picoquic_cnx_t *cnx)
{
    return true;
}

/* Always return false */
protoop_arg_t protoop_false(picoquic_cnx_t *cnx)
{
    return false;
}


protocol_operation_param_struct_t *create_protocol_operation_param(param_id_t param, protocol_operation op) 
{
    protocol_operation_param_struct_t *popst = malloc(sizeof(protocol_operation_param_struct_t));
    if (!popst) {
        printf("ERROR: failed to allocate memory for protocol operation param\n");
        return NULL;
    }
    popst->param = param;
    popst->core = op;
    popst->intern = true;  /* Assumes it is internal */
    popst->running = false; /* Of course, it does not run yet */
    /* Ensure NULL values */
    popst->replace = NULL;
    popst->pre = NULL;
    popst->post = NULL;
    return popst;
}

int register_noparam_protoop(picoquic_cnx_t* cnx, protoop_id_t *pid, protocol_operation op)
{
    /* This is a safety check */
    protocol_operation_struct_t *post;
    /* First check if the hash has been computed or not */
    if (pid->hash == 0) {
        /* And compute it if needed */
        pid->hash = hash_value_str(pid->id);
    }
    HASH_FIND_PID(cnx->ops, &(pid->hash), post);
    if (post) {
        printf("ERROR: trying to register twice the non-parametrable protocol operation %s\n", pid->id);
        return 1;
    }
    
    post = malloc(sizeof(protocol_operation_struct_t));
    if (!post) {
        printf("ERROR: failed to allocate memory to register non-parametrable protocol operation %s\n", pid->id);
        return 1;
    }
    size_t p_strlen = (strlen(pid->id) + 1);
    post->pid.id = malloc(sizeof(char) * p_strlen);
    if (!post->pid.id) {
        free(post);
        printf("ERROR: failed to allocate memory to register name of %s\n", pid->id);
        return 1;
    }
    strncpy(post->pid.id, pid->id, p_strlen);
    strncpy(post->name, pid->id, sizeof(post->name) > p_strlen ? p_strlen : sizeof(post->name));
    post->is_parametrable = false;
    post->params = create_protocol_operation_param(NO_PARAM, op);
    if (!post->params) {
        free(post->pid.id);
        free(post);
        return 1;
    }
    /* Don't forget to copy the hash of the pid */
    post->pid.hash = pid->hash;
    HASH_ADD_PID(cnx->ops, pid.hash, post);
    return 0;
}

int register_param_protoop(picoquic_cnx_t* cnx, protoop_id_t *pid, param_id_t param, protocol_operation op)
{
    /* Two possible options: either the protocol operation had a previously registered
     * value for another parameter, or it is the first one
     */
    protocol_operation_struct_t *post;
    protocol_operation_param_struct_t *popst;
    /* First check if the hash has been computed or not */
    if (pid->hash == 0) {
        /* And compute it if needed */
        pid->hash = hash_value_str(pid->id);
    }
    HASH_FIND_PID(cnx->ops, &(pid->hash), post);
    if (post) {
        /* Two sanity checks:
         * 1- Is it really a parametrable protocol operation?
         * 2- Is there no previously registered protocol operation for that parameter?
         */
        if (!post->is_parametrable) {
            printf("ERROR: trying to insert parameter in non-parametrable protocol operation %s\n", pid->id);
            return 1;
        }
        HASH_FIND(hh, post->params, &param, sizeof(param_id_t), popst);
        if (popst) {
            printf("ERROR: trying to register twice the parametrable protocol operation %s with param %u\n", pid->id, param);
            return 1;
        }
    } else {
        /* Create it */
        post = malloc(sizeof(protocol_operation_struct_t));
        if (!post) {
            printf("ERROR: failed to allocate memory to register parametrable protocol operation %s with param %u\n", pid->id, param);
            return 1;
        }
        size_t p_strlen = (strlen(pid->id) + 1);
        post->pid.id = malloc(sizeof(char) * p_strlen);
        if (!post->pid.id) {
            free(post);
            printf("ERROR: failed to allocate memory to register name of %s with param %u\n", pid->id, param);
            return 1;
        }
        strncpy(post->pid.id, pid->id, p_strlen);
        strncpy(post->name, pid->id, sizeof(post->name) > p_strlen ? p_strlen : sizeof(post->name));
        post->is_parametrable = true;
        /* Ensure the value is NULL */
        post->params = NULL;
    }

    popst = create_protocol_operation_param(param, op);

    if (!popst) {
        /* If the post is new, remove it */
        if (!post->params) {
            free(post->pid.id);
            free(post);
        }
        return 1;
    }

    /* Insert the post if it is new */
    if (!post->params) {
        /* Don't forget to copy the hash of the pid */
        post->pid.hash = pid->hash;
        HASH_ADD_PID(cnx->ops, pid.hash, post);
    }
    /* Insert the param struct */
    HASH_ADD(hh, post->params, param, sizeof(param_id_t), popst);
    return 0;
}

int register_param_protoop_default(picoquic_cnx_t* cnx, protoop_id_t *pid, protocol_operation op)
{
    return register_param_protoop(cnx, pid, NO_PARAM, op);
}

size_t reserve_frames(picoquic_cnx_t* cnx, uint8_t nb_frames, reserve_frame_slot_t* slots)
{
    if (!cnx->current_plugin) {
        printf("ERROR: reserve_frames can only be called by pluglets with plugins!\n");
        return 0;
    }
    PUSH_LOG_CTX(cnx, "\"plugin\": \"%s\", \"protoop\": \"%s\", \"anchor\": \"%s\"",  cnx->current_plugin->name, cnx->current_protoop->name, pluglet_type_name(cnx->current_anchor));

    /* Well, or we could use queues instead ? */
    reserve_frames_block_t *block = malloc(sizeof(reserve_frames_block_t));
    if (!block) {
        return 0;
    }
    memset(block, 0, sizeof(reserve_frames_block_t));
    block->nb_frames = nb_frames;
    block->total_bytes = 0;
    block->low_priority = true;
    for (int i = 0; i < nb_frames; i++) {
        block->total_bytes += slots[i].nb_bytes;
        block->is_congestion_controlled |= slots[i].is_congestion_controlled;
        block->low_priority &= slots[i].low_priority;   // it is higher priority as soon as a higher priority slot is present
    }
    block->frames = slots;
    int err = 0;
    if (block->is_congestion_controlled) {
        err = queue_enqueue(cnx->current_plugin->block_queue_cc, block);
    } else {
        err = queue_enqueue(cnx->current_plugin->block_queue_non_cc, block);
    }
    if (err) {
        free(block);
        POP_LOG_CTX(cnx);
        return 0;
    }
    LOG {
        char ftypes_str[250];
        size_t ftypes_ofs = 0;
        for (int i = 0; i < nb_frames; i++) {
            ftypes_ofs += snprintf(ftypes_str + ftypes_ofs, sizeof(ftypes_str) - ftypes_ofs, "%lu%s", block->frames[i].frame_type, i < nb_frames - 1 ? ", " : "");
        }
        ftypes_str[ftypes_ofs] = 0;
        LOG_EVENT(cnx, "PLUGINS", "RESERVE_FRAMES", "", "{\"nb_frames\": %d, \"total_bytes\": %lu, \"is_cc\": %d, \"frames\": [%s]}", block->nb_frames, block->total_bytes, block->is_congestion_controlled, ftypes_str);
    }
    POP_LOG_CTX(cnx);
    cnx->wake_now = 1;
    return block->total_bytes;
}

reserve_frame_slot_t* cancel_head_reservation(picoquic_cnx_t* cnx, uint8_t *nb_frames, int congestion_controlled) {
    if (!cnx->current_plugin) {
        printf("ERROR: cancel_head_reservation can only be called by pluglets with plugins!\n");
        return 0;
    }
    PUSH_LOG_CTX(cnx, "\"plugin\": \"%s\", \"protoop\": \"%s\", \"anchor\": \"%s\"",  cnx->current_plugin->name, cnx->current_protoop->name, pluglet_type_name(cnx->current_anchor));

    queue_t *block_queue = congestion_controlled ? cnx->current_plugin->block_queue_cc : cnx->current_plugin->block_queue_non_cc;
    reserve_frames_block_t *block = queue_dequeue(block_queue);
    if (block == NULL) {
        *nb_frames = 0;
        POP_LOG_CTX(cnx);
        return NULL;
    }
    *nb_frames = block->nb_frames;
    reserve_frame_slot_t *slots = block->frames;
    LOG {
        char ftypes_str[250];
        size_t ftypes_ofs = 0;
        for (int i = 0; i < *nb_frames; i++) {
            ftypes_ofs += snprintf(ftypes_str + ftypes_ofs, sizeof(ftypes_str) - ftypes_ofs, "%lu%s", block->frames[i].frame_type, i < *nb_frames - 1 ? ", " : "");
        }
        ftypes_str[ftypes_ofs] = 0;

        LOG_EVENT(cnx, "PLUGINS", "CANCEL_HEAD_RESERVATION", "", "{\"nb_frames\": %d, \"total_bytes\": %lu, \"is_cc\": %d, \"frames\": [%s]}", block->nb_frames, block->total_bytes, block->is_congestion_controlled, ftypes_str);
    }
    free(block);
    POP_LOG_CTX(cnx);
    return slots;
}
bool picoquic_has_booked_plugin_frames(picoquic_cnx_t *cnx)
{
    return (queue_peek(cnx->reserved_frames) != NULL || queue_peek(cnx->retry_frames) != NULL);
}

void quicctx_register_noparam_protoops(picoquic_cnx_t *cnx)
{
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_CONNECTION_STATE_CHANGED, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_CONGESTION_ALGORITHM_NOTIFY, &congestion_algorithm_notify);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_CALLBACK_FUNCTION, &callback_function);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PRINTF, &protoop_printf);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_SNPRINTF, &protoop_snprintf);

    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PACKET_WAS_LOST, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_STREAM_OPENED, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PLUGIN_STREAM_OPENED, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_STREAM_FLAGS_CHANGED, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_STREAM_CLOSED, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_FAST_RETRANSMIT, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_RETRANSMISSION_TIMEOUT, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_TAIL_LOSS_PROBE, &protoop_noop);

    /** \todo Those should be replaced by a pre/post of incoming_encrypted or incoming_segment */
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_RECEIVED_PACKET, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_BEFORE_SENDING_PACKET, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_RECEIVED_SEGMENT, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_BEFORE_SENDING_SEGMENT, &protoop_noop);

    /** \todo document these */
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_LOG_EVENT, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PUSH_LOG_CONTEXT, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_POP_LOG_CONTEXT, &protoop_noop);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_CONNECTION_ERROR, &connection_error);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_NOPARAM_UNKNOWN_TP_RECEIVED, &protoop_noop);
}