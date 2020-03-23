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

#include "../picoquic/picoquic_internal.h"
#include "../picoquic/util.h"
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>
#include "../picoquic/memory.h"

/* Start with a series of test vectors to test that 
 * encoding and decoding are OK. 
 * Then, add fuzz testing.
 */

#define TRANSPORT_CID_NULL { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },0 }

#define TRANSPORT_PREFERRED_ADDRESS_NULL \
    { {0, 0, 0, 0}, 0, \
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 0, \
    TRANSPORT_CID_NULL, \
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}

static picoquic_tp_t transport_param_test1 = {
    TRANSPORT_CID_NULL, 30000, 1480, 0x400000, 0x200000, 0x200000, 0x100000, 10000, 10000, 3, 25, 0, TRANSPORT_PREFERRED_ADDRESS_NULL, 2, NULL, NULL
};

static picoquic_tp_t transport_param_test2 = {
    TRANSPORT_CID_NULL, 30000, 1480, 0x400000, 0x200000, 0x200000, 0x100000, 10000, 10000, 1, 25, 0, TRANSPORT_PREFERRED_ADDRESS_NULL, 2, NULL, NULL
};

static picoquic_tp_t transport_param_test3 = {
    TRANSPORT_CID_NULL, 30000, 0, 0x400000, 0x200000, 0x200000, 0x100000, 10000, 10000, 3, 25, 0, TRANSPORT_PREFERRED_ADDRESS_NULL, 2, NULL, NULL
};

static picoquic_tp_t transport_param_test4 = {
    TRANSPORT_CID_NULL, 30000, 1480, 0x400000, 0x200000, 0x200000, 0x100000, 10000, 10000, 3, 25, 1, TRANSPORT_PREFERRED_ADDRESS_NULL, 2, NULL, NULL
};

static picoquic_tp_t transport_param_test5 = {
    TRANSPORT_CID_NULL, 30000, 1480, 0x400000, 0x100000, 0x200000, 0x100000, 10000, 10000, 3, 25, 0, TRANSPORT_PREFERRED_ADDRESS_NULL, 2, NULL, NULL
};

static picoquic_tp_t transport_param_test6 = {
    TRANSPORT_CID_NULL, 30000, 1480, 0x400000, 0x200000, 0x100000, 0x100000, 10000, 10000, 3, 25, 0, TRANSPORT_PREFERRED_ADDRESS_NULL, 2, NULL, NULL
};

static picoquic_tp_t transport_param_test7 = {
    TRANSPORT_CID_NULL, 30000, 1480, 0x100000, 0x200000, 0x200000, 0x100000, 10000, 10000, 3, 25, 0, TRANSPORT_PREFERRED_ADDRESS_NULL, 2, NULL, NULL
};

static picoquic_tp_t transport_param_test8 = {
    TRANSPORT_CID_NULL, 1000, 1480, 0x100000, 0x200000, 0x200000, 0x100000, 10000, 10000, 3, 25, 0, TRANSPORT_PREFERRED_ADDRESS_NULL, 2, NULL, NULL
};

static uint8_t transport_param_reset_secret[PICOQUIC_RESET_SECRET_SIZE] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

static int transport_param_compare(picoquic_tp_t* param, picoquic_tp_t* ref) {
    int ret = 0;

    if (param->initial_max_stream_data_bidi_local != ref->initial_max_stream_data_bidi_local) {
        ret = -1;
    }
    else if (param->initial_max_stream_data_bidi_remote != ref->initial_max_stream_data_bidi_remote) {
        ret = -1;
    }
    else if (param->initial_max_stream_data_uni != ref->initial_max_stream_data_uni) {
        ret = -1;
    }
    else if (param->initial_max_data != ref->initial_max_data) {
        ret = -1;
    }
    else if (param->initial_max_streams_bidi != ref->initial_max_streams_bidi) {
        ret = -1;
    }
    else if (param->initial_max_streams_uni != ref->initial_max_streams_uni) {
        ret = -1;
    }
    else if (param->max_idle_timeout != ref->max_idle_timeout) {
        ret = -1;
    }
    else if (memcmp(&param->preferred_address, &ref->preferred_address, sizeof(picoquic_tp_preferred_address_t)) != 0) {
        ret = -1;
    }

    return ret;
}

int transport_param_one_test(int mode, uint32_t version, uint32_t proposed_version, picoquic_tp_t* param)
{
    int ret = 0;
    picoquic_quic_t quic_ctx;
    picoquic_cnx_t test_cnx;
    uint8_t buffer[256];
    size_t encoded, decoded;

    memset(&quic_ctx, 0, sizeof(quic_ctx));
    memset(&test_cnx, 0, sizeof(picoquic_cnx_t));
    test_cnx.quic = &quic_ctx;
    struct sockaddr_in addr;
    picoquic_create_path(&test_cnx, 0, (struct sockaddr *) &addr);

    /* initialize the connection object to the test parameters */
    memcpy(&test_cnx.local_parameters, param, sizeof(picoquic_tp_t));
    // test_cnx.version = version;
    test_cnx.version_index = picoquic_get_version_index(version);
    test_cnx.proposed_version = proposed_version;
    memcpy(test_cnx.path[0]->reset_secret, transport_param_reset_secret, PICOQUIC_RESET_SECRET_SIZE);

    register_protocol_operations(&test_cnx);

    ret = picoquic_prepare_transport_extensions(&test_cnx, mode, buffer, sizeof(buffer), &encoded);

    if (ret == 0) {
        ret = picoquic_receive_transport_extensions(&test_cnx, mode, buffer, encoded, &decoded);

        if (ret == 0 && transport_param_compare(&test_cnx.remote_parameters, param) != 0) {
            ret = -1;
        }
    }

    return ret;
}

int transport_param_test()
{
    int ret = 0;
    uint32_t version_default = PICOQUIC_INTEROP_VERSION;

    if (ret == 0) {
        ret = transport_param_one_test(0, version_default, version_default,
            &transport_param_test1);
    }

    if (ret == 0) {
        ret = transport_param_one_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test2);
    }

    if (ret == 0) {
        ret = transport_param_one_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test3);
    }

    if (ret == 0) {
        ret = transport_param_one_test(1, version_default, version_default,
            &transport_param_test4);
    }

    if (ret == 0) {
        ret = transport_param_one_test(1, version_default, 0x0A1A0A1A,
            &transport_param_test5);
    }

    if (ret == 0) {
        ret = transport_param_one_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test6);
    }

    if (ret == 0) {
        ret = transport_param_one_test(0, version_default, 0xBABABABA,
            &transport_param_test7);
    }

    if (ret == 0) {
        ret = transport_param_one_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test8);
    }

    return ret;
}

/*
 * Verify that we can properly log all the transport parameters.
 */
static char const* log_tp_test_file = "log_tp_test.txt";
static char const* log_tp_fuzz_file = "log_tp_fuzz_test.txt";

#ifdef _WINDOWS
#ifndef _WINDOWS64
static char const* log_tp_test_ref = "..\\picoquictest\\log_tp_test_ref.txt";
#else
static char const* log_tp_test_ref = "..\\..\\picoquictest\\log_tp_test_ref.txt";
#endif
#else
static char const* log_tp_test_ref = "picoquictest/log_tp_test_ref.txt";
#endif

void picoquic_log_transport_extension_content(FILE* F, int log_cnxid, uint64_t cnx_id_64,
    uint8_t * bytes, size_t bytes_max, int client_mode,
    uint32_t initial_version, uint32_t final_version);


typedef struct st_transport_param_stream_id_test_t {
    int extension_mode;
    int stream_id_type;
    int rank;
    int stream_id;
} transport_param_stream_id_test_t;

transport_param_stream_id_test_t const transport_param_stream_id_test_table[] = {
    { 0, PICOQUIC_STREAM_ID_BIDIR, 0, 0 },
    { 1, PICOQUIC_STREAM_ID_BIDIR, 0, 0 },
    { 0, PICOQUIC_STREAM_ID_UNIDIR, 0, 0 },
    { 1, PICOQUIC_STREAM_ID_UNIDIR, 0, 0 },
    { 0, PICOQUIC_STREAM_ID_BIDIR,  1, PICOQUIC_STREAM_ID_SERVER_INITIATED_BIDIR },
    { 1, PICOQUIC_STREAM_ID_BIDIR, 1, PICOQUIC_STREAM_ID_CLIENT_INITIATED_BIDIR + 4},
    { 0, PICOQUIC_STREAM_ID_UNIDIR, 1, PICOQUIC_STREAM_ID_SERVER_INITIATED_UNIDIR },
    { 1, PICOQUIC_STREAM_ID_UNIDIR, 1, PICOQUIC_STREAM_ID_CLIENT_INITIATED_UNIDIR },
    { 0, PICOQUIC_STREAM_ID_BIDIR, 65535, PICOQUIC_STREAM_ID_SERVER_MAX_INITIAL_BIDIR },
    { 1, PICOQUIC_STREAM_ID_BIDIR, 65535, PICOQUIC_STREAM_ID_CLIENT_MAX_INITIAL_BIDIR },
    { 0, PICOQUIC_STREAM_ID_UNIDIR, 65535, PICOQUIC_STREAM_ID_SERVER_MAX_INITIAL_UNIDIR },
    { 1, PICOQUIC_STREAM_ID_UNIDIR, 65535, PICOQUIC_STREAM_ID_CLIENT_MAX_INITIAL_UNIDIR },
    { 0, PICOQUIC_STREAM_ID_BIDIR, 5, 17},
    { 1, PICOQUIC_STREAM_ID_BIDIR, 5, 20 }
};

static size_t const nb_transport_param_stream_id_test_table =
    sizeof(transport_param_stream_id_test_table) / sizeof(transport_param_stream_id_test_t);

uint32_t picoquic_transport_param_to_stream_id(uint16_t rank, int client_mode, int stream_type);
uint16_t picoquic_prepare_transport_param_stream_id(uint32_t stream_id, int extension_mode, int stream_type);

int transport_param_stream_id_test() {
    int ret = 0;

    /* Decoding test */
    for (size_t i = 0; i < nb_transport_param_stream_id_test_table; i++) {
        uint16_t rank = picoquic_prepare_transport_param_stream_id(
            transport_param_stream_id_test_table[i].stream_id,
            transport_param_stream_id_test_table[i].extension_mode,
            transport_param_stream_id_test_table[i].stream_id_type);

        if (rank != transport_param_stream_id_test_table[i].rank) {
            DBG_PRINTF("TP Stream prepare ID [%d] fails. Rank= 0x%x, expected 0x%x, got 0x%x\n", i,
                transport_param_stream_id_test_table[i].stream_id,
                transport_param_stream_id_test_table[i].rank,
                rank);
            ret = -1;
        }
    }

    /* Encoding test */
    for (size_t i = 0; i < nb_transport_param_stream_id_test_table; i++) {
        uint32_t stream_id = picoquic_transport_param_to_stream_id(
                transport_param_stream_id_test_table[i].rank,
                transport_param_stream_id_test_table[i].extension_mode,
                transport_param_stream_id_test_table[i].stream_id_type);

        if (stream_id != transport_param_stream_id_test_table[i].stream_id) {
            DBG_PRINTF("TP Stream decode ID [%d] fails. Rank= 0x%x, expected 0x%x, got 0x%x\n", i,
                transport_param_stream_id_test_table[i].rank,
                transport_param_stream_id_test_table[i].stream_id,
                stream_id);
            ret = -1;
        }
    }

    return ret;
}