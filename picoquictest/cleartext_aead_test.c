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

#ifdef _WINDOWS
#include "../picoquic/wincompat.h"
#endif

#include "picotls.h"
#include "picotls/openssl.h"
#include "../picoquic/picoquic_internal.h"
#include "../picoquic/tls_api.h"
#include "../picoquic/util.h"
#include <string.h>
#include "picoquictest_internal.h"

static uint8_t const addr1[4] = { 10, 0, 0, 1 };
static uint8_t const addr2[4] = { 10, 0, 0, 2 };

void cleartext_aead_packet_init_header(picoquic_packet_header* ph,
    picoquic_connection_id_t cnx_id, uint32_t pn, uint32_t vn, picoquic_packet_type_enum ptype)
{
    memset(ph, 0, sizeof(picoquic_packet_header));
    ph->dest_cnx_id = cnx_id;
    ph->srce_cnx_id = picoquic_null_connection_id;
    ph->pn = pn;
    ph->pn64 = pn;
    ph->vn = vn;
    ph->ptype = ptype;
    ph->offset = 17;
    ph->pnmask = 0xFFFFFFFF00000000ull;
    ph->version_index = picoquic_get_version_index(ph->vn);
}

void cleartext_aead_init_packet(picoquic_packet_header* ph,
    uint8_t* cleartext, size_t target)
{
    size_t byte_index = 0;
    uint64_t seed = picoquic_val64_connection_id(ph->dest_cnx_id);

    seed ^= ph->pn;

    /* Serialize the header */
    cleartext[byte_index++] = 0x80 | ((uint8_t)ph->ptype);
    picoformat_32(&cleartext[byte_index], ph->vn);
    byte_index += 4;
    byte_index += picoquic_format_connection_id(&cleartext[byte_index], 1526 - byte_index, ph->dest_cnx_id);
    byte_index += picoquic_format_connection_id(&cleartext[byte_index], 1526 - byte_index, ph->srce_cnx_id);
    ph->pn_offset = (uint32_t)byte_index;
    picoformat_32(&cleartext[byte_index], ph->pn);
    byte_index += 4;
    /* Add some silly content */
    while (byte_index < target) {
        seed *= 101;
        cleartext[byte_index++] = (uint8_t)seed & 255;
    }
}

int cleartext_aead_test()
{
    int ret = 0;
    uint8_t clear_text[1536];
    uint8_t incoming[1536];
    uint32_t seqnum = 0xdeadbeef;
    size_t clear_length = 1200;
    size_t encoded_length;
    size_t decoded_length;
    picoquic_packet_header ph_init;
    struct sockaddr_in test_addr_c, test_addr_s;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_cnx_t* cnx_server = NULL;
    picoquic_quic_t* qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, NULL, NULL, NULL, 0, NULL);
    picoquic_quic_t* qserver = picoquic_create(8,
        PICOQUIC_TEST_SERVER_CERT, PICOQUIC_TEST_SERVER_KEY, PICOQUIC_TEST_CERT_STORE,
        "test", NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0, NULL);
    if (qclient == NULL || qserver == NULL) {
        DBG_PRINTF("%s", "Could not create Quic contexts.\n");
        ret = -1;
    }

    if (ret == 0) {
        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_addr_c, 0, 0, NULL, NULL, 1);
        if (cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create client connection context.\n");
            ret = -1;
        }
        register_protocol_operations(cnx_client);
    }

    if (ret == 0) {

        memset(&test_addr_s, 0, sizeof(struct sockaddr_in));
        test_addr_s.sin_family = AF_INET;
        memcpy(&test_addr_s.sin_addr, addr2, 4);
        test_addr_s.sin_port = 4433;

        cnx_server = picoquic_create_cnx(qserver, cnx_client->initial_cnxid, cnx_client->initial_cnxid,
            (struct sockaddr*)&test_addr_s, 0,
            cnx_client->proposed_version, NULL, NULL, 0);

        if (cnx_server == NULL) {
            DBG_PRINTF("%s", "Could not create server connection context.\n");
            ret = -1;
        } else if (picoquic_compare_connection_id(&cnx_client->initial_cnxid, &cnx_server->initial_cnxid) != 0) {
            DBG_PRINTF("Server Cnx-ID= %" PRIx64 ", differs from Client Cnx-ID = %" PRIx64 "\n",
                 picoquic_val64_connection_id(cnx_client->initial_cnxid),
                 picoquic_val64_connection_id(cnx_server->initial_cnxid));
            ret = -1;
        }
        register_protocol_operations(cnx_server);
    }

    /* Create a packet from client to server, encrypt, decrypt */
    if (ret == 0) {
        cleartext_aead_packet_init_header(&ph_init,
            cnx_client->initial_cnxid, seqnum, cnx_client->proposed_version,
            picoquic_packet_initial);
        cleartext_aead_init_packet(&ph_init, clear_text, clear_length);

        /* AEAD Encrypt, to the send buffer */
        memcpy(incoming, clear_text, ph_init.offset);
        encoded_length = picoquic_aead_encrypt_generic(incoming + ph_init.offset,
            clear_text + ph_init.offset, clear_length - ph_init.offset,
            seqnum, incoming, ph_init.offset, cnx_client->crypto_context[0].aead_encrypt);
        encoded_length += ph_init.offset;

        /* AEAD Decrypt */
        decoded_length = picoquic_aead_decrypt_generic(incoming + ph_init.offset,
            incoming + ph_init.offset, encoded_length - ph_init.offset, seqnum,
            incoming, ph_init.offset, cnx_server->crypto_context[0].aead_decrypt);
        decoded_length += ph_init.offset;

        if (decoded_length != clear_length) {
            DBG_PRINTF("Decoded length (%d) does not match clear lenth (%d).\n", (int)decoded_length, (int)clear_length);
            ret = -1;
        } else if (memcmp(incoming, clear_text, clear_length) != 0) {
            DBG_PRINTF("%s", "Decoded message not match clear length.\n");
            ret = 1;
        }
    }

    if (cnx_client != NULL) {
        picoquic_delete_cnx(cnx_client);
    }

    if (cnx_server != NULL) {
        picoquic_delete_cnx(cnx_server);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

static picoquic_connection_id_t clear_test_vector_cnx_id = { { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }, 8 };

static uint32_t clear_test_vector_vn = PICOQUIC_INTEROP_VERSION;
static uint8_t clear_test_vector_client_iv[12] = {
    0x86, 0x81, 0x35, 0x94, 0x10, 0xa7, 0x0b, 0xb9,
    0xc9, 0x2f, 0x04, 0x20
};
static uint8_t clear_test_vector_server_iv[12] = {
    0x5e, 0x5a, 0xe6, 0x51, 0xfd, 0x1e, 0x84, 0x95,
    0xaf, 0x13, 0x50, 0x8b
};

int cleartext_aead_vector_test_one(picoquic_connection_id_t test_id, uint8_t * client_iv, size_t client_iv_length,
    uint8_t * server_iv, size_t server_iv_length, char const * test_name)
{
    int ret = 0;
    struct sockaddr_in test_addr_c;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_quic_t* qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, NULL, NULL, NULL, 0, NULL);
    if (qclient == NULL) {
        DBG_PRINTF("%s: Could not create Quic context.\n", test_name);
        ret = -1;
    }

    if (ret == 0) {
        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        cnx_client = picoquic_create_cnx(qclient, test_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_addr_c, 0, clear_test_vector_vn, NULL, NULL, 1);

        if (cnx_client == NULL) {
            DBG_PRINTF("%s: Could not create client connection context.\n", test_name);
            ret = -1;
        } else {
            ret = picoquic_start_client_cnx(cnx_client);
        }
        register_protocol_operations(cnx_client);
    }

    if (ret == 0) {
        /* Compare client key to expected value */
        if (cnx_client->crypto_context[0].aead_encrypt == NULL)
        {
            DBG_PRINTF("%s: Could not create clear text AEAD encryption context.\n", test_name);
            ret = -1;
        } else if (cnx_client->crypto_context[0].aead_decrypt == NULL) {
            DBG_PRINTF("%s: Could not create clear text AEAD decryption context.\n", test_name);
            ret = -1;
        }
    }

    if (cnx_client != NULL) {
        picoquic_delete_cnx(cnx_client);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    return ret;
}

int cleartext_aead_vector_test()
{
    return cleartext_aead_vector_test_one(clear_test_vector_cnx_id, clear_test_vector_client_iv, sizeof(clear_test_vector_client_iv),
        clear_test_vector_server_iv, sizeof(clear_test_vector_server_iv), "aead_vector");
}

/*
 * Test the CTR primitives used for PN encryption
 */

int pn_ctr_test()
{
    int ret = 0;

    static const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    static const uint8_t iv[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    static const uint8_t expected[] = { 
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
    static const uint8_t packet_clear_pn[] = {
        0x5D,
        0xba, 0xba, 0xc0, 0x01,
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0x20, 0x3f, 0xbe, 0x2e, 0x32, 0x17, 0xfc, 0x5b, 
        0x88, 0x55
    };
    static const uint8_t packet_encrypted_pn[] = {
        0x5d,
        0x80, 0x6d, 0xbb, 0xb5,
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0x20, 0x3f, 0xbe, 0x2e, 0x32, 0x17, 0xfc, 0x5b,
        0x88, 0x55
    };

    uint8_t in_bytes[16];
    uint8_t out_bytes[16];
    uint8_t decoded[16];
    ptls_aead_algorithm_t* aead = &ptls_openssl_aes128gcm;
    ptls_cipher_context_t *hp_enc = ptls_cipher_new(aead->ctr_cipher, 1, key);

    /* test against expected value, from PTLS test */
    ptls_cipher_init(hp_enc, iv);
    memset(in_bytes, 0, 16);
    ptls_cipher_encrypt(hp_enc, out_bytes, in_bytes, sizeof(in_bytes));
    if (memcmp(out_bytes, expected, 16) != 0)
    {
        ret = -1;
    }

    /* test for various values of the PN length */

    for (size_t i = 1; ret == 0 && i <= 16; i *= 2)
    {
        memset(in_bytes, (int)i, i);
        ptls_cipher_init(hp_enc, iv);
        ptls_cipher_encrypt(hp_enc, out_bytes, in_bytes, i);
        for (size_t j = 0; j < i; j++)
        {
            if (in_bytes[j] != (out_bytes[j] ^ expected[j]))
            {
                ret = -1;
                break;
            }
        }
        ptls_cipher_init(hp_enc, iv);
        ptls_cipher_encrypt(hp_enc, decoded, out_bytes, i);
        if (memcmp(in_bytes, decoded, i) != 0)
        {
            ret = -1;
        }

        ptls_cipher_init(hp_enc, iv);
        ptls_cipher_encrypt(hp_enc, out_bytes, out_bytes, i);
        if (memcmp(in_bytes, out_bytes, i) != 0)
        {
            ret = -1;
        }
    }

    /* Test with the encrypted value from the packet */
    if (ret == 0)
    {
        ptls_cipher_init(hp_enc, packet_clear_pn + 5);
        ptls_cipher_encrypt(hp_enc, out_bytes, packet_clear_pn + 1, 4);
        if (memcmp(out_bytes, packet_encrypted_pn + 1, 4) != 0)
        {
            ret = -1;
        }
        else
        {
            ptls_cipher_init(hp_enc, packet_encrypted_pn + 5);
            ptls_cipher_encrypt(hp_enc, out_bytes, packet_encrypted_pn + 1, 4);
            if (memcmp(out_bytes, packet_clear_pn + 1, 4) != 0)
            {
                ret = -1;
            }
        }
    }

    // cleanup
    if (hp_enc != NULL)
    {
        ptls_cipher_free(hp_enc);
    }

    return ret;
}

/*
* Test that the generated encryption and decryption produce
* the same results.
*/

int test_one_hp_enc_pair(uint8_t * seqnum, size_t seqnum_len, void * hp_enc, void * hp_dec, uint8_t * sample)
{
    int ret = 0;
    uint8_t encoded[32];
    uint8_t decoded[32];

    ptls_cipher_init((ptls_cipher_context_t *)hp_enc, sample);
    ptls_cipher_encrypt((ptls_cipher_context_t *)hp_enc, encoded, seqnum, seqnum_len);

    ptls_cipher_init((ptls_cipher_context_t *)hp_dec, sample);
    ptls_cipher_encrypt((ptls_cipher_context_t *)hp_dec, decoded, encoded, seqnum_len);

    if (memcmp(seqnum, decoded, seqnum_len) != 0)
    {
        ret = -1;
    }

    return ret;
}

/*
 * Test that the key generated for cleartext PN encryption on
 * client and server produce the correct results.
 */

int cleartext_hp_enc_test()
{
    int ret = 0;
    struct sockaddr_in test_addr_c, test_addr_s;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_cnx_t* cnx_server = NULL;
    picoquic_quic_t* qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, NULL, NULL, NULL, 0, NULL);
    picoquic_quic_t* qserver = picoquic_create(8,
#ifdef _WINDOWS
#ifdef _WINDOWS64
        "..\\..\\certs\\cert.pem", "..\\..\\certs\\key.pem",
#else
        "..\\certs\\cert.pem", "..\\certs\\key.pem",
#endif
#else
        "certs/cert.pem", "certs/key.pem",
#endif
        NULL, "test", NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0, NULL);
    if (qclient == NULL || qserver == NULL) {
        DBG_PRINTF("%s", "Could not create Quic contexts.\n");
        ret = -1;
    }

    if (ret == 0) {
        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_addr_c, 0, 0, NULL, NULL, 1);
        if (cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create client connection context.\n");
            ret = -1;
        } else {
            ret = picoquic_start_client_cnx(cnx_client);
        }
        register_protocol_operations(cnx_client);
    }

    if (ret == 0) {

        memset(&test_addr_s, 0, sizeof(struct sockaddr_in));
        test_addr_s.sin_family = AF_INET;
        memcpy(&test_addr_s.sin_addr, addr2, 4);
        test_addr_s.sin_port = 4433;

        cnx_server = picoquic_create_cnx(qserver, cnx_client->initial_cnxid, cnx_client->path[0]->local_cnxid,
            (struct sockaddr*)&test_addr_s, 0,
            cnx_client->proposed_version, NULL, NULL, 0);

        if (cnx_server == NULL) {
            DBG_PRINTF("%s", "Could not create server connection context.\n");
            ret = -1;
        }
        register_protocol_operations(cnx_server);
    }

    /* Try to encrypt a sequence number */
    if (ret == 0) {
        uint8_t seq_num_1[4] = { 0xde, 0xad, 0xbe, 0xef };
        uint8_t sample_1[16] = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
        uint8_t seq_num_2[4] = { 0xba, 0xba, 0xc0, 0x0l };
        uint8_t sample_2[16] = {
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96};

        ret = test_one_hp_enc_pair(seq_num_1, 4, 
            cnx_client->crypto_context[0].hp_enc, cnx_server->crypto_context[0].hp_dec, sample_1);

        if (ret != 0) {
            DBG_PRINTF("%s", "Test of encoding PN sample 1 failed.\n");
        } else {
            ret = test_one_hp_enc_pair(seq_num_2, 4, cnx_server->crypto_context[0].hp_enc,
                cnx_client->crypto_context[0].hp_dec, sample_2);
            if (ret != 0) {
                DBG_PRINTF("%s", "Test of encoding PN sample 2 failed.\n");
            }
        }
    }

    if (cnx_client != NULL) {
        picoquic_delete_cnx(cnx_client);
    }

    if (cnx_server != NULL) {
        picoquic_delete_cnx(cnx_server);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}