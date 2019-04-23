#include <picoquic_internal.h>
#include "../gf256/swif_symbol.c"
#include "../fec.h"
#include "../../helpers.h"
#include "../prng/tinymt32.c"
#include "../bpf.h"
#include "rlc_fec_scheme_gf256.h"
#define MIN(a, b) ((a < b) ? a : b)


/*******
Function that performs Gauss-Elimination and returns the Upper triangular matrix:
There are two options to do this in C.
1. Pass a matrix (a) as the parameter, and calculate and store the upperTriangular(Gauss-Eliminated Matrix) in it.
2. Use malloc and make the function of pointer type and return the pointer.
This program uses the first option.
********/
static __attribute__((always_inline)) void gaussElimination(picoquic_cnx_t *cnx, int n_eq, int n_unknowns, uint8_t **a, uint8_t *constant_terms[n_eq], uint8_t *x[n_eq], uint32_t symbol_size, uint8_t **mul, uint8_t *inv){
    int i,j,k;
    for(i=0;i<n_eq-1;i++){
        for(k=i+1;k<n_eq;k++){
            if(k > i){
                uint8_t mulnum = a[k][i];
                uint8_t muldenom = a[i][i];
                // term=a[k][i]/a[i][i]
                uint8_t term = gf256_mul(mulnum, inv[muldenom], mul);
                for(j=0;j<n_unknowns;j++){
                    // a[k][j] -= a[k][i]/a[i][i]*a[i][j]
//                    // i < m-1 AND m <= n, -> i < n-1
                      a[k][j] = gf256_sub(a[k][j], gf256_mul(term, a[i][j], mul));
                }
                // a[k][j] -= a[k][i]/a[i][i]*a[i][j] for the big, constant term
                symbol_sub_scaled(constant_terms[k], term, constant_terms[i], symbol_size, mul);
            }
        }
    }
    //Begin Back-substitution
    for(i=n_eq-1;i>=0;i--){
        my_memcpy(x[i], constant_terms[i], symbol_size);
        for(j=i+1;j<n_unknowns;j++){
//             x[i]=x[i]-a[i][j]*x[j];
            symbol_sub_scaled(x[i], a[i][j], x[j], symbol_size, mul);
        }
        // i < n_eq <= n_unknowns, so a[i][i] is small
        if (symbol_is_zero(x[i], symbol_size) || a[i][i] == 0) {
            // this solution is undetermined
            // TODO
            PROTOOP_PRINTF(cnx, "UNDETERMINED SOL\n");
        } else {
            // x[i] = x[i]/a[i][i]
            symbol_mul(x[i], inv[a[i][i]], symbol_size, mul);
        }
    }
}

static __attribute__((always_inline)) void get_coefs(picoquic_cnx_t *cnx, tinymt32_t *prng, uint32_t seed, int n, uint8_t *coefs) {
    tinymt32_init(prng, seed);
    int i;
    for (i = 0 ; i < n ; i++) {
        coefs[i] = (uint8_t) tinymt32_generate_uint32(prng);
        if (coefs[i] == 0)
            coefs[i] = 1;
    }
}

// TODO: handle when malloc returns NULL

/**
 * fec_block_t* fec_block = (fec_block_t *) cnx->protoop_inputv[0];
 *
 * Output: return code (int)
 */
protoop_arg_t fec_recover(picoquic_cnx_t *cnx)
{
    fec_block_t *fec_block = (fec_block_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    rlc_gf256_fec_scheme_t *fs = (rlc_gf256_fec_scheme_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    uint8_t **mul = fs->table_mul;
    PROTOOP_PRINTF(cnx, "TRYING TO RECOVER SYMBOLS WITH RLC256 FOR BLOCK %u !\n", fec_block->fec_block_number);
    if (fec_block->total_repair_symbols == 0 || fec_block->current_source_symbols == fec_block->total_source_symbols ||
        fec_block->current_source_symbols + fec_block->current_repair_symbols < fec_block->total_source_symbols) {
        PROTOOP_PRINTF(cnx, "NO RECOVERY TO DO\n");
        return 0;
    }
    tinymt32_t *prng = my_malloc(cnx, sizeof(tinymt32_t));
    prng->mat1 = 0x8f7011ee;
    prng->mat2 = 0xfc78ff1f;
    prng->tmat = 0x3793fdff;

    PROTOOP_PRINTF(cnx, "RECOVERING\n");
    int n_unknowns = fec_block->total_source_symbols - fec_block->current_source_symbols;
    int n_eq = MIN(n_unknowns, fec_block->current_repair_symbols);
    int i = 0;
    int j;
    uint8_t *coefs = my_malloc(cnx, fec_block->total_source_symbols*sizeof(uint8_t));//[fec_block->total_source_symbols];
    uint8_t **unknowns = my_malloc(cnx, (n_unknowns)*sizeof(uint8_t *));;//[n_unknowns];
    uint8_t **system_coefs = my_malloc(cnx, n_eq*sizeof(uint8_t *));//[n_eq][n_unknowns + 1];
    uint8_t **constant_terms = my_malloc(cnx, n_eq*sizeof(uint8_t *));


    if (!coefs || !unknowns || !system_coefs) {
        PROTOOP_PRINTF(cnx, "NOT ENOUGH MEM\n");
    }

    for (j = 0 ; j < n_eq ; j++) {
        system_coefs[j] = my_malloc(cnx, (n_unknowns) * sizeof(uint8_t));
        if (!system_coefs[j]) {
            PROTOOP_PRINTF(cnx, "NOT ENOUGH MEM\n");
        }
    }

    int idx = 0;
    int first_notnull_rs = -1;

    repair_symbol_t *rs;
    for_each_repair_symbol(fec_block, rs) {
        if (rs && first_notnull_rs == -1) {
            first_notnull_rs = idx;
            break;
        }
        idx++;
    }

    uint16_t max_length = fec_block->repair_symbols[first_notnull_rs]->data_length;

    for (j = 0 ; j < n_unknowns ; j++) {
        unknowns[j] = my_malloc(cnx, max_length);
        my_memset(unknowns[j], 0, max_length);
    }

    // building the system, equation by equation
    i = 0;
    for_each_repair_symbol(fec_block, rs) {
        if (rs && i < n_eq) {
            constant_terms[i] = my_malloc(cnx, max_length);
            my_memset(constant_terms[i], 0, max_length);
            my_memcpy(constant_terms[i], rs->data, rs->data_length);
            get_coefs(cnx, prng, (rs->repair_fec_payload_id.source_fpid.raw), fec_block->total_source_symbols, coefs);
            int current_unknown = 0;
            for (j = 0 ; j < fec_block->total_source_symbols ; j++) {
                if (fec_block->source_symbols[j]) {
                    // we add data_length to avoid overflowing on the source symbol. As we assume the source symbols are padded to 0, there is no harm in not adding the zeroes
                    symbol_sub_scaled(constant_terms[i], coefs[j], fec_block->source_symbols[j]->data, fec_block->source_symbols[j]->data_length, mul);
                } else if (current_unknown < n_unknowns) {
                    system_coefs[i][current_unknown++] = coefs[j];
                }
            }
            i++;
        }
    }

    PROTOOP_PRINTF(cnx, "BEFORE GAUSSIAN\n");
    // the system is built: let's recover it
    gaussElimination(cnx, n_eq, n_unknowns, system_coefs, constant_terms, unknowns, max_length, mul, fs->table_inv);
    PROTOOP_PRINTF(cnx, "AFTER GAUSSIAN\n");
    int current_unknown = 0;
    for (j = 0 ; j < fec_block->total_source_symbols ; j++) {
        if (!fec_block->source_symbols[j] && !symbol_is_zero(unknowns[current_unknown], max_length)) {
            // TODO: handle the case where source symbols could be 0

            source_symbol_t *ss = malloc_source_symbol(cnx, (source_fpid_t) (((fec_block->fec_block_number) << 8) + ((uint8_t)j)), max_length);
            if (!ss) {
                my_free(cnx, unknowns[current_unknown++]);
                continue;
            }
            my_memcpy(ss->data, unknowns[current_unknown], max_length);
            ss->data_length = max_length;
            fec_block->source_symbols[j] = ss;
            fec_block->current_source_symbols++;
            my_free(cnx, unknowns[current_unknown++]);
        }
    }

    // free the system
    for (i = 0 ; i < n_eq ; i++) {
        my_free(cnx, system_coefs[i]);
        my_free(cnx, constant_terms[i]);
    }
    my_free(cnx, prng);
    my_free(cnx, system_coefs);
    my_free(cnx, constant_terms);
    my_free(cnx, unknowns);
    my_free(cnx, coefs);

    return 0;
}
