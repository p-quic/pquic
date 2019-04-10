#include <picoquic_internal.h>
#include "../gf256/swif_symbol.c"
#include "../fec.h"
#include "../../helpers.h"
#include "../prng/tinymt32.c"



/*******
Function that performs Gauss-Elimination and returns the Upper triangular matrix:
There are two options to do this in C.
1. Pass a matrix (a) as the parameter, and calculate and store the upperTriangular(Gauss-Eliminated Matrix) in it.
2. Use malloc and make the function of pointer type and return the pointer.
This program uses the first option.
********/
static __attribute__((always_inline)) void gaussElimination(picoquic_cnx_t *cnx, int n_eq, int n_unknowns, uint8_t **a, uint8_t *constant_terms[n_eq], uint8_t *x[n_eq], uint32_t symbol_size){
    int i,j,k;
    for(i=0;i<n_eq-1;i++){
//        for(k=i+1;k<m;k++){
//            //If diagonal element(absolute value) is smaller than any of the terms below it
//            if(mpz_cmpabs(a[i][i], a[k][i]) < 0){
//                //Swap the rows
//                for(j=0;j<n;j++){
//                    mpz_swap(a[i][j], a[k][j]);
//                }
//            }
//        }
        for(k=i+1;k<n_eq;k++){
            uint8_t first = 1;
            if(k > i){
                uint8_t mulnum = a[k][i];
                uint8_t muldenom = a[i][i];
                // term=a[k][i]/a[i][i]
                uint8_t term = gf256_mul(mulnum, gf256_inv_table[muldenom]);
                for(j=0;j<n_unknowns;j++){
                    // a[k][j] -= a[k][i]/a[i][i]*a[i][j]
//                    // i < m-1 AND m <= n, -> i < n-1
                      a[k][j] = gf256_sub(a[k][j], gf256_mul(term, a[i][j]));
//                    if (first) {
//                        mpz_set(*mulnum, a[k][i]);
//                        mpz_set(*muldenom, a[i][i]);
//                        first = 0;
//                    }
//                    mpz_mul(*tmp, a[k][j], *muldenom);    // set a[k][j] at the common denominator
//                    mpz_mul(*tmp2, a[i][j], *mulnum);              // tmp2 = a[k][j]->denom * mulnum, but a[k][j]->denom == 1
//                    mpz_sub(a[k][j], *tmp, *tmp2);
                }
                // a[k][j] -= a[k][i]/a[i][i]*a[i][j] for the big, constant term
//                symbol_sub_scaled(constant_terms[k], term, constant_terms[i], symbol_size);
            }
        }
    }
    //Begin Back-substitution
    for(i=n_eq-1;i>=0;i--){
        my_memcpy(x[i], constant_terms[i], symbol_size);
        for(j=i+1;j<n_unknowns;j++){
//             x[i]=x[i]-a[i][j]*x[j];
            symbol_sub_scaled(x[i], a[i][j], x[j], symbol_size);
//            mpz_mul(*tmp, a[i][j], x[j]);
//            mpz_sub(x[i], x[i], *tmp);
        }
        // i < n_eq <= n_unknowns, so a[i][i] is small
        if (symbol_is_zero(x[i], symbol_size) || a[i][i] == 0) {
            // this solution is undetermined
            // TODO
            PROTOOP_PRINTF(cnx, "UNDETERMINED SOL\n");
        } else {
            // x[i] = x[i]/a[i][i]
            symbol_mul(x[i], gf256_inv_table[a[i][i]], symbol_size);
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
    PROTOOP_PRINTF(cnx, "TRYING TO RECOVER SYMBOLS WITH RLC FOR BLOCK %u !\n", fec_block->fec_block_number);
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
    int n_eq = fec_block->current_repair_symbols;
    int i = 0;
    int j;
    uint8_t *coefs = my_malloc(cnx, fec_block->total_source_symbols*sizeof(uint8_t));//[fec_block->total_source_symbols];
    uint8_t **knowns = my_malloc(cnx, fec_block->current_source_symbols*sizeof(uint8_t *));//[fec_block->current_source_symbols];
    uint8_t **unknowns = my_malloc(cnx, (n_unknowns)*sizeof(uint8_t *));;//[n_unknowns];
    uint8_t **system_coefs = my_malloc(cnx, n_eq*sizeof(uint8_t *));;//[n_eq][n_unknowns + 1];
    uint8_t **constant_terms = my_malloc(cnx, n_eq*sizeof(uint8_t *));


    if (!coefs || !knowns || !unknowns || !system_coefs) {
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
        if (first_notnull_rs == -1) {
            first_notnull_rs = idx;
            break;
        }
    }

    uint16_t max_length = fec_block->repair_symbols[first_notnull_rs]->data_length;

    for (j = 0 ; j < n_unknowns ; j++) {
        unknowns[j] = my_malloc(cnx, max_length);
        my_memset(unknowns[j], 0, max_length);
    }

    int current_known = 0;
    source_symbol_t *ss;
    for_each_source_symbol(fec_block, ss) {
            if (ss) {
                knowns[current_known] = my_malloc(cnx, max_length);
                my_memset(knowns[current_known], 0, max_length);
                my_memcpy(knowns[current_known++], ss->data, ss->data_length);
            }
        }

    // building the system, equation by equation
    i = 0;
    for_each_repair_symbol(fec_block, rs) {
        if (rs) {
            constant_terms[i] = my_malloc(cnx, max_length);
            my_memset(constant_terms[i], 0, max_length);
            my_memcpy(constant_terms[i], rs->data, rs->data_length);
            get_coefs(cnx, prng, (rs->repair_fec_payload_id.source_fpid.raw), fec_block->total_source_symbols, coefs);
            int current_unknown = 0;
            int current_known = 0;
            for (j = 0 ; j < fec_block->total_source_symbols ; j++) {
                if (fec_block->source_symbols[j]) {
                    symbol_sub_scaled(constant_terms[i], coefs[j], knowns[current_known++], max_length);
                } else if (current_unknown < n_unknowns) {
                    system_coefs[i][current_unknown++] = coefs[j];
                }
            }
            i++;
        }
        idx++;
    }

    for (j = 0 ; j < fec_block->current_source_symbols ; j++) {
        my_free(cnx, knowns[j]);
    }

    // the system is built: let's recover it
    gaussElimination(cnx, n_eq, n_unknowns, system_coefs, unknowns, constant_terms, max_length);
    int current_unknown = 0;
    for (j = 0 ; j < fec_block->total_source_symbols ; j++) {
        if (!fec_block->source_symbols[j] && !symbol_is_zero(unknowns[current_unknown], max_length)) {
            // TODO: handle the case where source symbols could be 0
            ss = malloc_source_symbol(cnx, (source_fpid_t) ((fec_block->fec_block_number << 8) + ((uint8_t)j)), max_length);
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
    my_free(cnx, knowns);
    my_free(cnx, coefs);

    return 0;
}
