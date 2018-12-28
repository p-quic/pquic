/* mini-gmp, a minimalistic implementation of a GNU GMP subset.

   Contributed to the GNU project by Niels Möller

Copyright 1991-1997, 1999-2016 Free Software Foundation, Inc.

This file is part of the GNU MP Library.

The GNU MP Library is free software; you can redistribute it and/or modify
it under the terms of either:

  * the GNU Lesser General Public License as published by the Free
    Software Foundation; either version 3 of the License, or (at your
    option) any later version.

or

  * the GNU General Public License as published by the Free Software
    Foundation; either version 2 of the License, or (at your option) any
    later version.

or both in parallel, as here.

The GNU MP Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received copies of the GNU General Public License and the
GNU Lesser General Public License along with the GNU MP Library.  If not,
see https://www.gnu.org/licenses/.  */

/* NOTE: All functions in this file which are not declared in
   mini-gmp.h are internal, and are not intended to be compatible
   neither with GMP nor with future versions of mini-gmp. */

/* Much of the material copied from GMP files, including: gmp-impl.h,
   longlong.h, mpn/generic/add_n.c, mpn/generic/addmul_1.c,
   mpn/generic/lshift.c, mpn/generic/mul_1.c,
   mpn/generic/mul_basecase.c, mpn/generic/rshift.c,
   mpn/generic/sbpi1_div_qr.c, mpn/generic/sub_n.c,
   mpn/generic/submul_1.c. */


#include "memory.h"
#include "memcpy.h"
#include "../../helpers.h"

#include <picoquic.h>

#define MALLOC_FRAGMENTATION_AVOIDANCE 20
#define size_t uint64_t
#define mpn_invert_limb(x) mpn_invert_3by2 ((x), 0)

typedef unsigned long mp_limb_t;
typedef long mp_size_t;
typedef unsigned long mp_bitcnt_t;

typedef mp_limb_t *mp_ptr;
typedef const mp_limb_t *mp_srcptr;

typedef struct {
    picoquic_cnx_t *cnx;
    int _mp_alloc;        /* Number of *limbs* allocated and pointed
				   to by the _mp_d field.  */
    int _mp_size;            /* abs(_mp_size) is the number of limbs the
				   last field points to.  If _mp_size is
				   negative this is a negative number.  */
    mp_limb_t *_mp_d;        /* Pointer to the limbs.  */
} __mpz_struct;

typedef __mpz_struct mpz_t[1];

typedef __mpz_struct *mpz_ptr;
typedef const __mpz_struct *mpz_srcptr;

// TODO michelfra: change this to a real assert ?
#define assert(ignore)((void) 0)
#define CHAR_BIT 8
/* Macros */
#define GMP_LIMB_BITS (sizeof(mp_limb_t) * CHAR_BIT)

#define GMP_LIMB_MAX (~ (mp_limb_t) 0)
#define GMP_LIMB_HIGHBIT ((mp_limb_t) 1 << (GMP_LIMB_BITS - 1))

#define GMP_HLIMB_BIT ((mp_limb_t) 1 << (GMP_LIMB_BITS / 2))
#define GMP_LLIMB_MASK (GMP_HLIMB_BIT - 1)

#define GMP_ULONG_BITS (sizeof(unsigned long) * CHAR_BIT)
#define GMP_ULONG_HIGHBIT ((unsigned long) 1 << (GMP_ULONG_BITS - 1))

#define GMP_ABS(x) ((x) >= 0 ? (x) : -(x))
#define GMP_NEG_CAST(T, x) (-((T)((x) + 1) - 1))

#define GMP_MIN(a, b) ((a) < (b) ? (a) : (b))
#define GMP_MAX(a, b) ((a) > (b) ? (a) : (b))

#define GMP_CMP(a, b) (((a) > (b)) - ((a) < (b)))

#define gmp_assert_nocarry(x) do { \
    mp_limb_t __cy = (x);       \
    assert (__cy == 0);           \
  } while (0)

#define gmp_clz(count, x) do {                        \
    mp_limb_t __clz_x = (x);                        \
    unsigned __clz_c;                            \
    for (__clz_c = 0;                            \
     (__clz_x & ((mp_limb_t) 0xff << (GMP_LIMB_BITS - 8))) == 0;    \
     __clz_c += 8)                            \
      __clz_x <<= 8;                            \
    for (; (__clz_x & GMP_LIMB_HIGHBIT) == 0; __clz_c++)        \
      __clz_x <<= 1;                            \
    (count) = __clz_c;                            \
  } while (0)

#define gmp_ctz(count, x) do {                        \
    mp_limb_t __ctz_x = (x);                        \
    unsigned __ctz_c = 0;                        \
    gmp_clz (__ctz_c, __ctz_x & - __ctz_x);                \
    (count) = GMP_LIMB_BITS - 1 - __ctz_c;                \
  } while (0)

#define gmp_add_ssaaaa(sh, sl, ah, al, bh, bl) \
  do {                                    \
    mp_limb_t __x;                            \
    __x = (al) + (bl);                            \
    (sh) = (ah) + (bh) + (__x < (al));                    \
    (sl) = __x;                                \
  } while (0)

#define gmp_sub_ddmmss(sh, sl, ah, al, bh, bl) \
  do {                                    \
    mp_limb_t __x;                            \
    __x = (al) - (bl);                            \
    (sh) = (ah) - (bh) - ((al) < (bl));                    \
    (sl) = __x;                                \
  } while (0)

#define gmp_umul_ppmm(w1, w0, u, v)                    \
  do {                                    \
    mp_limb_t __x0, __x1, __x2, __x3;                    \
    unsigned __ul, __vl, __uh, __vh;                    \
    mp_limb_t __u = (u), __v = (v);                    \
                                    \
    __ul = __u & GMP_LLIMB_MASK;                    \
    __uh = __u >> (GMP_LIMB_BITS / 2);                    \
    __vl = __v & GMP_LLIMB_MASK;                    \
    __vh = __v >> (GMP_LIMB_BITS / 2);                    \
                                    \
    __x0 = (mp_limb_t) __ul * __vl;                    \
    __x1 = (mp_limb_t) __ul * __vh;                    \
    __x2 = (mp_limb_t) __uh * __vl;                    \
    __x3 = (mp_limb_t) __uh * __vh;                    \
                                    \
    __x1 += __x0 >> (GMP_LIMB_BITS / 2);/* this can't give carry */    \
    __x1 += __x2;        /* but this indeed can */        \
    if (__x1 < __x2)        /* did we get it? */            \
      __x3 += GMP_HLIMB_BIT;    /* yes, add it in the proper pos. */    \
                                    \
    (w1) = __x3 + (__x1 >> (GMP_LIMB_BITS / 2));            \
    (w0) = (__x1 << (GMP_LIMB_BITS / 2)) + (__x0 & GMP_LLIMB_MASK);    \
  } while (0)

#define gmp_udiv_qrnnd_preinv(q, r, nh, nl, d, di)            \
  do {                                    \
    mp_limb_t _qh, _ql, _r, _mask;                    \
    gmp_umul_ppmm (_qh, _ql, (nh), (di));                \
    gmp_add_ssaaaa (_qh, _ql, _qh, _ql, (nh) + 1, (nl));        \
    _r = (nl) - _qh * (d);                        \
    _mask = -(mp_limb_t) (_r > _ql); /* both > and >= are OK */        \
    _qh += _mask;                            \
    _r += _mask & (d);                            \
    if (_r >= (d))                            \
      {                                    \
    _r -= (d);                            \
    _qh++;                                \
      }                                    \
                                    \
    (r) = _r;                                \
    (q) = _qh;                                \
  } while (0)

#define gmp_udiv_qr_3by2(q, r1, r0, n2, n1, n0, d1, d0, dinv)        \
  do {                                    \
    mp_limb_t _q0, _t1, _t0, _mask;                    \
    gmp_umul_ppmm ((q), _q0, (n2), (dinv));                \
    gmp_add_ssaaaa ((q), _q0, (q), _q0, (n2), (n1));            \
                                    \
    /* Compute the two most significant limbs of n - q'd */        \
    (r1) = (n1) - (d1) * (q);                        \
    gmp_sub_ddmmss ((r1), (r0), (r1), (n0), (d1), (d0));        \
    gmp_umul_ppmm (_t1, _t0, (d0), (q));                \
    gmp_sub_ddmmss ((r1), (r0), (r1), (r0), _t1, _t0);            \
    (q)++;                                \
                                    \
    /* Conditionally adjust q and the remainders */            \
    _mask = - (mp_limb_t) ((r1) >= _q0);                \
    (q) += _mask;                            \
    gmp_add_ssaaaa ((r1), (r0), (r1), (r0), _mask & (d1), _mask & (d0)); \
    if ((r1) >= (d1))                            \
      {                                    \
    if ((r1) > (d1) || (r0) >= (d0))                \
      {                                \
        (q)++;                            \
        gmp_sub_ddmmss ((r1), (r0), (r1), (r0), (d1), (d0));    \
      }                                \
      }                                    \
  } while (0)

#define MP_SIZE_T_SWAP(x, y)                        \
  do {                                    \
    mp_size_t __mp_size_t_swap__tmp = (x);                \
    (x) = (y);                                \
    (y) = __mp_size_t_swap__tmp;                    \
  } while (0)
#define MP_PTR_SWAP(x, y)                        \
  do {                                    \
    mp_ptr __mp_ptr_swap__tmp = (x);                    \
    (x) = (y);                                \
    (y) = __mp_ptr_swap__tmp;                        \
  } while (0)
#define MPZ_SRCPTR_SWAP(x, y)                        \
  do {                                    \
    mpz_srcptr __mpz_srcptr_swap__tmp = (x);                \
    (x) = (y);                                \
    (y) = __mpz_srcptr_swap__tmp;                    \
  } while (0)

//const int mp_bits_per_limb = GMP_LIMB_BITS;


/* Memory allocation and other helper functions. */
static __attribute__((always_inline)) void
gmp_die(const char *msg) {
    // TODO: print with protoop
    //fprintf (stderr, "%s\n", msg);
    //abort();
}

static __attribute__((always_inline)) void *
gmp_default_alloc(picoquic_cnx_t *cnx, size_t size) {
    void *p;

    assert (size > 0);

    p = my_malloc(cnx, size);
    if (!p)
        gmp_die("gmp_default_alloc: Virtual memory exhausted.");

    return p;
}

static __attribute__((always_inline)) void *
gmp_allocate_func(picoquic_cnx_t *cnx, size_t size) {
    void *p;

    assert (size > 0);

    p = my_malloc(cnx, size + MALLOC_FRAGMENTATION_AVOIDANCE);
    if (!p)
        gmp_die("gmp_default_alloc: Virtual memory exhausted.");

    return p;
}

static __attribute__((always_inline)) void *
gmp_default_realloc(picoquic_cnx_t *cnx, void *old, size_t old_size, size_t new_size) {
    void *p;

    p = my_realloc(cnx, old, new_size + MALLOC_FRAGMENTATION_AVOIDANCE);

    if (!p)
        gmp_die("gmp_default_realloc: Virtual memory exhausted.");

    return p;
}

static __attribute__((always_inline)) void *
gmp_reallocate_func(picoquic_cnx_t *cnx, void *old, size_t old_size, size_t new_size) {
    void *p;

    p = my_realloc(cnx, old, new_size);

    if (!p){
        gmp_die("gmp_default_realloc: Virtual memory exhausted.");
//        PROTOOP_PRINTF(cnx, "gmp_default_realloc: Virtual memory exhausted.\n");
    }

    return p;
}

static __attribute__((always_inline)) void
gmp_default_free(picoquic_cnx_t *cnx, void *p, size_t size) {
    my_free(cnx, p);
}

static __attribute__((always_inline)) void
gmp_free_func(picoquic_cnx_t *cnx, void *p, size_t size) {
    my_free(cnx, p);
}

//static void * (*gmp_allocate_func) (picoquic_cnx_t *, size_t) = gmp_default_alloc;
//static void * (*gmp_reallocate_func) (picoquic_cnx_t *, void *, size_t, size_t) = gmp_default_realloc;
//static void (*gmp_free_func) (picoquic_cnx_t *, void *, size_t) = gmp_default_free;;

//void
//mp_get_memory_functions (void *(**alloc_func) (picoquic_cnx_t *, size_t),
//			 void *(**realloc_func) (picoquic_cnx_t *, void *, size_t, size_t),
//			 void (**free_func) (picoquic_cnx_t *, void *, size_t))
//{
//  if (alloc_func)
//    *alloc_func = gmp_allocate_func;
//
//  if (realloc_func)
//    *realloc_func = gmp_reallocate_func;
//
//  if (free_func)
//    *free_func = gmp_free_func;
//}

//void
//mp_set_memory_functions (void *(*alloc_func) (picoquic_cnx_t *, size_t),
//			 void *(*realloc_func) (picoquic_cnx_t *, void *, size_t, size_t),
//			 void (*free_func) (picoquic_cnx_t *, void *, size_t))
//{
//  if (!alloc_func)
//    alloc_func = gmp_default_alloc;
//  if (!realloc_func)
//    realloc_func = gmp_default_realloc;
//  if (!free_func)
//    free_func = gmp_default_free;
//
//  gmp_allocate_func = alloc_func;
//  gmp_reallocate_func = realloc_func;
//  gmp_free_func = free_func;
//}

#define gmp_xalloc(cnx, size) (gmp_allocate_func((cnx), (size)))
#define gmp_free(cnx, p) (gmp_free_func((cnx), (p), 0))

static __attribute__((always_inline)) mp_ptr
gmp_xalloc_limbs(picoquic_cnx_t *cnx, mp_size_t size) {
    return (mp_ptr) gmp_allocate_func (cnx, size * sizeof(mp_limb_t));
}

static __attribute__((always_inline)) mp_ptr
gmp_xrealloc_limbs(picoquic_cnx_t *cnx, mp_ptr old, mp_size_t size) {
    assert (size > 0);
    return (mp_ptr) gmp_reallocate_func(cnx, old, 0, size * sizeof(mp_limb_t));
}


/* MPN interface */;

static __attribute__((always_inline)) void
mpn_copyi(mp_ptr d, mp_srcptr s, mp_size_t n) {
    mp_size_t i;
    for (i = 0; i < n; i++)
        d[i] = s[i];
}

static __attribute__((always_inline)) void
mpn_copyd(mp_ptr d, mp_srcptr s, mp_size_t n) {
    while (--n >= 0)
        d[n] = s[n];
}

static __attribute__((always_inline)) int
mpn_cmp(mp_srcptr ap, mp_srcptr bp, mp_size_t n) {
    while (--n >= 0) {
        if (ap[n] != bp[n])
            return ap[n] > bp[n] ? 1 : -1;
    }
    return 0;
}

static __attribute__((always_inline)) int
mpn_cmp4(mp_srcptr ap, mp_size_t an, mp_srcptr bp, mp_size_t bn) {
    if (an != bn)
        return an < bn ? -1 : 1;
    else
        return mpn_cmp(ap, bp, an);
}

static __attribute__((always_inline)) mp_size_t
mpn_normalized_size(mp_srcptr xp, mp_size_t n) {
    while (n > 0 && xp[n - 1] == 0)
        --n;
    return n;
}

static __attribute__((always_inline)) int
mpn_zero_p(mp_srcptr rp, mp_size_t n) {
    return mpn_normalized_size(rp, n) == 0;
}

static __attribute__((always_inline)) mp_limb_t
mpn_add_1(mp_ptr rp, mp_srcptr ap, mp_size_t n, mp_limb_t b) {
    mp_size_t i;

    assert (n > 0);
    i = 0;
    do {
        mp_limb_t r = ap[i] + b;
        /* Carry out */
        b = (r < b);
        rp[i] = r;
    } while (++i < n);

    return b;
}

static __attribute__((always_inline)) mp_limb_t
mpn_add_n(picoquic_cnx_t *cnx, mp_ptr rp, mp_srcptr ap, mp_srcptr bp, mp_size_t n) {
    mp_size_t i;
    mp_limb_t cy;
    mp_limb_t *limbs = gmp_allocate_func(cnx, 4*sizeof(mp_limb_t));
    #define a limbs[0]
    #define b limbs[1]
    #define r limbs[2]

    for (i = 0, cy = 0; i < n; i++) {
//        mp_limb_t a, b, r;
        a = ap[i];
        b = bp[i];
        r = a + cy;
        cy = (r < cy);
        r += b;
        cy += (r < b);
        rp[i] = r;
    }
    #undef a
    #undef b
    #undef r
    gmp_free(cnx, limbs);
    return cy;
}

static __attribute__((always_inline))  mp_limb_t
mpn_add(picoquic_cnx_t *cnx, mp_ptr rp, mp_srcptr ap, mp_size_t an, mp_srcptr bp, mp_size_t bn) {
    mp_limb_t cy;

    assert (an >= bn);

    cy = mpn_add_n(cnx, rp, ap, bp, bn);
    if (an > bn)
        cy = mpn_add_1(rp + bn, ap + bn, an - bn, cy);
    return cy;
}

static __attribute__((always_inline)) mp_limb_t
mpn_sub_1(mp_ptr rp, mp_srcptr ap, mp_size_t n, mp_limb_t b) {
    mp_size_t i;

    assert (n > 0);

    i = 0;
    do {
        mp_limb_t a = ap[i];
        /* Carry out */
        mp_limb_t cy = a < b;
        rp[i] = a - b;
        b = cy;
    } while (++i < n);

    return b;
}

static __attribute__((always_inline)) mp_limb_t
mpn_sub_n(mp_ptr rp, mp_srcptr ap, mp_srcptr bp, mp_size_t n) {
    mp_size_t i;
    mp_limb_t cy;

    for (i = 0, cy = 0; i < n; i++) {
        mp_limb_t a, b;
        a = ap[i];
        b = bp[i];
        b += cy;
        cy = (b < cy);
        cy += (a < b);
        rp[i] = a - b;
    }
    return cy;
}

static __attribute__((always_inline)) mp_limb_t
mpn_sub(mp_ptr rp, mp_srcptr ap, mp_size_t an, mp_srcptr bp, mp_size_t bn) {
    mp_limb_t cy;

    assert (an >= bn);

    cy = mpn_sub_n(rp, ap, bp, bn);
    if (an > bn)
        cy = mpn_sub_1(rp + bn, ap + bn, an - bn, cy);
    return cy;
}

static __attribute__((always_inline)) mp_limb_t
mpn_mul_1(mp_ptr rp, mp_srcptr up, mp_size_t n, mp_limb_t vl) {
    mp_limb_t ul, cl, hpl, lpl;

    assert (n >= 1);

    cl = 0;
    do {
        ul = *up++;
        gmp_umul_ppmm (hpl, lpl, ul, vl);

        lpl += cl;
        cl = (lpl < cl) + hpl;

        *rp++ = lpl;
    } while (--n != 0);

    return cl;
}

static __attribute__((always_inline)) mp_limb_t
mpn_addmul_1(mp_ptr rp, mp_srcptr up, mp_size_t n, mp_limb_t vl) {
    mp_limb_t ul, cl, hpl, lpl, rl;

    assert (n >= 1);

    cl = 0;
    do {
        ul = *up++;
        gmp_umul_ppmm (hpl, lpl, ul, vl);

        lpl += cl;
        cl = (lpl < cl) + hpl;

        rl = *rp;
        lpl = rl + lpl;
        cl += lpl < rl;
        *rp++ = lpl;
    } while (--n != 0);

    return cl;
}

static __attribute__((always_inline)) mp_limb_t
mpn_submul_1(mp_ptr rp, mp_srcptr up, mp_size_t n, mp_limb_t vl) {
    mp_limb_t ul, cl, hpl, lpl, rl;

    assert (n >= 1);

    cl = 0;
    do {
        ul = *up++;
        gmp_umul_ppmm (hpl, lpl, ul, vl);

        lpl += cl;
        cl = (lpl < cl) + hpl;

        rl = *rp;
        lpl = rl - lpl;
        cl += lpl > rl;
        *rp++ = lpl;
    } while (--n != 0);

    return cl;
}

static __attribute__((always_inline)) mp_limb_t
mpn_mul(mp_ptr rp, mp_srcptr up, mp_size_t un, mp_srcptr vp, mp_size_t vn) {
    assert (un >= vn);
    assert (vn >= 1);

    /* We first multiply by the low order limb. This result can be
       stored, not added, to rp. We also avoid a loop for zeroing this
       way. */

    rp[un] = mpn_mul_1(rp, up, un, vp[0]);

    /* Now accumulate the product of up[] and the next higher limb from
       vp[]. */

    while (--vn >= 1) {
        rp += 1, vp += 1;
        rp[un] = mpn_addmul_1(rp, up, un, vp[0]);
    }
    return rp[un];
}


static __attribute__((always_inline)) mp_limb_t
mpn_lshift(mp_ptr rp, mp_srcptr up, mp_size_t n, unsigned int cnt) {
    mp_limb_t high_limb, low_limb;
    unsigned int tnc;
    mp_limb_t retval;

    assert (n >= 1);
    assert (cnt >= 1);
    assert (cnt < GMP_LIMB_BITS);

    up += n;
    rp += n;

    tnc = GMP_LIMB_BITS - cnt;
    low_limb = *--up;
    retval = low_limb >> tnc;
    high_limb = (low_limb << cnt);

    while (--n != 0) {
        low_limb = *--up;
        *--rp = high_limb | (low_limb >> tnc);
        high_limb = (low_limb << cnt);
    }
    *--rp = high_limb;

    return retval;
}

static __attribute__((always_inline)) mp_limb_t
mpn_rshift(mp_ptr rp, mp_srcptr up, mp_size_t n, unsigned int cnt) {
    mp_limb_t high_limb, low_limb;
    unsigned int tnc;
    mp_limb_t retval;

    assert (n >= 1);
    assert (cnt >= 1);
    assert (cnt < GMP_LIMB_BITS);

    tnc = GMP_LIMB_BITS - cnt;
    high_limb = *up++;
    retval = (high_limb << tnc);
    low_limb = high_limb >> cnt;

    while (--n != 0) {
        high_limb = *up++;
        *rp++ = low_limb | (high_limb << tnc);
        low_limb = high_limb >> cnt;
    }
    *rp = low_limb;

    return retval;
}

static __attribute__((always_inline))  mp_bitcnt_t
mpn_common_scan(mp_limb_t limb, mp_size_t i, mp_srcptr up, mp_size_t un,
                mp_limb_t ux) {
    unsigned cnt;

    assert (ux == 0 || ux == GMP_LIMB_MAX);
    assert (0 <= i && i <= un);

    while (limb == 0) {
        i++;
        if (i == un)
            return (ux == 0 ? ~(mp_bitcnt_t) 0 : un * GMP_LIMB_BITS);
        limb = ux ^ up[i];
    }
    gmp_ctz (cnt, limb);
    return (mp_bitcnt_t) i * GMP_LIMB_BITS + cnt;
}

static __attribute__((always_inline)) void
mpn_com(mp_ptr rp, mp_srcptr up, mp_size_t n) {
    while (--n >= 0)
        *rp++ = ~*up++;
}

static __attribute__((always_inline)) mp_limb_t
mpn_neg(mp_ptr rp, mp_srcptr up, mp_size_t n) {
    while (*up == 0) {
        *rp = 0;
        if (!--n)
            return 0;
        ++up;
        ++rp;
    }
    *rp = -*up;
    mpn_com(++rp, ++up, --n);
    return 1;
}


/* MPN division interface. */

/* The 3/2 inverse is defined as

     m = floor( (B^3-1) / (B u1 + u0)) - B
*/
static __attribute__((always_inline)) mp_limb_t
mpn_invert_3by2(mp_limb_t u1, mp_limb_t u0) {
    mp_limb_t r, p, m, ql;
    unsigned ul, uh, qh;

    assert (u1 >= GMP_LIMB_HIGHBIT);

    /* For notation, let b denote the half-limb base, so that B = b^2.
       Split u1 = b uh + ul. */
    ul = u1 & GMP_LLIMB_MASK;
    uh = u1 >> (GMP_LIMB_BITS / 2);

    /* Approximation of the high half of quotient. Differs from the 2/1
       inverse of the half limb uh, since we have already subtracted
       u0. */
    qh = ~u1 / uh;

    /* Adjust to get a half-limb 3/2 inverse, i.e., we want

       qh' = floor( (b^3 - 1) / u) - b = floor ((b^3 - b u - 1) / u
           = floor( (b (~u) + b-1) / u),

       and the remainder

       r = b (~u) + b-1 - qh (b uh + ul)
         = b (~u - qh uh) + b-1 - qh ul

       Subtraction of qh ul may underflow, which implies adjustments.
       But by normalization, 2 u >= B > qh ul, so we need to adjust by
       at most 2.
    */

    r = ((~u1 - (mp_limb_t) qh * uh) << (GMP_LIMB_BITS / 2)) | GMP_LLIMB_MASK;

    p = (mp_limb_t) qh * ul;
    /* Adjustment steps taken from udiv_qrnnd_c */
    if (r < p) {
        qh--;
        r += u1;
        if (r >= u1) /* i.e. we didn't get carry when adding to r */
            if (r < p) {
                qh--;
                r += u1;
            }
    }
    r -= p;

    /* Low half of the quotient is

         ql = floor ( (b r + b-1) / u1).

       This is a 3/2 division (on half-limbs), for which qh is a
       suitable inverse. */

    p = (r >> (GMP_LIMB_BITS / 2)) * qh + r;
    /* Unlike full-limb 3/2, we can add 1 without overflow. For this to
       work, it is essential that ql is a full mp_limb_t. */
    ql = (p >> (GMP_LIMB_BITS / 2)) + 1;

    /* By the 3/2 trick, we don't need the high half limb. */
    r = (r << (GMP_LIMB_BITS / 2)) + GMP_LLIMB_MASK - ql * u1;

    if (r >= (p << (GMP_LIMB_BITS / 2))) {
        ql--;
        r += u1;
    }
    m = ((mp_limb_t) qh << (GMP_LIMB_BITS / 2)) + ql;
    if (r >= u1) {
        m++;
        r -= u1;
    }

    /* Now m is the 2/1 invers of u1. If u0 > 0, adjust it to become a
       3/2 inverse. */
    if (u0 > 0) {
        mp_limb_t th, tl;
        r = ~r;
        r += u0;
        if (r < u0) {
            m--;
            if (r >= u1) {
                m--;
                r -= u1;
            }
            r -= u1;
        }
        gmp_umul_ppmm (th, tl, u0, m);
        r += th;
        if (r < th) {
            m--;
            m -= ((r > u1) | ((r == u1) & (tl > u0)));
        }
    }

    return m;
}

struct gmp_div_inverse {
    /* Normalization shift count. */
    unsigned shift;
    /* Normalized divisor (d0 unused for mpn_div_qr_1) */
    mp_limb_t d1, d0;
    /* Inverse, for 2/1 or 3/2. */
    mp_limb_t di;
};

static __attribute__((always_inline)) void
mpn_div_qr_1_invert(struct gmp_div_inverse *inv, mp_limb_t d) {
    unsigned shift;

    assert (d > 0);
    gmp_clz (shift, d);
    inv->shift = shift;
    inv->d1 = d << shift;
    inv->di = mpn_invert_limb (inv->d1);
}

static __attribute__((always_inline)) void
mpn_div_qr_2_invert(struct gmp_div_inverse *inv,
                    mp_limb_t d1, mp_limb_t d0) {
    unsigned shift;

    assert (d1 > 0);
    gmp_clz (shift, d1);
    inv->shift = shift;
    if (shift > 0) {
        d1 = (d1 << shift) | (d0 >> (GMP_LIMB_BITS - shift));
        d0 <<= shift;
    }
    inv->d1 = d1;
    inv->d0 = d0;
    inv->di = mpn_invert_3by2(d1, d0);
}

static __attribute__((always_inline)) void
mpn_div_qr_invert(struct gmp_div_inverse *inv,
                  mp_srcptr dp, mp_size_t dn) {
    assert (dn > 0);

    if (dn == 1)
        mpn_div_qr_1_invert(inv, dp[0]);
    else if (dn == 2)
        mpn_div_qr_2_invert(inv, dp[1], dp[0]);
    else {
        unsigned shift;
        mp_limb_t d1, d0;

        d1 = dp[dn - 1];
        d0 = dp[dn - 2];
        assert (d1 > 0);
        gmp_clz (shift, d1);
        inv->shift = shift;
        if (shift > 0) {
            d1 = (d1 << shift) | (d0 >> (GMP_LIMB_BITS - shift));
            d0 = (d0 << shift) | (dp[dn - 3] >> (GMP_LIMB_BITS - shift));
        }
        inv->d1 = d1;
        inv->d0 = d0;
        inv->di = mpn_invert_3by2(d1, d0);
    }
}

/* Not matching current public gmp interface, rather corresponding to
   the sbpi1_div_* functions. */
static __attribute__((always_inline))  mp_limb_t
mpn_div_qr_1_preinv(picoquic_cnx_t *cnx, mp_ptr qp, mp_srcptr np, mp_size_t nn,
                    const struct gmp_div_inverse *inv) {
    mp_limb_t d, di;
    mp_limb_t r;
    mp_ptr tp = NULL;

    if (inv->shift > 0) {
        tp = gmp_xalloc_limbs(cnx, nn);
        r = mpn_lshift(tp, np, nn, inv->shift);
        np = tp;
    } else
        r = 0;

    d = inv->d1;
    di = inv->di;
    while (--nn >= 0) {
        mp_limb_t q;

        gmp_udiv_qrnnd_preinv (q, r, r, np[nn], d, di);
        if (qp)
            qp[nn] = q;
    }
    if (inv->shift > 0)
        gmp_free (cnx, tp);

    return r >> inv->shift;
}

static __attribute__((always_inline)) void
mpn_div_qr_2_preinv(picoquic_cnx_t *cnx, mpz_t q, mpz_t r, mpz_t n,
                    const struct gmp_div_inverse *inv) {
    unsigned shift;
    mp_ptr qp = q->_mp_d;
    mp_ptr rp = r->_mp_d;
    mp_srcptr np = n->_mp_d;
    mp_size_t nn = n->_mp_size;
    mp_size_t i;
    mp_limb_t d1, d0, di, r1, r0;
    mp_ptr tp;

    assert (nn >= 2);
    shift = inv->shift;
    d1 = inv->d1;
    d0 = inv->d0;
    di = inv->di;

    if (shift > 0) {
        tp = gmp_xalloc_limbs(cnx, nn);
        r1 = mpn_lshift(tp, np, nn, shift);
        np = tp;
    } else
        r1 = 0;

    r0 = np[nn - 1];

    i = nn - 2;
    do {
        mp_limb_t n0, q;
        n0 = np[i];
        gmp_udiv_qr_3by2 (q, r1, r0, r1, r0, n0, d1, d0, di);

        if (qp)
            qp[i] = q;
    } while (--i >= 0);

    if (shift > 0) {
        assert ((r0 << (GMP_LIMB_BITS - shift)) == 0);
        r0 = (r0 >> shift) | (r1 << (GMP_LIMB_BITS - shift));
        r1 >>= shift;

        gmp_free (cnx, tp);
    }

    rp[1] = r1;
    rp[0] = r0;
}

static __attribute__((always_inline)) void
mpn_div_qr_pi1(mpz_t qz, mpz_t n, mpz_t d, mp_limb_t n1,
               mp_limb_t dinv) {
    mp_ptr qp = qz->_mp_d;
    mp_ptr np = n->_mp_d;
//    mp_size_t nn = n->_mp_size;
    mp_srcptr dp = d->_mp_d;
//    mp_size_t dn = d->_mp_size;
//    mp_size_t i;

    mp_size_t *sizes = gmp_allocate_func(n->cnx, 3*sizeof(mp_size_t));

    mp_limb_t *limbs = gmp_allocate_func(n->cnx, 6*sizeof(mp_limb_t));

    #define nn sizes[0]
    #define dn sizes[1]
    #define i  sizes[2]

    nn = n->_mp_size;
    dn = d->_mp_size;

    #define d1 limbs[0]
    #define d0 limbs[1]
    #define cy limbs[2]
    #define cy1 limbs[3]
    #define q limbs[4]
    #define n0 limbs[5]

//    mp_limb_t d1, d0;
//    mp_limb_t cy, cy1;
//    mp_limb_t q;

    assert (dn > 2);
    assert (nn >= dn);

    d1 = dp[dn - 1];
    d0 = dp[dn - 2];

    assert ((d1 & GMP_LIMB_HIGHBIT) != 0);
    /* Iteration variable is the index of the q limb.
     *
     * We divide <n1, np[dn-1+i], np[dn-2+i], np[dn-3+i],..., np[i]>
     * by            <d1,          d0,        dp[dn-3],  ..., dp[0] >
     */

    i = nn - dn;
    do {
        n0 = np[dn - 1 + i];

        if (n1 == d1 && n0 == d0) {
            q = GMP_LIMB_MAX;
            mpn_submul_1(np + i, dp, dn, q);
            n1 = np[dn - 1 + i];    /* update n1, last loop's value will now be invalid */
        } else {
            gmp_udiv_qr_3by2 (q, n1, n0, n1, n0, np[dn - 2 + i], d1, d0, dinv);

            cy = mpn_submul_1(np + i, dp, dn - 2, q);

            cy1 = n0 < cy;
            n0 = n0 - cy;
            cy = n1 < cy1;
            n1 = n1 - cy1;
            np[dn - 2 + i] = n0;

            if (cy != 0) {
                n1 += d1 + mpn_add_n(n->cnx, np + i, np + i, dp, dn - 1);
                q--;
            }
        }

        if (qp)
            qp[i] = q;
    } while (--i >= 0);

    np[dn - 1] = n1;
    #undef d1
    #undef d0
    #undef cy
    #undef cy1
    #undef q
    #undef n0

    #undef nn
    #undef dn
    #undef i
    gmp_free(n->cnx, limbs);
    gmp_free(n->cnx, sizes);
}

static __attribute__((always_inline)) void
mpn_div_qr_preinv(picoquic_cnx_t *cnx, mpz_t q, mpz_t n, mpz_t d,
                  const struct gmp_div_inverse *inv) {
    mp_ptr qp = q->_mp_d;
    mp_ptr np = n->_mp_d;
    mp_size_t nn = n->_mp_size;
    mp_srcptr dp = d->_mp_d;
    mp_size_t dn = d->_mp_size;
    assert (dn > 0);
    assert (nn >= dn);

    if (dn == 1)
        np[0] = mpn_div_qr_1_preinv(cnx, q->_mp_d, n->_mp_d, n->_mp_size, inv);
    else if (dn == 2)
        mpn_div_qr_2_preinv(cnx, q, n, n, inv);
    else {
        mp_limb_t nh;
        unsigned shift;

        assert (inv->d1 == dp[dn - 1]);
        assert (inv->d0 == dp[dn - 2]);
        assert ((inv->d1 & GMP_LIMB_HIGHBIT) != 0);

        shift = inv->shift;
        if (shift > 0)
            nh = mpn_lshift(np, np, nn, shift);
        else
            nh = 0;

        mpn_div_qr_pi1(q, n, d, nh, inv->di);

        if (shift > 0)
            gmp_assert_nocarry (mpn_rshift(np, np, dn, shift));
    }
}

static __attribute__((always_inline)) void
mpn_div_qr(picoquic_cnx_t *cnx, mpz_t q, mpz_t n, mpz_t d) {
    mp_ptr qp = q->_mp_d;
    mp_ptr np = n->_mp_d;
    mp_size_t nn = n->_mp_size;
    mp_srcptr dp = d->_mp_d;
    mp_size_t dn = d->_mp_size;
    struct gmp_div_inverse inv;
    mp_ptr tp = NULL;

    assert (dn > 0);
    assert (nn >= dn);

    mpn_div_qr_invert(&inv, dp, dn);
    if (dn > 2 && inv.shift > 0) {
        tp = gmp_xalloc_limbs(cnx, dn);
        gmp_assert_nocarry (mpn_lshift(tp, dp, dn, inv.shift));
        dp = tp;
    }
    mpn_div_qr_preinv(cnx, q, n, d, &inv);
    if (tp)
        gmp_free (cnx, tp);
}


/* MPZ interface */
static __attribute__((always_inline)) void
mpz_init(picoquic_cnx_t *cnx, mpz_t r) {
    static const mp_limb_t dummy_limb = 0xc1a0;

    r->cnx = cnx;
    r->_mp_alloc = 0;
    r->_mp_size = 0;
    r->_mp_d = (mp_ptr) &dummy_limb;
}

/* The utility of this function is a bit limited, since many functions
   assigns the result variable using mpz_swap. */
static __attribute__((always_inline)) void
mpz_init2(picoquic_cnx_t *cnx, mpz_t r, mp_bitcnt_t bits) {
    mp_size_t rn;

    bits -= (bits != 0);        /* Round down, except if 0 */
    rn = 1 + bits / GMP_LIMB_BITS;

    r->cnx = cnx;
    r->_mp_alloc = rn;
    r->_mp_size = 0;
    r->_mp_d = gmp_xalloc_limbs(cnx, rn);
}

static __attribute__((always_inline)) void
mpz_clear(mpz_t r) {
    if (r->_mp_alloc)
        gmp_free (r->cnx, r->_mp_d);
}

static __attribute__((always_inline)) mp_ptr
mpz_realloc(mpz_t r, mp_size_t size) {
    size = GMP_MAX (size, 1);

    if (r->_mp_alloc)
        r->_mp_d = gmp_xrealloc_limbs(r->cnx, r->_mp_d, size);
    else
        r->_mp_d = gmp_xalloc_limbs(r->cnx, size);
    r->_mp_alloc = size;

    if (GMP_ABS (r->_mp_size) > size)
        r->_mp_size = 0;

    return r->_mp_d;
}

/* Realloc for an mpz_t WHAT if it has less than NEEDED limbs.  */
#define MPZ_REALLOC(z, n) ((n) > (z)->_mp_alloc            \
              ? mpz_realloc(z,n)            \
              : (z)->_mp_d)

static __attribute__((always_inline)) void
mpz_set_ui(mpz_t r, unsigned long int x) {
    if (x > 0) {
        r->_mp_size = 1;
        MPZ_REALLOC (r, 1)[0] = x;
    } else
        r->_mp_size = 0;
}

/* MPZ assignment and basic conversions. */
static __attribute__((always_inline)) void
mpz_set_si(mpz_t r, signed long int x) {
    if (x >= 0)
        mpz_set_ui(r, x);
    else /* (x < 0) */
    {
        r->_mp_size = -1;
        MPZ_REALLOC (r, 1)[0] = GMP_NEG_CAST (unsigned long int, x);
    }
}

static __attribute__((always_inline)) void
mpz_set(mpz_t r, const mpz_t x) {
    /* Allow the NOP r == x */
    if (r != x) {
        mp_size_t n;
        mp_ptr rp;

        n = GMP_ABS (x->_mp_size);
        rp = MPZ_REALLOC (r, n);

        mpn_copyi(rp, x->_mp_d, n);
        r->_mp_size = x->_mp_size;
    }
}

static __attribute__((always_inline)) void
mpz_init_set_si(picoquic_cnx_t *cnx, mpz_t r, signed long int x) {
    mpz_init(cnx, r);
    mpz_set_si(r, x);
}

static __attribute__((always_inline)) void
mpz_init_set_ui(picoquic_cnx_t *cnx, mpz_t r, unsigned long int x) {
    mpz_init(cnx, r);
    mpz_set_ui(r, x);
}

static __attribute__((always_inline)) void
mpz_init_set(picoquic_cnx_t *cnx, mpz_t r, const mpz_t x) {
    mpz_init(cnx, r);
    mpz_set(r, x);
}

static __attribute__((always_inline)) int
mpz_fits_slong_p(const mpz_t u) {
    mp_size_t us = u->_mp_size;

    if (us == 1)
        return u->_mp_d[0] < GMP_LIMB_HIGHBIT;
    else if (us == -1)
        return u->_mp_d[0] <= GMP_LIMB_HIGHBIT;
    else
        return (us == 0);
}

static __attribute__((always_inline)) int
mpz_fits_ulong_p(const mpz_t u) {
    mp_size_t us = u->_mp_size;

    return (us == (us > 0));
}

static __attribute__((always_inline)) unsigned long int
mpz_get_ui(const mpz_t u) {
    return u->_mp_size == 0 ? 0 : u->_mp_d[0];
}

static __attribute__((always_inline)) long int
mpz_get_si(const mpz_t u) {
    if (u->_mp_size < 0)
        /* This expression is necessary to properly handle 0x80000000 */
        return -1 - (long) ((u->_mp_d[0] - 1) & ~GMP_LIMB_HIGHBIT);
    else
        return (long) (mpz_get_ui(u) & ~GMP_LIMB_HIGHBIT);
}

static __attribute__((always_inline)) size_t
mpz_size(const mpz_t u) {
    return GMP_ABS (u->_mp_size);
}

static __attribute__((always_inline)) mp_limb_t
mpz_getlimbn(const mpz_t u, mp_size_t n) {
    if (n >= 0 && n < GMP_ABS (u->_mp_size))
        return u->_mp_d[n];
    else
        return 0;
}

static __attribute__((always_inline)) void
mpz_realloc2(mpz_t x, mp_bitcnt_t n) {
    mpz_realloc(x, 1 + (n - (n != 0)) / GMP_LIMB_BITS);
}

static __attribute__((always_inline)) mp_srcptr
mpz_limbs_read(mpz_srcptr x) {
    return x->_mp_d;
}

static __attribute__((always_inline)) mp_ptr
mpz_limbs_modify(mpz_t x, mp_size_t n) {
    assert (n > 0);
    return MPZ_REALLOC (x, n);
}

static __attribute__((always_inline)) mp_ptr
mpz_limbs_write(mpz_t x, mp_size_t n) {
    return mpz_limbs_modify(x, n);
}

static __attribute__((always_inline)) void
mpz_limbs_finish(mpz_t x, mp_size_t xs) {
    mp_size_t xn;
    xn = mpn_normalized_size(x->_mp_d, GMP_ABS (xs));
    x->_mp_size = xs < 0 ? -xn : xn;
}

static __attribute__((always_inline)) mpz_srcptr
mpz_roinit_n(mpz_t x, mp_srcptr xp, mp_size_t xs) {
    x->_mp_alloc = 0;
    x->_mp_d = (mp_ptr) xp;
    mpz_limbs_finish(x, xs);
    return x;
}


/* MPZ comparisons and the like. */
static __attribute__((always_inline)) int
mpz_sgn(const mpz_t u) {
    return GMP_CMP (u->_mp_size, 0);
}

static __attribute__((always_inline)) int
mpz_cmp_ui(const mpz_t u, unsigned long v) {
    mp_size_t usize = u->_mp_size;

    if (usize > 1)
        return 1;
    else if (usize < 0)
        return -1;
    else
        return GMP_CMP (mpz_get_ui(u), v);
}

static __attribute__((always_inline)) int
mpz_cmp_si(const mpz_t u, long v) {
    mp_size_t usize = u->_mp_size;

    if (usize < -1)
        return -1;
    else if (v >= 0)
        return mpz_cmp_ui(u, v);
    else if (usize >= 0)
        return 1;
    else /* usize == -1 */
        return GMP_CMP (GMP_NEG_CAST(mp_limb_t, v), u->_mp_d[0]);
}

static __attribute__((always_inline)) int
mpz_cmp(const mpz_t a, const mpz_t b) {
    mp_size_t asize = a->_mp_size;
    mp_size_t bsize = b->_mp_size;

    if (asize != bsize)
        return (asize < bsize) ? -1 : 1;
    else if (asize >= 0)
        return mpn_cmp(a->_mp_d, b->_mp_d, asize);
    else
        return mpn_cmp(b->_mp_d, a->_mp_d, -asize);
}

static __attribute__((always_inline)) int
mpz_cmpabs_ui(const mpz_t u, unsigned long v) {
    if (GMP_ABS (u->_mp_size) > 1)
        return 1;
    else
        return GMP_CMP (mpz_get_ui(u), v);
}

static __attribute__((always_inline)) int
mpz_cmpabs(const mpz_t u, const mpz_t v) {
    return mpn_cmp4(u->_mp_d, GMP_ABS (u->_mp_size),
                    v->_mp_d, GMP_ABS (v->_mp_size));
}

static __attribute__((always_inline)) void
mpz_abs(mpz_t r, const mpz_t u) {
    mpz_set(r, u);
    r->_mp_size = GMP_ABS (r->_mp_size);
}

static __attribute__((always_inline)) void
mpz_neg(mpz_t r, const mpz_t u) {
    mpz_set(r, u);
    r->_mp_size = -r->_mp_size;
}

static __attribute__((always_inline)) void
mpz_swap(mpz_t u, mpz_t v) {
    MP_SIZE_T_SWAP (u->_mp_size, v->_mp_size);
    MP_SIZE_T_SWAP (u->_mp_alloc, v->_mp_alloc);
    MP_PTR_SWAP (u->_mp_d, v->_mp_d);
}


/* MPZ addition and subtraction */

/* Adds to the absolute value. Returns new size, but doesn't store it. */
static __attribute__((always_inline)) mp_size_t
mpz_abs_add_ui(mpz_t r, const mpz_t a, unsigned long b) {
    mp_size_t an;
    mp_ptr rp;
    mp_limb_t cy;

    an = GMP_ABS (a->_mp_size);
    if (an == 0) {
        MPZ_REALLOC (r, 1)[0] = b;
        return b > 0;
    }

    rp = MPZ_REALLOC (r, an + 1);

    cy = mpn_add_1(rp, a->_mp_d, an, b);
    rp[an] = cy;
    an += cy;

    return an;
}

/* Subtract from the absolute value. Returns new size, (or -1 on underflow),
   but doesn't store it. */
static __attribute__((always_inline)) mp_size_t
mpz_abs_sub_ui(mpz_t r, const mpz_t a, unsigned long b) {
    mp_size_t an = GMP_ABS (a->_mp_size);
    mp_ptr rp;

    if (an == 0) {
        MPZ_REALLOC (r, 1)[0] = b;
        return -(b > 0);
    }
    rp = MPZ_REALLOC (r, an);
    if (an == 1 && a->_mp_d[0] < b) {
        rp[0] = b - a->_mp_d[0];
        return -1;
    } else {
        gmp_assert_nocarry (mpn_sub_1(rp, a->_mp_d, an, b));
        return mpn_normalized_size(rp, an);
    }
}

static __attribute__((always_inline)) void
mpz_add_ui(mpz_t r, const mpz_t a, unsigned long b) {
    if (a->_mp_size >= 0)
        r->_mp_size = mpz_abs_add_ui(r, a, b);
    else
        r->_mp_size = -mpz_abs_sub_ui(r, a, b);
}

static __attribute__((always_inline)) void
mpz_sub_ui(mpz_t r, const mpz_t a, unsigned long b) {
    if (a->_mp_size < 0)
        r->_mp_size = -mpz_abs_add_ui(r, a, b);
    else
        r->_mp_size = mpz_abs_sub_ui(r, a, b);
}

static __attribute__((always_inline)) void
mpz_ui_sub(mpz_t r, unsigned long a, const mpz_t b) {
    if (b->_mp_size < 0)
        r->_mp_size = mpz_abs_add_ui(r, b, a);
    else
        r->_mp_size = -mpz_abs_sub_ui(r, b, a);
}

static __attribute__((always_inline)) mp_size_t
mpz_abs_add(mpz_t r, const mpz_t a, const mpz_t b) {
    mp_size_t an = GMP_ABS (a->_mp_size);
    mp_size_t bn = GMP_ABS (b->_mp_size);
    mp_ptr rp;
    mp_limb_t cy;

    if (an < bn) {
        MPZ_SRCPTR_SWAP (a, b);
        MP_SIZE_T_SWAP (an, bn);
    }

    rp = MPZ_REALLOC (r, an + 1);
    cy = mpn_add(a->cnx, rp, a->_mp_d, an, b->_mp_d, bn);

    rp[an] = cy;

    return an + cy;
}

static __attribute__((always_inline)) mp_size_t
mpz_abs_sub(mpz_t r, const mpz_t a, const mpz_t b) {
    mp_size_t an = GMP_ABS (a->_mp_size);
    mp_size_t bn = GMP_ABS (b->_mp_size);
    int cmp;
    mp_ptr rp;

    cmp = mpn_cmp4(a->_mp_d, an, b->_mp_d, bn);
    if (cmp > 0) {
        rp = MPZ_REALLOC (r, an);
        gmp_assert_nocarry (mpn_sub(rp, a->_mp_d, an, b->_mp_d, bn));
        return mpn_normalized_size(rp, an);
    } else if (cmp < 0) {
        rp = MPZ_REALLOC (r, bn);
        gmp_assert_nocarry (mpn_sub(rp, b->_mp_d, bn, a->_mp_d, an));
        return -mpn_normalized_size(rp, bn);
    } else
        return 0;
}

static __attribute__((always_inline)) void
mpz_add(mpz_t r, const mpz_t a, const mpz_t b) {
    mp_size_t rn;

    if ((a->_mp_size ^ b->_mp_size) >= 0)
        rn = mpz_abs_add(r, a, b);
    else
        rn = mpz_abs_sub(r, a, b);

    r->_mp_size = a->_mp_size >= 0 ? rn : -rn;
}

static __attribute__((always_inline)) void
mpz_sub(mpz_t r, const mpz_t a, const mpz_t b) {
    mp_size_t rn;

    if ((a->_mp_size ^ b->_mp_size) >= 0)
        rn = mpz_abs_sub(r, a, b);
    else
        rn = mpz_abs_add(r, a, b);

    r->_mp_size = a->_mp_size >= 0 ? rn : -rn;
}

static __attribute__((always_inline)) void
mpz_mul_ui(mpz_t r, const mpz_t u, unsigned long int v) {
    mp_size_t un, us;
    mp_ptr tp;
    mp_limb_t cy;

    us = u->_mp_size;

    if (us == 0 || v == 0) {
        r->_mp_size = 0;
        return;
    }

    un = GMP_ABS (us);

    tp = MPZ_REALLOC (r, un + 1);
    cy = mpn_mul_1(tp, u->_mp_d, un, v);
    tp[un] = cy;

    un += (cy > 0);
    r->_mp_size = (int) ((us < 0) ? -un : un);
}


/* MPZ multiplication */
static __attribute__((always_inline)) void
mpz_mul_si(mpz_t r, const mpz_t u, long int v) {
    if (v < 0) {
        mpz_mul_ui(r, u, GMP_NEG_CAST (unsigned long int, v));
        mpz_neg(r, r);
    } else
        mpz_mul_ui(r, u, (unsigned long int) v);
}

static __attribute__((always_inline)) void
mpz_mul(mpz_t r, const mpz_t u, const mpz_t v) {
    int sign;
    mp_size_t un, vn, rn;
    mpz_t t;
    mp_ptr tp;

    un = u->_mp_size;
    vn = v->_mp_size;

    if (un == 0 || vn == 0) {
        r->_mp_size = 0;
        return;
    }

    sign = (un ^ vn) < 0;

    un = GMP_ABS (un);
    vn = GMP_ABS (vn);

    mpz_init2(u->cnx, t, (un + vn) * GMP_LIMB_BITS);

    tp = t->_mp_d;
    if (un >= vn)
        mpn_mul(tp, u->_mp_d, un, v->_mp_d, vn);
    else
        mpn_mul(tp, v->_mp_d, vn, u->_mp_d, un);

    rn = un + vn;
    rn -= tp[rn - 1] == 0;

    t->_mp_size = sign ? -rn : rn;
    mpz_swap(r, t);
    mpz_clear(t);
}


/* MPZ division */
enum mpz_div_round_mode {
    GMP_DIV_FLOOR, GMP_DIV_CEIL, GMP_DIV_TRUNC
};

/* Allows q or r to be zero. Returns 1 iff remainder is non-zero. */
static __attribute__((always_inline)) int
mpz_div_qr(mpz_t q, mpz_t r,
           const mpz_t n, const mpz_t d, enum mpz_div_round_mode mode) {
    mp_size_t ns, ds, nn, dn, qs;
    ns = n->_mp_size;
    ds = d->_mp_size;

    if (ds == 0)
        gmp_die("mpz_div_qr: Divide by zero.");

    if (ns == 0) {
        if (q)
            q->_mp_size = 0;
        if (r)
            r->_mp_size = 0;
        return 0;
    }

    nn = GMP_ABS (ns);
    dn = GMP_ABS (ds);

    qs = ds ^ ns;

    if (nn < dn) {
        if (mode == GMP_DIV_CEIL && qs >= 0) {
            /* q = 1, r = n - d */
            if (r)
                mpz_sub(r, n, d);
            if (q)
                mpz_set_ui(q, 1);
        } else if (mode == GMP_DIV_FLOOR && qs < 0) {
            /* q = -1, r = n + d */
            if (r)
                mpz_add(r, n, d);
            if (q)
                mpz_set_si(q, -1);
        } else {
            /* q = 0, r = d */
            if (r)
                mpz_set(r, n);
            if (q)
                q->_mp_size = 0;
        }
        return 1;
    } else {
        mp_ptr np, qp;
        mp_size_t qn, rn;
        mpz_t tq, tr;

        mpz_init_set(d->cnx, tr, n);
        np = tr->_mp_d;

        qn = nn - dn + 1;

        if (q) {
            mpz_init2(d->cnx, tq, qn * GMP_LIMB_BITS);
            qp = tq->_mp_d;
        } else
            qp = NULL;

        mpn_div_qr(d->cnx, q, (__mpz_struct *) n, (__mpz_struct *) d);

        if (qp) {
            qn -= (qp[qn - 1] == 0);

            tq->_mp_size = qs < 0 ? -qn : qn;
        }
        rn = mpn_normalized_size(np, dn);
        tr->_mp_size = ns < 0 ? -rn : rn;

        if (mode == GMP_DIV_FLOOR && qs < 0 && rn != 0) {
            if (q)
                mpz_sub_ui(tq, tq, 1);
            if (r)
                mpz_add(tr, tr, d);
        } else if (mode == GMP_DIV_CEIL && qs >= 0 && rn != 0) {
            if (q)
                mpz_add_ui(tq, tq, 1);
            if (r)
                mpz_sub(tr, tr, d);
        }

        if (q) {
            mpz_swap(tq, q);
            mpz_clear(tq);
        }
        if (r)
            mpz_swap(tr, r);

        mpz_clear(tr);

        return rn != 0;
    }
}

/* Allows q or r to be zero. Returns 1 iff remainder is non-zero. */
static __attribute__((always_inline)) int
mpz_div_q(mpz_t q,
          const mpz_t n, const mpz_t d, enum mpz_div_round_mode mode) {
//  mp_size_t ns, ds, nn, dn, qs;
    mp_size_t *sizes = gmp_allocate_func(n->cnx, 5 * sizeof(mp_size_t));
#define ns sizes[0]
#define ds sizes[1]
#define nn sizes[2]
#define dn sizes[3]
#define qs sizes[4]
    ns = n->_mp_size;
    ds = d->_mp_size;

    if (ds == 0)
        gmp_die("mpz_div_qr: Divide by zero.");

    if (ns == 0) {
        if (q)
            q->_mp_size = 0;

        gmp_free(n->cnx, sizes);
        return 0;
    }

    nn = GMP_ABS (ns);
    dn = GMP_ABS (ds);

    qs = ds ^ ns;

    if (nn < dn) {
        if (mode == GMP_DIV_CEIL && qs >= 0) {
            /* q = 1, r = n - d */
            if (q)
                mpz_set_ui(q, 1);
        } else if (mode == GMP_DIV_FLOOR && qs < 0) {
            /* q = -1, r = n + d */
            if (q)
                mpz_set_si(q, -1);
        } else {
            /* q = 0, r = d */
            if (q)
                q->_mp_size = 0;
        }
        gmp_free(n->cnx, sizes);
        return 1;
    } else {
        mp_ptr np, qp;
        mp_size_t qn, rn;
        mpz_t tq, tr;

        mpz_init_set(d->cnx, tr, n);
        np = tr->_mp_d;

        qn = nn - dn + 1;

        if (q) {
            mpz_init2(d->cnx, tq, qn * GMP_LIMB_BITS);
            qp = tq->_mp_d;
        } else
            qp = NULL;

        mpn_div_qr(d->cnx, tq, (__mpz_struct *) n, (__mpz_struct *) d);

        if (qp) {
            qn -= (qp[qn - 1] == 0);

            tq->_mp_size = qs < 0 ? -qn : qn;
        }
        rn = mpn_normalized_size(np, dn);
        tr->_mp_size = ns < 0 ? -rn : rn;

        if (mode == GMP_DIV_FLOOR && qs < 0 && rn != 0) {
            if (q)
                mpz_sub_ui(tq, tq, 1);
        } else if (mode == GMP_DIV_CEIL && qs >= 0 && rn != 0) {
            if (q)
                mpz_add_ui(tq, tq, 1);
        }

        if (q) {
            mpz_swap(tq, q);
            mpz_clear(tq);
        }

        mpz_clear(tr);

        gmp_free(n->cnx, sizes);
        return rn != 0;
    }
#undef ns
#undef ds
#undef nn
#undef dn
#undef qs
}

static __attribute__((always_inline)) void
mpz_cdiv_qr(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d) {
    mpz_div_qr(q, r, n, d, GMP_DIV_CEIL);
}

static __attribute__((always_inline)) void
mpz_fdiv_qr(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d) {
    mpz_div_qr(q, r, n, d, GMP_DIV_FLOOR);
}

static __attribute__((always_inline)) void
mpz_tdiv_qr(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d) {
    mpz_div_qr(q, r, n, d, GMP_DIV_TRUNC);
}

static __attribute__((always_inline)) void
mpz_cdiv_q(mpz_t q, const mpz_t n, const mpz_t d) {
    mpz_div_qr(q, NULL, n, d, GMP_DIV_CEIL);
}

static __attribute__((always_inline)) void
mpz_fdiv_q(mpz_t q, const mpz_t n, const mpz_t d) {
    mpz_div_q(q, n, d, GMP_DIV_FLOOR);
}

static __attribute__((always_inline)) void
mpz_tdiv_q(mpz_t q, const mpz_t n, const mpz_t d) {
    mpz_div_qr(q, NULL, n, d, GMP_DIV_TRUNC);
}

static __attribute__((always_inline)) void
mpz_cdiv_r(mpz_t r, const mpz_t n, const mpz_t d) {
    mpz_div_qr(NULL, r, n, d, GMP_DIV_CEIL);
}

static __attribute__((always_inline)) void
mpz_fdiv_r(mpz_t r, const mpz_t n, const mpz_t d) {
    mpz_div_qr(NULL, r, n, d, GMP_DIV_FLOOR);
}

static __attribute__((always_inline)) void
mpz_tdiv_r(mpz_t r, const mpz_t n, const mpz_t d) {
    mpz_div_qr(NULL, r, n, d, GMP_DIV_TRUNC);
}

static int
gmp_detect_endian(void) {
    static const int i = 2;
    const unsigned char *p = (const unsigned char *) &i;
    return 1 - *p;
}

/* Import and export. Does not support nails. */
static __attribute__((always_inline)) void
mpz_import(mpz_t r, size_t count, int order, size_t size, const void *src) {
    size_t nails = 0;
    int endian = 0;
    unsigned char *p;
    ptrdiff_t word_step;
    mp_ptr rp;
    mp_size_t rn;

    /* The current (partial) limb. */
    mp_limb_t limb;
    /* The number of bytes already copied to this limb (starting from
       the low end). */
    size_t bytes;
    /* The index where the limb should be stored, when completed. */
    mp_size_t i;

    if (nails != 0)
        gmp_die("mpz_import: Nails not supported.");

    assert (order == 1 || order == -1);
    assert (endian >= -1 && endian <= 1);

    if (endian == 0)
        endian = gmp_detect_endian();

    p = (unsigned char *) src;

    word_step = (order != endian) ? 2 * size : 0;

    /* Process bytes from the least significant end, so point p at the
       least significant word. */
    if (order == 1) {
        p += size * (count - 1);
        word_step = -word_step;
    }

    /* And at least significant byte of that word. */
    if (endian == 1)
        p += (size - 1);

    rn = (size * count + sizeof(mp_limb_t) - 1) / sizeof(mp_limb_t);
    rp = MPZ_REALLOC (r, rn);
    for (limb = 0, bytes = 0, i = 0; count > 0; count--, p += word_step) {
        size_t j;
        for (j = 0; j < size; j++, p -= (ptrdiff_t) endian) {
            limb |= (mp_limb_t) *p << (bytes++ * CHAR_BIT);
            if (bytes == sizeof(mp_limb_t)) {
                rp[i++] = limb;
                bytes = 0;
                limb = 0;
            }
        }
    }
    assert (i + (bytes > 0) == rn);
    if (limb != 0)
        rp[i++] = limb;
    else
        i = mpn_normalized_size(rp, i);

    r->_mp_size = (int) i;
}

static __attribute__((always_inline)) void *
mpz_export(void *r, size_t *countp, int order, size_t size, const mpz_t u) {
    size_t nails = 0;
    int endian = 0;
    size_t count;
    mp_size_t un;

    if (nails != 0)
        gmp_die("mpz_import: Nails not supported.");

    assert (order == 1 || order == -1);
    assert (endian >= -1 && endian <= 1);
    assert (size > 0 || u->_mp_size == 0);

    un = u->_mp_size;
    count = 0;
    if (un != 0) {
        size_t k;
        unsigned char *p;
        ptrdiff_t word_step;
        /* The current (partial) limb. */
        mp_limb_t limb;
        /* The number of bytes left to to in this limb. */
        size_t bytes;
        /* The index where the limb was read. */
        mp_size_t i;

        un = GMP_ABS (un);

        /* Count bytes in top limb. */
        limb = u->_mp_d[un - 1];
        assert (limb != 0);

        k = 0;
        do {
            k++;
            limb >>= CHAR_BIT;
        } while (limb != 0);

        count = (k + (un - 1) * sizeof(mp_limb_t) + size - 1) / size;

        if (!r)
            r = gmp_xalloc (u->cnx, count * size);

        if (endian == 0)
            endian = gmp_detect_endian();

        p = (unsigned char *) r;

        word_step = (order != endian) ? 2 * size : 0;

        /* Process bytes from the least significant end, so point p at the
       least significant word. */
        if (order == 1) {
            p += size * (count - 1);
            word_step = -word_step;
        }

        /* And at least significant byte of that word. */
        if (endian == 1)
            p += (size - 1);

        for (bytes = 0, i = 0, k = 0; k < count; k++, p += word_step) {
            size_t j;
            for (j = 0; j < size; j++, p -= (ptrdiff_t) endian) {
                if (bytes == 0) {
                    if (i < un)
                        limb = u->_mp_d[i++];
                    bytes = sizeof(mp_limb_t);
                }
                *p = (unsigned char) limb;
                limb >>= CHAR_BIT;
                bytes--;
            }
        }
        assert (i == un);
        assert (k == count);
    }

    if (countp)
        *countp = count;

    return r;
}

static __attribute__((always_inline)) mp_bitcnt_t
mpn_limb_size_in_base_2(mp_limb_t u) {
    unsigned shift;

    assert (u > 0);
    gmp_clz (shift, u);
    return GMP_LIMB_BITS - shift;
}

static __attribute__((always_inline)) size_t
mpz_sizeinbase(const mpz_t u, int base) {
    mp_size_t un;
    mp_srcptr up;
    mp_ptr tp;
    mp_bitcnt_t bits;
    struct gmp_div_inverse bi;
    size_t ndigits;

    assert (base >= 2);
    assert (base <= 36);

    un = GMP_ABS (u->_mp_size);
    if (un == 0)
        return 1;

    up = u->_mp_d;

    bits = (un - 1) * GMP_LIMB_BITS + mpn_limb_size_in_base_2(up[un - 1]);
    switch (base) {
        case 2:
            return bits;
        case 4:
            return (bits + 1) / 2;
        case 8:
            return (bits + 2) / 3;
        case 16:
            return (bits + 3) / 4;
        case 32:
            return (bits + 4) / 5;

    }

    tp = gmp_xalloc_limbs(u->cnx, un);
    mpn_copyi(tp, up, un);
    mpn_div_qr_1_invert(&bi, base);
    ndigits = 0;
    do {
        ndigits++;
        mpn_div_qr_1_preinv(u->cnx, tp, tp, un, &bi);
        un -= (tp[un - 1] == 0);
    } while (un > 0);

    gmp_free(u->cnx, tp);
    return ndigits;
}

/* MPN base conversion. */
//static unsigned
//mpn_base_power_of_two_p (unsigned b)
//{
//  switch (b)
//  {
//    case 2: return 1;
//    case 4: return 2;
//    case 8: return 3;
//    case 16: return 4;
//    case 32: return 5;
//    case 64: return 6;
//    case 128: return 7;
//    case 256: return 8;
//    default: return 0;
//  }
//}
//
//
