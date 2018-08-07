/**
 * Copyright 2018 Quentin De Coninck
 * Glue needed to run plugins
 */

#ifndef PLUGIN_H
#define PLUGIN_H

#include "picoquic_internal.h"
#include <stdio.h>
#include <stdarg.h>

/* Function to insert plugins */
int plugin_plug_elf(picoquic_cnx_t *cnx, protoop_id_t pid, char *elf_fname);

/**
 * Function allowing running operations, either built-in or plugged.
 * It runs at invocation time, and returns to the caller the status of the callee.
 * Notice that this function is reentrant, i.e., a plugin might use an
 * external function that call this one under the hood without any
 * interference.
 * Arguments can be provided to the operations. It ensures that they will
 * be safely passed to them without corrupting previous arguments due to
 * reentrant calls. There are as many arguments in inputv as the value of inputc.
 * Both inputv and outputv are provided by the caller.
 * The size of the output is stored in cnx->protoop_outputc.
 * outputv can be set to NULL if no output is required.
 * One output is always guaranteed: the return value of this call.
 */
protoop_arg_t plugin_run_protoop(picoquic_cnx_t *cnx, protoop_id_t pid, int inputc, uint64_t *inputv, uint64_t *outputv);

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifdef DEBUG_PLUGIN_PRINTF

#define DBG_PLUGIN_PRINTF_FILENAME_MAX 24
#define DBG_PLUGIN_PRINTF(fmt, ...)                                                                 \
    debug_printf("%s:%u [%s]: " fmt "\n",                                                    \
        __FILE__ + MAX(DBG_PLUGIN_PRINTF_FILENAME_MAX, sizeof(__FILE__)) - DBG_PLUGIN_PRINTF_FILENAME_MAX, \
        __LINE__, __FUNCTION__, __VA_ARGS__)

#else

#define DBG_PLUGIN_PRINTF(fmt, ...)

#endif // #ifdef DEBUG_PLUGIN_PRINTF

/* Helper macros */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)

/* C99-style: anonymous argument referenced by __VA_ARGS__, empty arg not OK */

# define N_ARGS(...) N_ARGS_HELPER1(__VA_ARGS__, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
# define N_ARGS_HELPER1(...) N_ARGS_HELPER2(__VA_ARGS__)
# define N_ARGS_HELPER2(x1, x2, x3, x4, x5, x6, x7, x8, x9, n, ...) n

# define protoop_prepare_and_run(cnx, pid, outputv, ...) protoop_prepare_and_run_helper(cnx, pid, outputv, N_ARGS(__VA_ARGS__), __VA_ARGS__)
# define protoop_save_outputs(cnx, ...) protoop_save_outputs_helper(cnx, N_ARGS(__VA_ARGS__), __VA_ARGS__)

#elif defined(__GNUC__)

/* GCC-style: named argument, empty arg is OK */

# define N_ARGS(args...) N_ARGS_HELPER1(args, 9, 8, 7, 6, 5, 4, 3, 2, 1)
# define N_ARGS_HELPER1(args...) N_ARGS_HELPER2(args)
# define N_ARGS_HELPER2(x1, x2, x3, x4, x5, x6, x7, x8, x9, n, x...) n

# define protoop_prepare_and_run(cnx, pid, outputv, ...) protoop_prepare_and_run_helper(cnx, pid, outputv, N_ARGS(args), args)
# define protoop_save_outputs(cnx, ...) protoop_save_outputs_helper(cnx, N_ARGS(args), args)

#else

#error variadic macros for your compiler here

#endif

static inline protoop_arg_t protoop_prepare_and_run_helper(picoquic_cnx_t *cnx, protoop_id_t pid, protoop_arg_t *outputv, unsigned int n_args, ...)
{
  protoop_arg_t i, arg;
  va_list ap;

  va_start(ap, n_args);
  protoop_arg_t args[n_args];
  DBG_PLUGIN_PRINTF("%u argument(s):", n_args);
  for (i = 0; i < n_args; i++) {
    arg = va_arg(ap, protoop_arg_t);
    args[i] = arg;
    DBG_PLUGIN_PRINTF("  %lu\n", arg);
  }
  va_end(ap);
  return plugin_run_protoop(cnx, pid, n_args, args, outputv);
}

static inline void protoop_save_outputs_helper(picoquic_cnx_t *cnx, unsigned int n_args, ...)
{
  protoop_arg_t i, arg;
  va_list ap;

  va_start(ap, n_args);
  DBG_PLUGIN_PRINTF("%u saved:", n_args);
  for (i = 0; i < n_args; i++) {
    arg = va_arg(ap, protoop_arg_t);
    cnx->protoop_outputv[i] = arg;
    DBG_PLUGIN_PRINTF("  %lu\n", arg);
  }
  cnx->protoop_outputc_callee = n_args;
  va_end(ap);
}

#endif // #ifndef PLUGIN_H