#define RR_OPAQUE_ID 0x0

static __attribute__((always_inline)) uint64_t *get_last_drr_stream_id(picoquic_cnx_t *cnx)
{
    uint64_t *bpfd_ptr = (uint64_t *) get_cnx_metadata(cnx, RR_OPAQUE_ID);
    if (!bpfd_ptr) {
        bpfd_ptr = my_malloc_ex(cnx, sizeof(uint64_t));
        /* TODO handle NULL */
        *bpfd_ptr = 0;
        set_cnx_metadata(cnx, RR_OPAQUE_ID, (protoop_arg_t) bpfd_ptr);
    }
    return bpfd_ptr;
}
