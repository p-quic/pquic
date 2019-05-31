#define RR_OPAQUE_ID 0x0

static __attribute__((always_inline)) uint64_t *get_last_drr_stream_id(picoquic_cnx_t *cnx)
{
    int allocated = 0;
    uint64_t *bpfd_ptr = (uint64_t *) get_opaque_data(cnx, RR_OPAQUE_ID, sizeof(uint64_t), &allocated);
    if (!bpfd_ptr) return NULL;
    if (allocated) {
        *bpfd_ptr = 0;
    }
    return bpfd_ptr;
}
