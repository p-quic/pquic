#include "../framework/window_framework_sender.c"
#include "../framework/window_framework_receiver.c"


protoop_arg_t window_write_sfpid_frame(picoquic_cnx_t *cnx)
{
    uint64_t consumed = (uint64_t) get_cnx(cnx, CNX_AK_OUTPUT, 0);
    int retval = (int) get_cnx(cnx, CNX_AK_RETURN_VALUE, 0);

    bpf_state *state = get_bpf_state(cnx);
    if (!state)
        return PICOQUIC_ERROR_MEMORY;
    if (retval == 0 && consumed > 0)
        sfpid_takes_off(state->framework_sender, ((source_fpid_frame_t *)get_cnx(cnx, CNX_AK_INPUT, 2))->source_fpid);
    return 0;
}