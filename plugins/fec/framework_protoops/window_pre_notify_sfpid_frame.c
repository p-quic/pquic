#include "../framework/window_framework_sender.h"
#include "../framework/window_framework_receiver.h"


protoop_arg_t framework_notify_sfpid_frame(picoquic_cnx_t *cnx)
{
    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    bpf_state *state = get_bpf_state(cnx);
    if (!state)
        return PICOQUIC_ERROR_MEMORY;
    sfpid_has_landed(state->framework_sender, ((source_fpid_frame_t *)rfs->frame_ctx)->source_fpid);
    return 0;
}