#include "memory.h"
#include "util.h"

#include "../helpers.h"

#define QLOG_OPAQUE_ID 0x00

#define QLOG_VANTAGE_POINT_CLIENT "CLIENT"
#define QLOG_VANTAGE_POINT_SERVER "SERVER"
#define QLOG_VERSION "draft-00"
#define QLOG_N_EVENT_FIELDS 6
#define QLOG_EVENT_FIELDS {"relative_time", "CATEGORY", "EVENT_TYPE", "TRIGGER", "CONTEXT", "DATA"}
#define QLOG_N_END_CHARS 4
#define QLOG_END_CHARS "]}]}"

typedef struct st_qlog_ctx_t {
    char *ctx;
    struct st_qlog_ctx_t *next;
} qlog_ctx_t;

typedef struct st_qlog_event_t {
    uint64_t reference_time;
    char *fields[QLOG_N_EVENT_FIELDS - 1];
    struct st_qlog_event_t *next;
} qlog_event_t;

typedef struct st_qlog_header_t {
    char *title;
    char *description;
    char *vantage_point;
    picoquic_connection_id_t odcid;
    uint64_t reference_time;
    char *event_fields[QLOG_N_EVENT_FIELDS];
} qlog_hdr_t;

typedef struct st_qlog_t {
    int fd;
    qlog_hdr_t hdr;
    qlog_event_t *head;
    qlog_event_t *tail;
    qlog_ctx_t *top;
    bool wrote_hdr;
    bool wrote_event;
} qlog_t;

static __attribute__((always_inline)) qlog_t* get_qlog_t(picoquic_cnx_t *cnx) {
    int allocated = 0;
    qlog_t *bpfd_ptr = (qlog_t *) get_opaque_data(cnx, QLOG_OPAQUE_ID, sizeof(qlog_t), &allocated);
    if (!bpfd_ptr) return NULL;
    if (allocated) {
        my_memset(bpfd_ptr, 0, sizeof(qlog_t));
        bpfd_ptr->fd = -1;
        char *events[QLOG_N_EVENT_FIELDS] = QLOG_EVENT_FIELDS;
        my_memcpy(bpfd_ptr->hdr.event_fields, events, sizeof(events));
    }
    return bpfd_ptr;
}

static __attribute__((always_inline)) void push_ctx(picoquic_cnx_t *cnx, qlog_t *q, char *ctx) {
    qlog_ctx_t *e = (qlog_ctx_t *) my_malloc(cnx, sizeof(qlog_ctx_t));
    if (e) {
        e->next = q->top;
        e->ctx = ctx;
        q->top = e;
    }
}

static __attribute__((always_inline)) char * pop_ctx(picoquic_cnx_t *cnx, qlog_t *q) {
    char *ctx = NULL;
    qlog_ctx_t *e = q->top;
    if (e) {
        q->top = e->next;
        ctx = e->ctx;
        my_free(cnx, e);
    }
    return ctx;
}

static __attribute__((always_inline)) char * format_ctx(picoquic_cnx_t *cnx, qlog_t *q) {
    size_t ctx_size = 256;
    char *ctx = (char *) my_malloc(cnx, ctx_size);
    if (!ctx) {
        return NULL;
    }
    size_t ofs = snprintf(ctx, ctx_size, "{");
    qlog_ctx_t *c = q->top;
    while (c && ofs < ctx_size) {
        ofs += snprintf(ctx + ofs, ctx_size - ofs, "%s", c->ctx);
        if ((c = c->next)) {
            ofs += snprintf(ctx + ofs, ctx_size - ofs, ", ");
        }
    }
    if (ofs < ctx_size) {
        ofs += snprintf(ctx + ofs, ctx_size - ofs, "}");
    }
    ctx[ofs] = 0;
    return ctx;
}

static __attribute__((always_inline)) void free_event(picoquic_cnx_t *cnx, qlog_event_t *e) {
    for (int i = 0; i < QLOG_N_EVENT_FIELDS - 1; i++) {
        if (e->fields[i]) {
            my_free(cnx, e->fields[i]);
        }
    }
    my_free(cnx, e);
}

static __attribute__((always_inline)) void append_event(qlog_t *q, uint64_t absolute_time, char **fields) {
    if (q->wrote_hdr || q->wrote_event) {
        lseek(q->fd, -QLOG_N_END_CHARS, SEEK_END);
    }
    uint64_t relative_time = absolute_time - q->hdr.reference_time;
    dprintf(q->fd, "[%lu, ", relative_time);
    for (int i = 0; i < QLOG_N_EVENT_FIELDS - 3; i++) {
        dprintf(q->fd, "\"%s\", ", fields[i]);
    }
    dprintf(q->fd, "%s, %s],", fields[QLOG_N_EVENT_FIELDS - 3], fields[QLOG_N_EVENT_FIELDS - 2]);
    dprintf(q->fd, QLOG_END_CHARS);
    q->wrote_event = true;
}

static void write_header(picoquic_cnx_t *cnx, qlog_t *q) {
    dprintf(q->fd, "{\"qlog_version\": \"%s\", \"title\": \"%s\", \"description\": \"%s\", \"summary\": {}, ", QLOG_VERSION, q->hdr.title, q->hdr.description);
    dprintf(q->fd, "\"traces\": [{\"vantage_point\": {\"type\": \"%s\"}, \"title\": \"%s\", \"description\": \"%s\", ", q->hdr.vantage_point, q->hdr.title, q->hdr.description);
    dprintf(q->fd, "\"events\": []}]}");
    q->wrote_hdr = true;

    while (q->head) {
        qlog_event_t *e = q->head;
        append_event(q, e->reference_time, e->fields);
        q->head = e->next;
        free_event(cnx, e);
    }
}

static void write_trailer(picoquic_cnx_t *cnx, qlog_t *q) {
    lseek(q->fd, -(QLOG_N_END_CHARS + q->wrote_event), SEEK_END);
    char *id_str = my_malloc(cnx, (sizeof(char) * (q->hdr.odcid.id_len * 2)) + sizeof(char));
    if (!id_str) return;
    for (int i = 0; i < q->hdr.odcid.id_len; i ++) {
        snprintf(id_str + (i * 2), 2, "%02x", q->hdr.odcid.id[i]);
    }
    id_str[(q->hdr.odcid.id_len * 2)] = 0;
    dprintf(q->fd, "], \"configuration\": {\"time_offset\": 0, \"time_units\": \"us\"}, \"common_fields\": {\"group_id\": \"%s\", \"ODCID\": \"%s\", ", id_str, id_str);
    dprintf(q->fd, "\"reference_time\": %lu}, \"event_fields\": [", q->hdr.reference_time);
    for (int i = 0; i < QLOG_N_EVENT_FIELDS - 1; i++) {
        dprintf(q->fd, "\"%s\", ", q->hdr.event_fields[i]);
    }
    dprintf(q->fd, "\"%s\"]}]}", q->hdr.event_fields[QLOG_N_EVENT_FIELDS - 1]);

    off_t cur = lseek(q->fd, 0, SEEK_CUR);
    ftruncate(q->fd, cur);
}
