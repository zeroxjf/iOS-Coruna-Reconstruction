#include "coruna_stage_loader.h"

#include <string.h>

_Static_assert(sizeof(struct coruna_stage_slot) == 0x30, "stage slot size drift");

static int coruna_stage_record_store_find_index(
    const struct coruna_stage_record_store *store,
    uint32_t record_id)
{
    uint32_t index;

    for (index = 0; index < store->count; index++) {
        if (store->entries[index].record_id == record_id) {
            return (int)index;
        }
    }

    return -1;
}

void coruna_mode_status_init_default(struct coruna_mode_status *out_status)
{
    if (out_status == NULL) {
        return;
    }

    out_status->enabled = false;
    out_status->ttl_seconds = CORUNA_MODE_DEFAULT_TTL_SECONDS;
}

bool coruna_mode_status_init_from_blob(
    struct coruna_mode_status *out_status,
    const void *bytes,
    size_t byte_size)
{
    struct coruna_mode_blob_view view;

    if (out_status == NULL) {
        return false;
    }

    if (!coruna_mode_blob_view_init(&view, bytes, byte_size)) {
        return false;
    }

    out_status->enabled = view.enabled;
    out_status->ttl_seconds = view.ttl_seconds;
    return true;
}

int64_t coruna_stage_record_store_init(struct coruna_stage_record_store *out_store)
{
    if (out_store == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    memset(out_store, 0, sizeof(*out_store));
    return CORUNA_STATUS_OK;
}

int64_t coruna_stage_record_store_add(
    struct coruna_stage_record_store *store,
    uint32_t record_id,
    const void *bytes,
    uint32_t byte_size)
{
    int existing_index;
    const struct coruna_stage_record *existing;

    if (store == NULL || record_id == 0) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    if (bytes == NULL || byte_size == 0) {
        return CORUNA_STATUS_RECORD_MISSING_DATA;
    }

    existing_index = coruna_stage_record_store_find_index(store, record_id);
    if (existing_index >= 0) {
        existing = &store->entries[(uint32_t)existing_index];
        if (existing->byte_size == byte_size
            && memcmp(existing->bytes, bytes, byte_size) == 0) {
            return CORUNA_STATUS_OK;
        }
        return CORUNA_STATUS_RECORD_CONFLICT;
    }

    if (store->count >= CORUNA_STAGE_SLOT_COUNT) {
        return CORUNA_STATUS_RECORD_STORE_FULL;
    }

    store->entries[store->count].record_id = record_id;
    store->entries[store->count].bytes = bytes;
    store->entries[store->count].byte_size = byte_size;
    store->count++;
    return CORUNA_STATUS_OK;
}

int64_t coruna_stage_record_store_add_cstring(
    struct coruna_stage_record_store *store,
    uint32_t record_id,
    const char *cstring)
{
    if (store == NULL || cstring == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return coruna_stage_record_store_add(
        store,
        record_id,
        cstring,
        (uint32_t)(strlen(cstring) + 1));
}

int64_t coruna_stage_record_store_build_from_slots(
    struct coruna_stage_record_store *out_store,
    const struct coruna_stage_slot *slots,
    size_t slot_count)
{
    size_t index;
    size_t limit;
    int64_t status;

    if (out_store == NULL || slots == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    status = coruna_stage_record_store_init(out_store);
    if (status != CORUNA_STATUS_OK) {
        return status;
    }

    limit = slot_count;
    if (limit > CORUNA_STAGE_SLOT_COUNT) {
        limit = CORUNA_STAGE_SLOT_COUNT;
    }

    for (index = 0; index < limit; index++) {
        if (slots[index].record_id == 0) {
            continue;
        }

        status = coruna_stage_record_store_add(
            out_store,
            slots[index].record_id,
            slots[index].bytes,
            slots[index].byte_size);
        if (status != CORUNA_STATUS_OK) {
            return status;
        }
    }

    return CORUNA_STATUS_OK;
}

bool coruna80000_thread_pack_init(
    struct coruna80000_thread_pack *out_pack,
    const struct coruna90000_driver_object *driver_object,
    bool create_detached_thread,
    void *payload_bytes,
    uint32_t payload_size,
    char *record_70003,
    char *record_70004,
    char *record_70006)
{
    if (out_pack == NULL
        || !coruna90000_driver_object_validate(driver_object)
        || payload_bytes == NULL
        || payload_size == 0) {
        return false;
    }

    memset(out_pack, 0, sizeof(*out_pack));
    out_pack->driver_object = driver_object;
    out_pack->join_worker = (uint8_t)(!create_detached_thread);
    out_pack->payload_bytes = payload_bytes;
    out_pack->payload_size = payload_size;
    out_pack->symbol_slot_0 = record_70003;
    out_pack->symbol_slot_1 = record_70004;
    out_pack->symbol_slot_2 = record_70006;
    return true;
}
