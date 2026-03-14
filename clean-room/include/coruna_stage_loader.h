#ifndef CORUNA_STAGE_LOADER_H
#define CORUNA_STAGE_LOADER_H

#include "coruna_contracts.h"

#ifdef __cplusplus
extern "C" {
#endif

enum coruna_stage_loader_offset {
    CORUNA_CTX_OFFSET_RECORD_70003_STRING = 120,
    CORUNA_CTX_OFFSET_RECORD_70004_STRING = 160,
    CORUNA_CTX_OFFSET_RECORD_70006_STRING = 168,
    CORUNA_CTX_OFFSET_STAGE_FLAG_1472 = 1472,
    CORUNA_CTX_OFFSET_STAGE_FLAG_1473 = 1473,
    CORUNA_CTX_OFFSET_STAGE_FLAG_1476 = 1476,
    CORUNA_CTX_OFFSET_CREATE_DETACHED_THREAD = 1478,
    CORUNA_CTX_OFFSET_LOG_ENABLED = 1515,
    CORUNA_CTX_OFFSET_LOG_CALLBACK = 1520,
};

enum coruna_stage_limit {
    CORUNA_STAGE_SLOT_COUNT = 24,
};

enum coruna_stage_object_abi {
    CORUNA_STAGE_STORE_ABI = 0x00010001u,
    CORUNA_STAGE_SESSION_ABI = 0x00010003u,
    CORUNA_STAGE_CONTAINER_ABI = 0x00060004u,
};

enum coruna_stage_default {
    CORUNA_MODE_DEFAULT_TTL_SECONDS = 86400u,
};

struct coruna_stage_slot {
    uint32_t record_id;
    uint32_t reserved_04;
    const void *bytes;
    uint32_t byte_size;
    uint32_t reserved_14;
    uint8_t reserved_18[0x18];
};

struct coruna_stage_record {
    uint32_t record_id;
    const void *bytes;
    uint32_t byte_size;
};

struct coruna_stage_record_store {
    uint32_t count;
    struct coruna_stage_record entries[CORUNA_STAGE_SLOT_COUNT];
};

struct coruna_mode_status {
    bool enabled;
    uint32_t ttl_seconds;
};

bool coruna_mode_status_init_from_blob(
    struct coruna_mode_status *out_status,
    const void *bytes,
    size_t byte_size);
void coruna_mode_status_init_default(struct coruna_mode_status *out_status);

int64_t coruna_stage_record_store_init(struct coruna_stage_record_store *out_store);
int64_t coruna_stage_record_store_add(
    struct coruna_stage_record_store *store,
    uint32_t record_id,
    const void *bytes,
    uint32_t byte_size);
int64_t coruna_stage_record_store_add_cstring(
    struct coruna_stage_record_store *store,
    uint32_t record_id,
    const char *cstring);
int64_t coruna_stage_record_store_build_from_slots(
    struct coruna_stage_record_store *out_store,
    const struct coruna_stage_slot *slots,
    size_t slot_count);

bool coruna80000_thread_pack_init(
    struct coruna80000_thread_pack *out_pack,
    const struct coruna90000_driver_object *driver_object,
    bool create_detached_thread,
    void *payload_bytes,
    uint32_t payload_size,
    char *record_70003,
    char *record_70004,
    char *record_70006);

#ifdef __cplusplus
}
#endif

#endif
