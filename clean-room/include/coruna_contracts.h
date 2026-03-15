#ifndef CORUNA_CONTRACTS_H
#define CORUNA_CONTRACTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum coruna_status_code {
    CORUNA_STATUS_OK = 0,
    CORUNA_STATUS_INVALID_ARGUMENT = 708609,
    CORUNA_STATUS_UNSUPPORTED = 708616,
    CORUNA_STATUS_NO_MEMORY = 708617,
    CORUNA_STATUS_BAD_OUTPUT = 708618,
    CORUNA_STATUS_SYSTEM = 708619,
    CORUNA_STATUS_RECORD_MISSING_DATA = 28674,
    CORUNA_STATUS_RECORD_NOT_FOUND = 28675,
    CORUNA_STATUS_BAD_RECORD_LAYOUT = 28676,
    CORUNA_STATUS_RECORD_STORE_FULL = 28678,
    CORUNA_STATUS_RECORD_CONFLICT = 28682,
};

enum coruna_record_id {
    CORUNA_RECORD_50000 = 0x50000,
    CORUNA_RECORD_70000 = 0x70000,
    CORUNA_RECORD_70003 = 0x70003,
    CORUNA_RECORD_70004 = 0x70004,
    CORUNA_RECORD_70005 = 0x70005,
    CORUNA_RECORD_70006 = 0x70006,
    CORUNA_RECORD_80000 = 0x80000,
    CORUNA_RECORD_90000 = 0x90000,
    CORUNA_RECORD_90001 = 0x90001,
    CORUNA_RECORD_A0000 = 0xA0000,
    CORUNA_RECORD_F0000 = 0xF0000,
};

enum coruna_bootstrap_request_id {
    CORUNA_BOOTSTRAP_REQUEST_SELECTED_PATH = 0x70001u,
    CORUNA_BOOTSTRAP_REQUEST_PREFIX32 = 0x70002u,
};

enum coruna90001_command {
    CORUNA90001_CMD_SELF_PREPARE = 13,
    CORUNA90001_CMD_TASK_PORT_PREPARE = 22,
    CORUNA90001_CMD_PMAP_BOUNDS = 38,
    CORUNA90001_CMD_40000010 = 0x40000010u,
    CORUNA90001_CMD_STAGE_1B_SET = 0x4000001Bu,
    CORUNA90001_CMD_STAGE_1B_QUERY = 0xC000001Bu,
};

enum coruna90000_selector {
    CORUNA90000_SEL_APPLY_IOKIT_USERCLIENT_CLASSES = 0x40000010u,
    CORUNA90000_SEL_STAGE_1B_SET = 0x4000001Bu,
    CORUNA90000_SEL_STAGE_1B_QUERY = 0xC000001Bu,
};

enum coruna90000_stage1b_cap_bit {
    CORUNA90000_STAGE1B_CAP_BIT_0 = 0x1,
    CORUNA90000_STAGE1B_CAP_BIT_1 = 0x2,
    CORUNA90000_STAGE1B_CAP_BIT_2 = 0x4,
    CORUNA90000_STAGE1B_CAP_BIT_3 = 0x8,
};

enum coruna_blob_magic {
    CORUNA_CONTAINER_MAGIC = 0xF00DBEEF,
    CORUNA_SELECTOR_MAGIC = 0x12345678,
    CORUNA_MODE_MAGIC = 0xDEADD00F,
};

enum coruna_bootstrap_offset {
    CORUNA_CTX_SLOT_LOAD_IMAGE = 0x30,
    CORUNA_CTX_SLOT_RESOLVE_SYMBOL = 0x38,
    CORUNA_CTX_SLOT_UNLOAD_IMAGE = 0x130,

    CORUNA_CTX_WRAPPER_STAGE_RECORD = 0xE8,
    CORUNA_CTX_WRAPPER_LOAD_RECORD = 0xF8,
    CORUNA_CTX_WRAPPER_UNLOAD_RECORD = 0x100,
    CORUNA_CTX_WRAPPER_GET_HANDLE = 0x108,
    CORUNA_CTX_WRAPPER_FETCH_RECORD = 0x110,
};

struct coruna_container_header {
    uint32_t magic;
    uint32_t count;
};

struct coruna_container_entry {
    uint32_t f1;
    uint32_t f2;
    uint32_t data_offset;
    uint32_t size;
};

struct coruna_selector_record_disk {
    uint32_t selector_key;
    uint8_t prefix32[32];
    char filename[64];
};

struct coruna_selector_blob_disk {
    uint32_t magic;
    uint32_t field_04;
    char base_path[256];
    uint32_t count;
    struct coruna_selector_record_disk records[];
};

struct coruna_selector_blob_view {
    const struct coruna_selector_blob_disk *blob;
    size_t byte_size;
};

struct coruna_mode_blob_view {
    const uint8_t *bytes;
    size_t byte_size;
    uint32_t raw_flags_04;
    bool enabled;
    uint32_t ttl_seconds;
    uint32_t field_0c;
    uint32_t field_10;
    uint32_t field_14;
    uint32_t field_18;
    uint32_t string_offset;
    uint32_t string_length;
    const char *payload_name;
};

struct coruna_kernel_version {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
};

struct coruna90000_state;
struct coruna90001_session;

struct coruna90000_batch_op {
    uint32_t opcode;
    uint32_t reserved_04;
    uint64_t argument;
};

struct coruna90000_stage1b_request {
    uint32_t task_port;
    /*
     * The live driver stores these three bytes into a task-local 32-bit flag
     * word, but the byte-to-bit mapping changes across kernel families.
     * `flag_06` is the byte used by the recovered `0x80000` callers when
     * `dyldVersionNumber >= 900.0`.
     */
    uint8_t flag_04;
    uint8_t flag_05;
    uint8_t flag_06;
    uint8_t reserved_07;
};

struct coruna90000_driver_object {
    /* Preserved leading halfwords; semantic meaning is not yet pinned down. */
    uint16_t header_word_00;
    uint16_t header_word_02;
    uint32_t reserved_04;
    uint64_t reserved_08;
    int64_t (*destroy)(struct coruna90000_driver_object *self);
    int64_t (*create_state)(
        struct coruna90000_driver_object *self,
        int64_t unused,
        struct coruna90000_state **out_state);
    int64_t (*refresh_state)(
        struct coruna90000_driver_object *self,
        struct coruna90000_state *state);
    int64_t (*dispatch_state)(
        struct coruna90000_driver_object *self,
        struct coruna90000_state *state,
        int64_t argument);
    int64_t (*release_state)(
        struct coruna90000_driver_object *self,
        struct coruna90000_state *state);
    int64_t (*get_cached_status)(
        struct coruna90000_driver_object *self,
        struct coruna90000_state *state,
        uint32_t *out_status);
    int64_t (*dispatch_batch)(
        struct coruna90000_driver_object *self,
        struct coruna90000_state **state_inout,
        const struct coruna90000_batch_op *ops,
        uint32_t op_count,
        int fail_fast);
    int64_t (*get_kernel_version)(
        struct coruna90000_driver_object *self,
        struct coruna_kernel_version *out_version);
};

struct coruna90001_driver_object {
    /* Preserved leading halfwords; semantic meaning is not yet pinned down. */
    uint16_t header_word_00;
    uint16_t header_word_02;
    uint32_t reserved_04;
    uint64_t reserved_08;
    int64_t (*destroy)(struct coruna90001_driver_object *self);
    int64_t (*create_session)(
        struct coruna90001_driver_object *self,
        uint64_t argument,
        struct coruna90001_session **out_session);
    int64_t (*destroy_session)(
        struct coruna90001_driver_object *self,
        struct coruna90001_session *session);
    int64_t (*dispatch_command)(
        struct coruna90001_driver_object *self,
        struct coruna90001_session *session,
        uint64_t command,
        void *arg_or_out);
    int64_t (*secondary_state_op)(
        struct coruna90001_driver_object *self,
        struct coruna90001_session *session,
        void *arg_or_out);
    int64_t (*get_cached_status)(
        struct coruna90001_driver_object *self,
        struct coruna90001_session *session,
        uint32_t *out_status);
    int64_t (*dispatch_batch)(
        struct coruna90001_driver_object *self,
        struct coruna90001_session **session_inout,
        const struct coruna90000_batch_op *ops,
        uint32_t op_count,
        int fail_fast);
    int64_t (*get_kernel_version)(
        struct coruna90001_driver_object *self,
        struct coruna_kernel_version *out_version);
};

struct coruna90001_helper_wrapper {
    uint64_t image_handle;
    struct coruna90001_driver_object *object;
};

struct coruna50000_installed_callbacks {
    int64_t (*load_image)(
        void *bootstrap_ctx,
        const void *image_bytes,
        uint32_t image_size,
        void **out_loaded_image);
    int64_t (*resolve_symbol)(
        void *bootstrap_ctx,
        void *loaded_image,
        const char *symbol_name,
        void **out_symbol);
    int64_t (*unload_image)(
        void *bootstrap_ctx,
        void *loaded_image);
};

struct coruna80000_thread_pack {
    const void *driver_object;
    uint8_t join_worker;
    uint8_t reserved_09[7];
    void *payload_bytes;
    uint32_t payload_size;
    uint32_t reserved_1c;
    void *record_70003_string;
    void *record_70004_string;
    void *record_70006_string;
};

size_t coruna_selector_blob_expected_size(uint32_t count);
bool coruna_selector_blob_view_init(
    struct coruna_selector_blob_view *out_view,
    const void *bytes,
    size_t byte_size);
const struct coruna_selector_record_disk *coruna_selector_find_record(
    const struct coruna_selector_blob_view *view,
    uint32_t selector_key);

bool coruna_mode_blob_view_init(
    struct coruna_mode_blob_view *out_view,
    const void *bytes,
    size_t byte_size);

bool coruna90000_driver_object_validate(const struct coruna90000_driver_object *object);
bool coruna90001_driver_object_validate(const struct coruna90001_driver_object *object);

int64_t coruna90000_destroy(struct coruna90000_driver_object *object);
int64_t coruna90000_create_state(
    struct coruna90000_driver_object *object,
    struct coruna90000_state **out_state);
int64_t coruna90000_refresh_state(
    struct coruna90000_driver_object *object,
    struct coruna90000_state *state);
int64_t coruna90000_dispatch_state(
    struct coruna90000_driver_object *object,
    struct coruna90000_state *state,
    int64_t argument);
int64_t coruna90000_release_state(
    struct coruna90000_driver_object *object,
    struct coruna90000_state *state);
int64_t coruna90000_get_cached_status(
    struct coruna90000_driver_object *object,
    struct coruna90000_state *state,
    uint32_t *out_status);
int64_t coruna90000_dispatch_batch(
    struct coruna90000_driver_object *object,
    struct coruna90000_state **state_inout,
    const struct coruna90000_batch_op *ops,
    uint32_t op_count,
    int fail_fast);
int64_t coruna90000_get_kernel_version(
    struct coruna90000_driver_object *object,
    struct coruna_kernel_version *out_version);

int64_t coruna90001_create_session(
    struct coruna90001_driver_object *object,
    uint64_t argument,
    struct coruna90001_session **out_session);
int64_t coruna90001_destroy_session(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session);
int64_t coruna90001_dispatch_command(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    uint64_t command,
    void *arg_or_out);
int64_t coruna90001_dispatch_self_prepare(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session);
int64_t coruna90001_dispatch_task_port_prepare(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    void *task_port_state);
int64_t coruna90001_dispatch_pmap_bounds(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session);
int64_t coruna90001_dispatch_stage_1b_set(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    void *state_bytes);
int64_t coruna90001_dispatch_stage_1b_query(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    void *out_state_flags);
int64_t coruna90001_secondary_state_op(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    void *arg_or_out);
int64_t coruna90001_get_cached_status(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    uint32_t *out_status);
int64_t coruna90001_dispatch_batch(
    struct coruna90001_driver_object *object,
    struct coruna90001_session **session_inout,
    const struct coruna90000_batch_op *ops,
    uint32_t op_count,
    int fail_fast);
int64_t coruna90001_get_kernel_version(
    struct coruna90001_driver_object *object,
    struct coruna_kernel_version *out_version);

#ifdef __cplusplus
}
#endif

#endif
