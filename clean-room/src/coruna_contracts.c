#include "coruna_contracts.h"

#include <string.h>

_Static_assert(sizeof(struct coruna_container_header) == 0x8, "container header size drift");
_Static_assert(sizeof(struct coruna_container_entry) == 0x10, "container entry size drift");
_Static_assert(sizeof(struct coruna_selector_record_disk) == 0x64, "selector record size drift");
_Static_assert(sizeof(struct coruna90000_driver_object) == 0x50, "0x90000 driver size drift");
_Static_assert(sizeof(struct coruna90001_driver_object) == 0x50, "0x90001 driver size drift");
_Static_assert(sizeof(struct coruna90001_helper_wrapper) == 0x10, "0x90001 helper wrapper size drift");
_Static_assert(sizeof(struct coruna80000_thread_pack) == 0x38, "0x80000 thread pack size drift");

static bool coruna_has_nul(const char *bytes, size_t max_len)
{
    return memchr(bytes, '\0', max_len) != NULL;
}

static bool coruna_callbacks_present_90000(const struct coruna90000_driver_object *object)
{
    return object->destroy != NULL
        && object->create_state != NULL
        && object->refresh_state != NULL
        && object->dispatch_state != NULL
        && object->release_state != NULL
        && object->get_cached_status != NULL
        && object->dispatch_batch != NULL
        && object->get_kernel_version != NULL;
}

static bool coruna_callbacks_present_90001(const struct coruna90001_driver_object *object)
{
    return object->destroy != NULL
        && object->create_session != NULL
        && object->destroy_session != NULL
        && object->dispatch_command != NULL
        && object->secondary_state_op != NULL
        && object->get_cached_status != NULL
        && object->dispatch_batch != NULL
        && object->get_kernel_version != NULL;
}

size_t coruna_selector_blob_expected_size(uint32_t count)
{
    return offsetof(struct coruna_selector_blob_disk, records)
        + ((size_t)count * sizeof(struct coruna_selector_record_disk));
}

bool coruna_selector_blob_view_init(
    struct coruna_selector_blob_view *out_view,
    const void *bytes,
    size_t byte_size)
{
    const struct coruna_selector_blob_disk *blob;
    uint32_t count;
    size_t expected_size;
    uint32_t index;

    if (out_view == NULL || bytes == NULL) {
        return false;
    }

    if (byte_size < offsetof(struct coruna_selector_blob_disk, records)) {
        return false;
    }

    blob = (const struct coruna_selector_blob_disk *)bytes;
    if (blob->magic != CORUNA_SELECTOR_MAGIC) {
        return false;
    }

    count = blob->count;
    expected_size = coruna_selector_blob_expected_size(count);
    if (expected_size > byte_size) {
        return false;
    }

    if (!coruna_has_nul(blob->base_path, sizeof(blob->base_path))) {
        return false;
    }

    for (index = 0; index < count; index++) {
        if (!coruna_has_nul(blob->records[index].filename, sizeof(blob->records[index].filename))) {
            return false;
        }
    }

    out_view->blob = blob;
    out_view->byte_size = expected_size;
    return true;
}

const struct coruna_selector_record_disk *coruna_selector_find_record(
    const struct coruna_selector_blob_view *view,
    uint32_t selector_key)
{
    uint32_t index;

    if (view == NULL || view->blob == NULL) {
        return NULL;
    }

    for (index = 0; index < view->blob->count; index++) {
        if (view->blob->records[index].selector_key == selector_key) {
            return &view->blob->records[index];
        }
    }

    return NULL;
}

bool coruna_mode_blob_view_init(
    struct coruna_mode_blob_view *out_view,
    const void *bytes,
    size_t byte_size)
{
    const uint32_t *words;
    const uint8_t *raw;

    if (out_view == NULL || bytes == NULL) {
        return false;
    }

    if (byte_size < 0x1c) {
        return false;
    }

    words = (const uint32_t *)bytes;
    raw = (const uint8_t *)bytes;
    if (words[0] != CORUNA_MODE_MAGIC) {
        return false;
    }

    out_view->bytes = raw;
    out_view->byte_size = byte_size;
    out_view->raw_flags_04 = words[1];
    out_view->enabled = raw[5] != 0;
    out_view->ttl_seconds = words[2];
    out_view->field_0c = words[3];
    out_view->field_10 = words[4];
    out_view->field_14 = words[5];
    out_view->field_18 = words[6];
    return true;
}

bool coruna90000_driver_object_validate(const struct coruna90000_driver_object *object)
{
    if (object == NULL) {
        return false;
    }

    if (object->abi_major < 2 || object->abi_minor < 2) {
        return false;
    }

    return coruna_callbacks_present_90000(object);
}

bool coruna90001_driver_object_validate(const struct coruna90001_driver_object *object)
{
    if (object == NULL) {
        return false;
    }

    if (object->abi_major < 2 || object->abi_minor < 2) {
        return false;
    }

    return coruna_callbacks_present_90001(object);
}

int64_t coruna90000_destroy(struct coruna90000_driver_object *object)
{
    if (!coruna90000_driver_object_validate(object)) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->destroy(object);
}

int64_t coruna90000_create_state(
    struct coruna90000_driver_object *object,
    struct coruna90000_state **out_state)
{
    if (!coruna90000_driver_object_validate(object) || out_state == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->create_state(object, 0, out_state);
}

int64_t coruna90000_refresh_state(
    struct coruna90000_driver_object *object,
    struct coruna90000_state *state)
{
    if (!coruna90000_driver_object_validate(object) || state == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->refresh_state(object, state);
}

int64_t coruna90000_dispatch_state(
    struct coruna90000_driver_object *object,
    struct coruna90000_state *state,
    int64_t argument)
{
    if (!coruna90000_driver_object_validate(object) || state == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->dispatch_state(object, state, argument);
}

int64_t coruna90000_release_state(
    struct coruna90000_driver_object *object,
    struct coruna90000_state *state)
{
    if (!coruna90000_driver_object_validate(object) || state == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->release_state(object, state);
}

int64_t coruna90000_get_cached_status(
    struct coruna90000_driver_object *object,
    struct coruna90000_state *state,
    uint32_t *out_status)
{
    if (!coruna90000_driver_object_validate(object) || state == NULL || out_status == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->get_cached_status(object, state, out_status);
}

int64_t coruna90000_dispatch_batch(
    struct coruna90000_driver_object *object,
    struct coruna90000_state **state_inout,
    const struct coruna90000_batch_op *ops,
    uint32_t op_count,
    int fail_fast)
{
    if (!coruna90000_driver_object_validate(object) || state_inout == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    if ((ops == NULL) != (op_count == 0)) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->dispatch_batch(object, state_inout, ops, op_count, fail_fast);
}

int64_t coruna90000_get_kernel_version(
    struct coruna90000_driver_object *object,
    struct coruna_kernel_version *out_version)
{
    if (!coruna90000_driver_object_validate(object) || out_version == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->get_kernel_version(object, out_version);
}

int64_t coruna90001_create_session(
    struct coruna90001_driver_object *object,
    uint64_t argument,
    struct coruna90001_session **out_session)
{
    if (!coruna90001_driver_object_validate(object) || out_session == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->create_session(object, argument, out_session);
}

int64_t coruna90001_destroy_session(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session)
{
    if (!coruna90001_driver_object_validate(object) || session == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->destroy_session(object, session);
}

int64_t coruna90001_dispatch_command(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    uint64_t command,
    void *arg_or_out)
{
    if (!coruna90001_driver_object_validate(object) || session == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->dispatch_command(object, session, command, arg_or_out);
}

int64_t coruna90001_dispatch_self_prepare(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session)
{
    return coruna90001_dispatch_command(
        object,
        session,
        CORUNA90001_CMD_SELF_PREPARE,
        NULL);
}

int64_t coruna90001_dispatch_task_port_prepare(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    void *task_port_state)
{
    return coruna90001_dispatch_command(
        object,
        session,
        CORUNA90001_CMD_TASK_PORT_PREPARE,
        task_port_state);
}

int64_t coruna90001_dispatch_pmap_bounds(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session)
{
    return coruna90001_dispatch_command(
        object,
        session,
        CORUNA90001_CMD_PMAP_BOUNDS,
        NULL);
}

int64_t coruna90001_dispatch_stage_1b_set(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    void *state_bytes)
{
    return coruna90001_dispatch_command(
        object,
        session,
        CORUNA90001_CMD_STAGE_1B_SET,
        state_bytes);
}

int64_t coruna90001_dispatch_stage_1b_query(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    void *out_state_flags)
{
    return coruna90001_dispatch_command(
        object,
        session,
        CORUNA90001_CMD_STAGE_1B_QUERY,
        out_state_flags);
}

int64_t coruna90001_secondary_state_op(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    void *arg_or_out)
{
    if (!coruna90001_driver_object_validate(object) || session == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->secondary_state_op(object, session, arg_or_out);
}

int64_t coruna90001_get_cached_status(
    struct coruna90001_driver_object *object,
    struct coruna90001_session *session,
    uint32_t *out_status)
{
    if (!coruna90001_driver_object_validate(object) || session == NULL || out_status == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->get_cached_status(object, session, out_status);
}

int64_t coruna90001_dispatch_batch(
    struct coruna90001_driver_object *object,
    struct coruna90001_session **session_inout,
    const struct coruna90000_batch_op *ops,
    uint32_t op_count,
    int fail_fast)
{
    if (!coruna90001_driver_object_validate(object) || session_inout == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    if ((ops == NULL) != (op_count == 0)) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->dispatch_batch(object, session_inout, ops, op_count, fail_fast);
}

int64_t coruna90001_get_kernel_version(
    struct coruna90001_driver_object *object,
    struct coruna_kernel_version *out_version)
{
    if (!coruna90001_driver_object_validate(object) || out_version == NULL) {
        return CORUNA_STATUS_INVALID_ARGUMENT;
    }

    return object->get_kernel_version(object, out_version);
}
