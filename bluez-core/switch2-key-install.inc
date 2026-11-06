/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Included in adapter.c: NEVER use LOAD_LONG_TERM_KEYS for live enrollment.
 * The experimental kernel command adds one public, central, legacy LTK and
 * rejects replacement. Its UUID/version handshake is mandatory. */
#include "switch2-key-install.h"
#define SWITCH2_MGMT_KEY 0x0100
static const uint8_t switch2_key_magic[16] = {
    0x85,0x19,0xa2,0x14,0x69,0x2b,0x43,0xc5,
    0xb8,0x72,0x7e,0x06,0x58,0xe2,0x10,0x01
};
struct switch2_key_request {
    uint8_t magic[16], operation, address[6], key[16];
} __attribute__((packed));
struct switch2_key_pending {
    btd_switch2_key_cb callback;
    void *data;
    GDestroyNotify destroy;
    bool completed;
};
static void switch2_key_pending_free(void *data)
{
    struct switch2_key_pending *p = data;
    if (!p->completed) p->callback(-ECANCELED, p->data);
    if (p->destroy) p->destroy(p->data);
    g_free(p);
}
static void switch2_key_complete(uint8_t status, uint16_t len,
                                const void *param, void *data)
{
    struct switch2_key_pending *p = data;
    int error = 0;
    if (status == MGMT_STATUS_UNKNOWN_COMMAND || status == MGMT_STATUS_NOT_SUPPORTED)
        error = -EOPNOTSUPP;
    else if (status == MGMT_STATUS_ALREADY_PAIRED)
        error = -EEXIST;
    else if (status == MGMT_STATUS_INVALID_INDEX)
        error = -ENODEV;
    else if (status == MGMT_STATUS_BUSY)
        error = -EBUSY;
    else if (status)
        error = -EIO;
    else if (len != sizeof(switch2_key_magic) || !param ||
             memcmp(param, switch2_key_magic, sizeof(switch2_key_magic)))
        error = -EPROTO;
    p->completed = true;
    p->callback(error, p->data);
}
static bool switch2_key_send(struct btd_adapter *adapter, const bdaddr_t *peer,
                            const uint8_t *key, btd_switch2_key_cb callback,
                            void *data, GDestroyNotify destroy)
{
    struct switch2_key_request request = {0};
    struct switch2_key_pending *p = g_new0(struct switch2_key_pending, 1);
    unsigned int id;
    memcpy(request.magic, switch2_key_magic, sizeof(request.magic));
    if (peer && key) {
        request.operation = 1;
        memcpy(request.address, peer, 6);
        memcpy(request.key, key, 16);
    }
    p->callback = callback;
    p->data = data;
    p->destroy = destroy;
    id = mgmt_send_timeout(adapter->mgmt, SWITCH2_MGMT_KEY, adapter->dev_id,
            sizeof(request), &request, switch2_key_complete, p,
            switch2_key_pending_free, 5);
    explicit_bzero(&request, sizeof(request));
    if (!id) g_free(p); /* caller retains data on enqueue failure */
    return id != 0;
}
bool btd_switch2_key_probe(struct btd_adapter *adapter,
        btd_switch2_key_cb callback, void *data, GDestroyNotify destroy)
{
    return switch2_key_send(adapter, NULL, NULL, callback, data, destroy);
}
bool btd_switch2_key_install(struct btd_device *device, const uint8_t key[16],
        btd_switch2_key_cb callback, void *data, GDestroyNotify destroy)
{
    if (device_get_le_address_type(device) != BDADDR_LE_PUBLIC)
        return false;
    return switch2_key_send(device_get_adapter(device), device_get_address(device),
                           key, callback, data, destroy);
}

int btd_switch2_availability(struct btd_adapter *adapter)
{
    if (rfkill_get_blocked(adapter->dev_id) > 0) return -ERFKILL;
    return btd_adapter_get_powered(adapter) ? 0 : -EHOSTDOWN;
}
