/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Private BlueZ adapter API. Completion is asynchronous; keys never leave BlueZ. */
#ifndef SWITCH2_KEY_INSTALL_H
#define SWITCH2_KEY_INSTALL_H
struct btd_adapter;
struct btd_device;
int btd_switch2_availability(struct btd_adapter *adapter);
typedef void (*btd_switch2_key_cb)(int error, void *data);
bool btd_switch2_key_probe(struct btd_adapter *adapter,
        btd_switch2_key_cb callback, void *data, GDestroyNotify destroy);
bool btd_switch2_key_install(struct btd_device *device, const uint8_t key[16],
        btd_switch2_key_cb callback, void *data, GDestroyNotify destroy);
#endif
