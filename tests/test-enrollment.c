/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Exercise the actual enrollment state machine with a fake GATT transport.
 * Real GLib file persistence and OpenSSL crypto, no Bluetooth hardware. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include "switch2-pairing.h"
#define SWITCH2_BUILD_ID "unit-test"
#define BDADDR_LE_PUBLIC 1
#define BDADDR_LE_RANDOM 2
static void discard_log(const char *format, ...) { (void)format; }
#define info(...) discard_log(__VA_ARGS__)
#define error(...) discard_log(__VA_ARGS__)
typedef struct { uint8_t b[6]; } bdaddr_t;
struct btd_adapter { bdaddr_t address; };
struct btd_device { bdaddr_t address; };
struct switch2_session {
    struct btd_adapter *adapter;
    struct btd_device *device;
    void *gatt;
    char address[18];
    bool stopping, enroll_checked, enroll_active, enroll_key_ready;
    unsigned int stop_source, enroll_timeout, enroll_write_id;
    uint8_t enroll_step, enroll_component[16], enroll_challenge[16], enroll_key[16];
};
static char root[PATH_MAX];
static bool deny_storage, fail_write;
static int sent_step, attaches;
static const bdaddr_t *btd_adapter_get_address(struct btd_adapter *a) { return &a->address; }
static const bdaddr_t *device_get_address(struct btd_device *d) { return &d->address; }
static const char *btd_adapter_get_storage_dir(struct btd_adapter *a) { (void)a; return "adapter"; }
static uint8_t btd_adapter_get_address_type(struct btd_adapter *a) { (void)a; return 1; }
static uint8_t device_get_le_address_type(struct btd_device *d) { (void)d; return 1; }
static int ba2str(const bdaddr_t *b, char *s) {
    return sprintf(s, "%02X:%02X:%02X:%02X:%02X:%02X", b->b[5], b->b[4], b->b[3], b->b[2], b->b[1], b->b[0]);
}
static int create_filename(char *path, size_t size, const char *format, ...) {
    va_list ap;
    int n = snprintf(path, size, "%s", deny_storage ? "/nonexistent-enrollment-test-dir" : root);
    va_start(ap, format);
    vsnprintf(path + n, size - n, format, ap);
    va_end(ap);
    return 0;
}
static void switch2_schedule_stop(struct switch2_session *s) { s->stop_source = 1; }
static void switch2_maybe_attach_kernel(struct switch2_session *s) { (void)s; attaches++; }
static uint16_t bt_gatt_client_get_mtu(void *g) { (void)g; return 247; }
static unsigned int bt_gatt_client_write_without_response(void *g, uint16_t h,
        bool sign, const uint8_t *v, uint16_t len) {
    (void)g; (void)sign;
    assert(h == 0x16 && len >= 26 && v[17] == 0x15);
    if (fail_write) return 0;
    sent_step = v[20];
    return 1;
}
static unsigned int bt_gatt_client_write_value(void *g, uint16_t h,
        const uint8_t *v, uint16_t len, void (*cb)(bool, uint8_t, void *),
        void *data, void *destroy) {
    (void)g; (void)cb; (void)data; (void)destroy;
    assert(h == 5 && len == 2 && v[0] == 1 && v[1] == 0);
    return 1;
}
#include "switch2-enrollment.inc"

static void arm(struct switch2_session *s) {
    char path[PATH_MAX];
    switch2_enroll_path(s, path, "switch2-enroll.request");
    assert(g_file_set_contents_full(path, "armed", 5, G_FILE_SET_CONTENTS_CONSISTENT, 0600, NULL));
    assert(switch2_enroll_begin(s));
    assert(s->enroll_active && sent_step == 0 && attaches == 0);
    switch2_enroll_bootstrap(true, 0, s);
    assert(sent_step == 1);
}
static void through_key(struct switch2_session *s) {
    uint8_t reply[25] = {0x15,1,1,1,0x10,0x78,0,0,1,4,1};
    memcpy(reply + 11, device_get_address(s->device), 6);
    switch2_enroll_reply(s, reply, 17);
    assert(sent_step == 4 && !s->enroll_key_ready);
    reply[3] = 4;
    memset(reply + 9, 0x23, 16);
    switch2_enroll_reply(s, reply, 25);
    assert(sent_step == 2 && s->enroll_key_ready);
}
static void challenge(struct switch2_session *s, bool corrupt) {
    uint8_t reply[25] = {0x15,1,1,2,0x10,0x78,0,0,1}, out[16];
    assert(switch2_pair_encrypt_le(s->enroll_key, s->enroll_challenge, out));
    for (int i=0; i<16; i++) reply[9+i] = out[15-i];
    if (corrupt) reply[9] ^= 1;
    switch2_enroll_reply(s, reply, sizeof(reply));
}
int main(void) {
    struct btd_adapter adapter = {{{1,2,3,4,5,6}}};
    struct btd_device device = {{{6,5,4,3,2,1}}};
    char *tmp = g_dir_make_tmp("switch2-enroll-XXXXXX", NULL), folder[PATH_MAX];
    assert(tmp); snprintf(root, sizeof(root), "%s", tmp); g_free(tmp);
    snprintf(folder, sizeof(folder), "%s/adapter/01:02:03:04:05:06", root);
    assert(g_mkdir_with_parents(folder, 0700) == 0);
    for (int test=0; test<6; test++) {
        struct switch2_session s = {.adapter=&adapter, .device=&device};
        uint8_t reply[9] = {0x15,1,1,3,0x10,0x78,0,0,1};
        strcpy(s.address, "01:02:03:04:05:06");
        sent_step = attaches = 0; deny_storage = fail_write = false;
        assert(!switch2_enroll_begin(&s)); /* No request never enrolls. */
        s.enroll_checked = false;
        arm(&s);
        if (test == 4) {
            switch2_enroll_reply(&s, reply, sizeof(reply)); /* stale finalize */
            assert(sent_step == 1 && !s.stop_source);
            reply[3] = 1;
            switch2_enroll_reply(&s, reply, sizeof(reply)); /* short address */
            assert(s.stop_source && sent_step == 1);
        } else if (test == 5) {
            g_source_remove(s.enroll_timeout);
            switch2_enroll_timeout(&s);
            assert(s.stop_source && attaches == 0);
        } else {
            through_key(&s);
            if (test == 2) deny_storage = true;
            if (test == 3) fail_write = true;
            challenge(&s, test == 1);
            if (test == 0) {
                assert(sent_step == 3 && attaches == 0);
                char path[PATH_MAX]; GKeyFile *f = g_key_file_new();
                switch2_enroll_path(&s, path, "switch2-enrollment");
                assert(g_key_file_load_from_file(f, path, 0, NULL));
                char *state = g_key_file_get_string(f, "Enrollment", "State", NULL);
                assert(!strcmp(state, "commit-pending")); g_free(state); g_key_file_free(f);
                switch2_enroll_reply(&s, reply, sizeof(reply));
                assert(attaches == 1 && !s.enroll_active);
            } else {
                assert(s.stop_source && sent_step == 2 && attaches == 0);
            }
        }
        if (s.enroll_timeout) g_source_remove(s.enroll_timeout);
        deny_storage = false;
    }
    puts("PASS: enrollment success, durable-before-commit, corrupt challenge, storage/write failure, stale/truncated replies, timeout");
    return 0;
}
