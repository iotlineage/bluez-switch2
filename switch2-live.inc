/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Live provider. Included in switch2.c after the transport teardown helpers. */
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>
#include <pwd.h>
#include "src/dbus-common.h"
#include "src/switch2-key-install.h"

#define S2_PATH "/org/bluez/ns_os/switch2"
#define S2_IFACE "org.ns_os.Switch2Enrollment1"
#define S2_MAX_OPS 64
#define S2_MAX_ACTIVE 4
#define S2_RETAIN_MS 300000

struct s2_device;
struct s2_operation {
    struct s2_device *target;
    char *path, *owner, *request;
    const char *phase, *error;
    uint64_t revision, deadline, finished;
    uint32_t timeout;
    guint owner_watch;
    bool cancel, transmitted, acknowledged, durable, active, terminal;
    bool io_pending, removed, recovering, activation_wait;
    uint64_t activation_until;
    uint8_t step, component[16], challenge[16], key[16];
};
struct s2_device {
    struct btd_device *device;
    struct btd_adapter *adapter;
    char *path, *adapter_path, *journal, *legacy;
    char address[18], host[18];
    unsigned int refs;
    int directory_fd;
    bool removed, loading, known, acknowledged, durable, active, uncertain;
    bool capability, probe_pending, observed, legacy_journal, recovery_attempted;
    uint8_t key[16];
    struct s2_operation *operation;
};
static GSList *s2_devices, *s2_operations;
static DBusConnection *s2_bus;
static char *s2_instance;
static uint64_t s2_serial;
static guint s2_tick_id;
static uid_t s2_service_uid = (uid_t)-1;
static bool s2_exiting;
static GThreadPool *s2_storage_pool;
static void s2_advance(struct s2_operation *op);
static void s2_recover(struct s2_device *d);
static void s2_fail(struct s2_operation *op, const char *code);
static void s2_try_session(struct switch2_session *s);
static void s2_connect(struct s2_operation *op);

static uint64_t s2_now(void) { return g_get_monotonic_time() / 1000; }
static struct s2_device *s2_ref(struct s2_device *d) { d->refs++; return d; }
static void s2_unref(void *data)
{
    struct s2_device *d = data;
    if (--d->refs) return;
    if (d->directory_fd >= 0) close(d->directory_fd);
    btd_device_unref(d->device);
    btd_adapter_unref(d->adapter);
    g_free(d->path); g_free(d->adapter_path); g_free(d->journal); g_free(d->legacy);
    explicit_bzero(d->key, sizeof(d->key));
    g_free(d);
}
static struct s2_device *s2_find(struct btd_device *device)
{
    GSList *l;
    for (l = s2_devices; l; l = l->next) {
        struct s2_device *d = l->data;
        if (d->device == device && !d->removed) return d;
    }
    return NULL;
}
static const char *s2_registration(struct s2_device *d)
{
    if (d->loading) return "unknown";
    if (d->acknowledged && d->durable && d->active) return "registered";
    if (d->known || d->uncertain) return "recovery_required";
    if (device_is_bonded(d->device, BDADDR_LE_PUBLIC)) return "unknown";
    return "unregistered";
}
static void s2_string(DBusMessageIter *dict, const char *name, const char *value)
{ dict_append_entry(dict, name, DBUS_TYPE_STRING, &value); }
static void s2_object(DBusMessageIter *dict, const char *name, const char *value)
{ dict_append_entry(dict, name, DBUS_TYPE_OBJECT_PATH, &value); }
static void s2_bool(DBusMessageIter *dict, const char *name, bool value)
{ dbus_bool_t v = value; dict_append_entry(dict, name, DBUS_TYPE_BOOLEAN, &v); }
static void s2_u64(DBusMessageIter *dict, const char *name, uint64_t value)
{ dict_append_entry(dict, name, DBUS_TYPE_UINT64, &value); }
static void s2_state(DBusMessageIter *iter, struct s2_operation *op)
{
    DBusMessageIter dict;
    struct s2_device *d = op->target;
    dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{sv}", &dict);
    s2_object(&dict, "Operation", op->path);
    s2_string(&dict, "InstanceId", s2_instance);
    s2_string(&dict, "RequestId", op->request);
    s2_string(&dict, "Owner", op->owner);
    s2_object(&dict, "Device", d->path);
    s2_object(&dict, "Adapter", d->adapter_path);
    s2_string(&dict, "Phase", op->phase);
    s2_u64(&dict, "Revision", op->revision);
    s2_u64(&dict, "DeadlineMonotonicMs", op->deadline);
    s2_bool(&dict, "CancelRequested", op->cancel);
    s2_bool(&dict, "ControllerAcknowledged", op->acknowledged);
    s2_bool(&dict, "AssociationDurable", op->durable);
    s2_bool(&dict, "AssociationActive", op->active);
    s2_string(&dict, "RegistrationState", s2_registration(d));
    s2_bool(&dict, "Connected", !d->removed && btd_device_is_connected(d->device));
    s2_string(&dict, "ErrorCode", op->error ? op->error : "");
    /* Stable code is intentionally the entire public error; never GError text. */
    s2_string(&dict, "ErrorMessage", op->error ? op->error : "");
    dbus_message_iter_close_container(iter, &dict);
}
static void s2_publish(struct s2_operation *op, const char *phase)
{
    DBusMessage *msg;
    DBusMessageIter iter;
    op->phase = phase;
    op->revision++;
    if (!s2_bus || s2_exiting) return;
    msg = dbus_message_new_signal(S2_PATH, S2_IFACE, "OperationChanged");
    /* Directed signals: unrelated users cannot observe operation metadata. */
    dbus_message_set_destination(msg, op->owner);
    dbus_message_iter_init_append(msg, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &op->path);
    s2_state(&iter, op);
    g_dbus_send_message(s2_bus, msg);
}
static void s2_wipe(struct s2_operation *op)
{
    explicit_bzero(op->component, 16); explicit_bzero(op->challenge, 16);
    explicit_bzero(op->key, 16);
}
static void s2_finish(struct s2_operation *op, const char *phase, const char *error)
{
    if (op->terminal) {
        s2_publish(op, op->phase);
        if (!op->io_pending) s2_wipe(op);
        return;
    }
    op->error = error;
    op->terminal = true;
    op->finished = s2_now();
    if (op->transmitted && !(op->durable && op->active)) op->target->uncertain = true;
    if (op->target->operation == op) op->target->operation = NULL;
    s2_publish(op, phase);
    if (!op->io_pending) s2_wipe(op);
}
static void s2_fail(struct s2_operation *op, const char *code)
{
    struct switch2_session *s = switch2_find_session(op->target->device);
    s2_finish(op, "failed", code);
    if (s && !op->active) {
        switch2_schedule_stop(s);
        device_request_disconnect(op->target->device,NULL);
    }
}

/* Each bounded job owns immutable input. Only main-context completion touches
 * BlueZ objects. fsync/reads never execute on the Bluetooth dispatch loop. */
struct s2_io {
    struct s2_device *d;
    struct s2_operation *op;
    unsigned int action; /* 0 read, 1 intent, 2 acknowledged, 3 abort, 4 pin directory */
    int directory_fd;
    bool ok, present, acknowledged, malformed, legacy;
    uint8_t key[16];
};
static bool s2_parse_file(struct s2_io *job, const char *path, bool legacy)
{
    struct stat st;
    char text[8193] = {0}, *host=NULL, *peer=NULL, *state=NULL, *key=NULL;
    char *version=NULL, *line, *save=NULL;
    ssize_t size, total=0;
    bool ok=false, group=false;
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return false;
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode&077) ||
        st.st_size<0 || st.st_size>8192) goto out;
    while ((size=read(fd,text+total,8192-total))>0) {
        total+=size;
        if (total>=8192) break;
    }
    if (size<0 || total!=st.st_size || memchr(text,0,total)) goto out;
    for(line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) {
        char *equal;
        line=g_strstrip(line);
        if (!*line || *line=='#') continue;
        if (*line=='[') { group=!strcmp(line,legacy?"[Enrollment]":"[Association]"); continue; }
        if (!group || !(equal=strchr(line,'='))) continue;
        *equal++=0; line=g_strstrip(line); equal=g_strstrip(equal);
        char **field=!strcmp(line,"Adapter")?&host:!strcmp(line,"Peer")?&peer:
            !strcmp(line,"State")?&state:!strcmp(line,"KeyLE")?&key:
            !strcmp(line,"Version")?&version:NULL;
        if (field) { if (*field) goto out; *field=equal; }
    }
    if (!host || !peer || !state || strcmp(host,job->d->host) || strcmp(peer,job->d->address)) goto out;
    if (!legacy && (!version || strcmp(version,"1"))) goto out;
    if (!strcmp(state,"aborted") && !legacy) { job->present=false; ok=true; goto out; }
    if (!key || strlen(key)!=32) goto out;
    for (int i=0;i<16;i++) {
        int a=g_ascii_xdigit_value(key[2*i]), b=g_ascii_xdigit_value(key[2*i+1]);
        if(a<0 || b<0) goto out;
        job->key[i]=(a<<4)|b;
    }
    job->acknowledged=!strcmp(state,legacy?"complete":"acknowledged");
    if (!job->acknowledged && strcmp(state,"commit-pending")) goto out;
    job->legacy=legacy; ok=true;
 out:
    close(fd); explicit_bzero(text,sizeof(text)); return ok;
}
static bool s2_write_file(struct s2_io *job)
{
    char key[33]={0}, *text;
    bool ok;
    const char *state=job->action==1?"commit-pending":job->action==2?"acknowledged":"aborted";
    if(job->action!=3)
        for(int i=0;i<16;i++) sprintf(key+2*i,"%02X",job->key[i]);
    text=g_strdup_printf("[Association]\nVersion=1\nAdapter=%s\nPeer=%s\nState=%s\nKeyLE=%s\n",
                         job->d->host,job->d->address,state,key);
    char *path=g_strdup_printf("/proc/self/fd/%d/switch2-association",job->directory_fd);
    ok=job->directory_fd>=0 && g_file_set_contents_full(path,text,strlen(text),
        G_FILE_SET_CONTENTS_CONSISTENT|G_FILE_SET_CONTENTS_DURABLE,0600,NULL);
    g_free(path);
    explicit_bzero(key,sizeof(key)); explicit_bzero(text,strlen(text)); g_free(text);
    return ok;
}
static gboolean s2_io_done(void *data);
static void s2_io_worker(void *data, void *unused)
{
    struct s2_io *job = data;
    (void)unused;
    if (!job->action || job->action==4) {
        char *directory=g_path_get_dirname(job->d->journal);
        if (job->action==4 && job->directory_fd<0)
            g_mkdir_with_parents(directory,0700);
        if (job->directory_fd<0)
            job->directory_fd=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        g_free(directory);
        struct stat st;
        job->ok=job->directory_fd>=0;
        if (job->ok && (fstat(job->directory_fd,&st) || st.st_uid || (st.st_mode&077)))
            job->ok=false;
        if (!job->action && job->directory_fd<0 && errno==ENOENT) job->ok=true;
        if (!job->action && job->directory_fd>=0 && job->ok) {
            char *path=g_strdup_printf("/proc/self/fd/%d/switch2-association",job->directory_fd);
            bool legacy=false;
            if (lstat(path,&st)<0 && errno==ENOENT) {
                g_free(path); path=g_strdup_printf("/proc/self/fd/%d/switch2-enrollment",job->directory_fd);
                legacy=true;
            }
            if (!lstat(path,&st)) {
                job->present=true;
                job->ok=s2_parse_file(job,path,legacy);
            } else job->ok=errno==ENOENT;
            g_free(path);
        }
        job->malformed=!job->ok;
    } else job->ok = s2_write_file(job);
    g_idle_add(s2_io_done, job);
}
static void s2_io_start(struct s2_device *d, struct s2_operation *op, unsigned int action)
{
    struct s2_io *job = g_new0(struct s2_io, 1);
    job->d = s2_ref(d); job->op = op; job->action = action;
    job->directory_fd=d->directory_fd>=0?dup(d->directory_fd):-1;
    if (op) { op->io_pending = true; memcpy(job->key, op->key, 16); }
    if (!g_thread_pool_push(s2_storage_pool, job, NULL))
        g_idle_add(s2_io_done,job);
}
static void s2_activated(int error, void *data)
{
    struct s2_operation *op = data;
    struct s2_device *d = op->target;
    op->io_pending = false;
    if (d->removed || s2_exiting) { s2_fail(op, "AdapterRemoved"); return; }
    if (error == -EBUSY && s2_now() < op->activation_until) {
        op->activation_wait = op->io_pending = true;
        return;
    }
    if (error) { s2_fail(op, error == -EEXIST ? "AssociationExists" : "ActivationFailed"); return; }
    d->active = op->active = true;
    d->uncertain = false;
    switch2_autoconnect_enable(d->adapter, d->device);
    device_set_ltk(d->device, d->key, true, 16);
    device_set_paired(d->device, BDADDR_LE_PUBLIC);
    device_set_bonded(d->device, BDADDR_LE_PUBLIC);
    btd_device_set_trusted(d->device, true);
    if (op->terminal) {
        /* A timed-out operation keeps its truthful terminal outcome. Status
         * records that bounded local reconciliation eventually succeeded. */
        s2_publish(op, op->phase);
        s2_wipe(op);
    } else s2_finish(op, "succeeded", NULL);
    struct switch2_session *s = switch2_find_session(d->device);
    if (s) switch2_maybe_attach_kernel(s);
}
static void s2_activate(struct s2_operation *op)
{
    if (op->target->removed) { s2_fail(op, "AdapterRemoved"); return; }
    if (!op->activation_until) op->activation_until = s2_now() + 5000;
    if (!op->terminal) s2_publish(op, "activating");
    op->io_pending = true;
    if (btd_device_is_connected(op->target->device)) {
        op->activation_wait = true;
        switch2_autoconnect_disable(op->target->adapter, op->target->device);
        device_request_disconnect(op->target->device, NULL);
        return;
    }
    op->activation_wait = false;
    if (!btd_switch2_key_install(op->target->device, op->key, s2_activated, op, NULL)) {
        op->io_pending = false; s2_fail(op, "ActivationFailed");
    }
}
static gboolean s2_io_done(void *data)
{
    struct s2_io *job = data;
    struct s2_device *d = job->d;
    struct s2_operation *op = job->op;
    if (op) op->io_pending = false;
    if (job->ok && job->directory_fd>=0 && d->directory_fd<0) {
        d->directory_fd=job->directory_fd; job->directory_fd=-1;
    }
    if (job->action==4) {
        if (!job->ok) s2_fail(op,"StorageFailed");
        else if (op->terminal || op->cancel || d->removed || s2_now()>=op->deadline)
            s2_finish(op,op->cancel?"cancelled":"timed_out",op->cancel?NULL:"Timeout");
        else s2_connect(op);
    } else if (!job->action) {
        d->loading = false;
        d->known = job->present;
        d->uncertain = job->malformed || (job->present && !job->acknowledged);
        if (job->ok && job->present) {
            d->legacy_journal = job->legacy;
            d->acknowledged = job->acknowledged;
            d->durable = job->acknowledged && !job->legacy;
            memcpy(d->key, job->key, 16);
        }
        if (!d->removed && !s2_exiting) {
            s2_recover(d);
            struct switch2_session *session=switch2_find_session(d->device);
            if (session) switch2_maybe_attach_kernel(session);
        }
    } else if (!job->ok) {
        d->uncertain = true;
        s2_fail(op, "StorageFailed");
    } else if (job->action == 3) {
        d->known = d->uncertain = false;
        s2_finish(op, op->cancel ? "cancelled" : "timed_out", op->cancel ? NULL : "Timeout");
    } else if (job->action == 1) {
        d->known = d->uncertain = true;
        if (op->cancel || op->terminal || d->removed || s2_now() >= op->deadline) {
            s2_io_start(d, op, 3);
        } else {
            op->phase = "committing";
            s2_advance(op);
        }
    } else if (job->action == 2) {
        d->known = d->acknowledged = d->durable = true;
        op->acknowledged = op->durable = true;
        memcpy(d->key, job->key, 16);
        if (!d->removed && !s2_exiting) s2_activate(op);
        else s2_fail(op, "AdapterRemoved");
    }
    if (job->directory_fd>=0) close(job->directory_fd);
    explicit_bzero(job->key, sizeof(job->key));
    s2_unref(d); g_free(job);
    return G_SOURCE_REMOVE;
}

static struct s2_operation *s2_new(struct s2_device *d, const char *owner,
                                  const char *request, uint32_t timeout)
{
    struct s2_operation *op = g_new0(struct s2_operation, 1);
    op->target = s2_ref(d);
    op->owner = g_strdup(owner); op->request = g_strdup(request);
    op->path = g_strdup_printf(S2_PATH "/%s/op%" G_GUINT64_FORMAT, s2_instance, ++s2_serial);
    op->deadline = s2_now() + timeout; op->timeout = timeout;
    op->phase = "connecting";
    d->operation = op;
    d->recovery_attempted = true;
    s2_operations = g_slist_append(s2_operations, op);
    return op;
}
static unsigned int s2_active_count(void)
{
    unsigned int count=0;
    for (GSList *l=s2_operations;l;l=l->next) {
        struct s2_operation *op=l->data;
        if (!op->terminal || op->io_pending) count++;
    }
    return count;
}
static void s2_recover(struct s2_device *d)
{
    struct s2_operation *op;
    if (d->loading || d->removed || d->operation || d->active || d->recovery_attempted || !d->capability ||
        !d->acknowledged || s2_active_count()>=S2_MAX_ACTIVE || g_slist_length(s2_operations) >= S2_MAX_OPS) return;
    op = s2_new(d, ":0.0", "startup-recovery", 30000);
    op->recovering = op->transmitted = op->acknowledged = true;
    memcpy(op->key, d->key, 16);
    s2_publish(op, "reconciling");
    /* Also converts the acknowledged legacy journal; never new flash writes. */
    s2_io_start(d, op, 2);
}
static void s2_probed(int error, void *data)
{
    struct s2_device *d = data;
    d->probe_pending = false;
    d->capability = !error;
    if (!d->removed && !s2_exiting) s2_recover(d);
}
static void s2_track(struct btd_adapter *adapter, struct btd_device *device)
{
    struct s2_device *d;
    char path[PATH_MAX];
    if (s2_find(device) || s2_exiting) return;
    d = g_new0(struct s2_device, 1);
    d->refs = 1; d->loading = true; d->directory_fd=-1;
    d->device = btd_device_ref(device); d->adapter = btd_adapter_ref(adapter);
    d->path = g_strdup(device_get_path(device)); d->adapter_path = g_strdup(adapter_get_path(adapter));
    ba2str(device_get_address(device), d->address);
    ba2str(btd_adapter_get_address(adapter), d->host);
    create_filename(path, sizeof(path), "/%s/%s/switch2-association",
                    btd_adapter_get_storage_dir(adapter), d->address);
    d->journal = g_strdup(path);
    create_filename(path, sizeof(path), "/%s/%s/switch2-enrollment",
                    btd_adapter_get_storage_dir(adapter), d->address);
    d->legacy = g_strdup(path);
    s2_devices = g_slist_prepend(s2_devices, d);
    s2_io_start(d, NULL, 0);
    d->probe_pending = true;
    if (!btd_switch2_key_probe(adapter, s2_probed, s2_ref(d), s2_unref)) {
        d->probe_pending = false; s2_unref(d);
    }
}
static void s2_removed(struct btd_device *device)
{
    struct s2_device *d = s2_find(device);
    if (!d) return;
    d->removed = true;
    if (d->operation) {
        d->operation->removed = true;
        s2_fail(d->operation, "DeviceRemoved");
    }
    s2_devices = g_slist_remove(s2_devices, d); s2_unref(d);
}
static bool s2_supported(struct s2_device *d)
{
    uint16_t product = btd_device_get_product(d->device);
    return btd_device_get_vendor(d->device) == SWITCH2_VENDOR &&
           (product == SWITCH2_LEFT_PRODUCT || product == SWITCH2_RIGHT_PRODUCT);
}
static bool s2_send(struct s2_operation *op, uint8_t step, const uint8_t *data, size_t size)
{
    uint8_t packet[64];
    size_t length = switch2_pair_packet(packet, sizeof(packet), step, data, size);
    struct switch2_session *s = switch2_find_session(op->target->device);
    bool ok = s && !s->stopping && !s->stop_source && length;
    if (ok) {
        op->step = step;
        if (step == 3) op->transmitted = true; /* conservative before enqueue */
        ok = bt_gatt_client_write_without_response(s->gatt, 0x16, false, packet, length);
    }
    explicit_bzero(packet, sizeof(packet));
    if (!ok) s2_fail(op, "ProtocolWriteFailed");
    return ok;
}
static void s2_bootstrapped(bool success, uint8_t ecode, void *data)
{
    struct switch2_session *s = data;
    struct s2_device *d = s2_find(s->device);
    struct s2_operation *op = d ? d->operation : NULL;
    uint8_t addresses[8] = {0,1};
    s->enroll_write_id = 0;
    if (!op || op->terminal || op->cancel || op->step != 0xfe) return;
    if (!success || ecode) { s2_fail(op, "ProtocolBootstrapFailed"); return; }
    memcpy(addresses + 2, btd_adapter_get_address(s->adapter), 6);
    s2_publish(op, "exchanging");
    s2_send(op, 1, addresses, sizeof(addresses));
}
static void s2_advance(struct s2_operation *op)
{
    uint8_t zero = 0;
    s2_publish(op, "committing");
    s2_send(op, 3, &zero, 1);
}
static void s2_try_session(struct switch2_session *s)
{
    struct s2_device *d = s2_find(s->device);
    struct s2_operation *op = d ? d->operation : NULL;
    static const uint8_t bootstrap[] = {1,0};
    if (!op || op->terminal || op->step || op->recovering || op->io_pending ||
        !s->reply_notify_ready || !s->side_notify_ready || s->stopping || s->stop_source) return;
    s2_publish(op, "validating");
    if (!s2_supported(d) || !d->observed || !switch2_find_handles(s->device, &s->handles)) {
        s2_fail(op, "UnsupportedDevice"); return;
    }
    if (!switch2_pair_random(op->component) || !switch2_pair_random(op->challenge)) {
        s2_fail(op, "CryptoUnavailable"); return;
    }
    op->step = 0xfe;
    s->enroll_active = true;
    s->enroll_write_id = bt_gatt_client_write_value(s->gatt, 5, bootstrap, sizeof(bootstrap),
                                                  s2_bootstrapped, s, NULL);
    if (!s->enroll_write_id) s2_fail(op, "ProtocolBootstrapFailed");
}
static bool switch2_enroll_begin(struct switch2_session *s)
{
    struct s2_device *d = s2_find(s->device);
    if (!d) return false;
    if (d->loading) return true;
    /* Preserve already-imported development transport on kernels without the
     * new extension. This is not reported as live registration success. */
    bool legacy_transport=d->legacy_journal && d->acknowledged && !d->capability &&
                          device_is_bonded(d->device,BDADDR_LE_PUBLIC);
    if ((d->known || d->uncertain) && !d->active && !legacy_transport) return true;
    if (d->operation && !d->operation->terminal) {
        s2_try_session(s);
        return true;
    }
    return false;
}
static void switch2_enroll_reply(struct switch2_session *s, const uint8_t *value, uint16_t length)
{
    struct s2_device *d = s2_find(s->device);
    struct s2_operation *op = d ? d->operation : NULL;
    uint8_t payload[17] = {0}, encrypted[16] = {0};
    size_t needed;
    if (!op || op->terminal || op->io_pending || !op->step || op->step == 0xfe ||
        s->stopping || s->stop_source || length < 4 || value[0] != 0x15 || value[3] != op->step) return;
    needed = op->step == 1 ? 9 : op->step == 3 ? 1 : 17;
    if (!switch2_pair_reply(value, length, op->step, needed)) { s2_fail(op, "ProtocolAcknowledgementFailed"); return; }
    switch (op->step) {
    case 1:
        if (value[10] != 1 || memcmp(value+11, device_get_address(s->device), 6)) {
            s2_fail(op, "PeerAddressMismatch"); break;
        }
        memcpy(payload+1, op->component, 16);
        s2_send(op, 4, payload, sizeof(payload)); break;
    case 4:
        switch2_pair_key(op->component, value+9, op->key);
        memcpy(payload+1, op->challenge, 16);
        s2_send(op, 2, payload, sizeof(payload)); break;
    case 2:
        if (!switch2_pair_encrypt_le(op->key, op->challenge, encrypted) ||
            !switch2_pair_challenge(encrypted, value+9)) { s2_fail(op, "ChallengeFailed"); break; }
        s2_publish(op, "committing");
        s2_io_start(d, op, 1); break;
    case 3:
        op->acknowledged = d->acknowledged = true;
        s->enroll_active = false;
        s2_publish(op, "persisting");
        s2_io_start(d, op, 2); break;
    }
    explicit_bzero(payload, sizeof(payload)); explicit_bzero(encrypted, sizeof(encrypted));
}

static void s2_cancel(struct s2_operation *op)
{
    if (op->terminal) return;
    op->cancel = true;
    s2_publish(op, op->phase);
    /* After transmission, continue only bounded reconciliation of this key. */
    if (op->transmitted || op->io_pending) return;
    struct switch2_session *s = switch2_find_session(op->target->device);
    s2_finish(op, "cancelled", NULL);
    if (s) {
        switch2_schedule_stop(s);
        device_request_disconnect(op->target->device,NULL);
    }
}
static void s2_owner_gone(DBusConnection *conn, void *data)
{
    struct s2_operation *op = data;
    (void)conn;
    op->owner_watch = 0;
    s2_cancel(op);
}
static void s2_op_free(struct s2_operation *op)
{
    if (op->owner_watch) g_dbus_remove_watch(s2_bus, op->owner_watch);
    if (op->target->operation == op) op->target->operation = NULL;
    s2_unref(op->target); s2_wipe(op);
    g_free(op->path); g_free(op->owner); g_free(op->request); g_free(op);
}
static gboolean s2_tick(void *unused)
{
    GSList *l = s2_operations;
    uint64_t now = s2_now();
    (void)unused;
    while (l) {
        GSList *next = l->next;
        struct s2_operation *op = l->data;
        if (op->activation_wait) {
            if (now >= op->activation_until || op->target->removed) {
                op->activation_wait = op->io_pending = false;
                s2_fail(op, "ActivationFailed");
            } else if (!btd_device_is_connected(op->target->device)) s2_activate(op);
        }
        if (!op->terminal && now >= op->deadline) {
            struct switch2_session *s = switch2_find_session(op->target->device);
            s2_finish(op, "timed_out", "Timeout");
            if (s && !op->io_pending) {
                switch2_schedule_stop(s);
                device_request_disconnect(op->target->device,NULL);
            }
        }
        if (op->terminal && !op->io_pending && now - op->finished >= S2_RETAIN_MS) {
            s2_operations = g_slist_remove(s2_operations, op); s2_op_free(op);
        }
        l = next;
    }
    for (GSList *device=s2_devices;device;device=device->next) s2_recover(device->data);
    return G_SOURCE_CONTINUE;
}
static DBusMessage *s2_error(DBusMessage *msg, const char *code)
{
    char *name = g_strdup_printf("org.ns_os.Switch2Enrollment1.Error.%s", code);
    DBusMessage *reply = g_dbus_create_error(msg, name, "%s", code);
    g_free(name); return reply;
}
static DBusMessage *s2_handle(DBusMessage *msg)
{
    const char *method = dbus_message_get_member(msg), *path = NULL;
    const char *owner = dbus_message_get_sender(msg);
    DBusMessage *reply;
    DBusMessageIter iter;
    struct s2_device *d = NULL;
    struct s2_operation *op = NULL;
    GSList *l;
    if (!strcmp(method, "ListOperations")) {
        DBusMessageIter array;
        reply = dbus_message_new_method_return(msg);
        dbus_message_iter_init_append(reply, &iter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "o", &array);
        for (l=s2_operations;l;l=l->next) {
            op=l->data;
            dbus_message_iter_append_basic(&array, DBUS_TYPE_OBJECT_PATH, &op->path);
        }
        dbus_message_iter_close_container(&iter, &array);
        return reply;
    }
    if (!strcmp(method, "GetOperation") || !strcmp(method, "Cancel")) {
        if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
            return s2_error(msg, "InvalidArguments");
        for (l=s2_operations;l;l=l->next) {
            struct s2_operation *candidate=l->data;
            if (!strcmp(candidate->path,path)) { op=candidate; break; }
        }
        if (!op) return s2_error(msg,"UnknownOperation");
        if (!strcmp(method,"Cancel")) {
            if (strcmp(owner,op->owner)) return s2_error(msg,"PermissionDenied");
            s2_cancel(op); return dbus_message_new_method_return(msg);
        }
        reply=dbus_message_new_method_return(msg);
        dbus_message_iter_init_append(reply,&iter); s2_state(&iter,op); return reply;
    }
    const char *request = NULL;
    uint32_t timeout = 0;
    bool start = !strcmp(method, "StartEnrollment");
    if (start) {
        if (!dbus_message_get_args(msg,NULL,DBUS_TYPE_OBJECT_PATH,&path,DBUS_TYPE_STRING,&request,
                                  DBUS_TYPE_UINT32,&timeout,DBUS_TYPE_INVALID) ||
            !request[0] || strlen(request)>128 || !timeout || timeout>180000)
            return s2_error(msg,"InvalidArguments");
        for (l=s2_operations;l;l=l->next) {
            struct s2_operation *old=l->data;
            if (strcmp(owner,old->owner) || strcmp(request,old->request)) continue;
            if (strcmp(path,old->target->path) || timeout!=old->timeout)
                return s2_error(msg,"InvalidArguments");
            return g_dbus_create_reply(msg,DBUS_TYPE_OBJECT_PATH,&old->path,DBUS_TYPE_INVALID);
        }
    } else if (!dbus_message_get_args(msg,NULL,DBUS_TYPE_OBJECT_PATH,&path,DBUS_TYPE_INVALID))
        return s2_error(msg,"InvalidArguments");
    for (l=s2_devices;l;l=l->next) {
        struct s2_device *candidate=l->data;
        if (!strcmp(candidate->path,path)) { d=candidate; break; }
    }
    if (!d) return s2_error(msg,"DeviceRemoved");
    if (!start) {
        DBusMessageIter dict;
        uint16_t vendor=btd_device_get_vendor(d->device), product=btd_device_get_product(d->device);
        reply=dbus_message_new_method_return(msg);
        dbus_message_iter_init_append(reply,&iter);
        dbus_message_iter_open_container(&iter,DBUS_TYPE_ARRAY,"{sv}",&dict);
        s2_object(&dict,"Device",d->path); s2_object(&dict,"Adapter",d->adapter_path);
        s2_string(&dict,"AdapterAddress",d->host); s2_string(&dict,"Address",d->address);
        s2_string(&dict,"AddressType",device_get_le_address_type(d->device)==BDADDR_LE_PUBLIC?"public":"random");
        s2_bool(&dict,"Supported",s2_supported(d));
        dict_append_entry(&dict,"VendorId",DBUS_TYPE_UINT16,&vendor);
        dict_append_entry(&dict,"ProductId",DBUS_TYPE_UINT16,&product);
        s2_string(&dict,"IdentityConfidence",d->observed?"manufacturer_metadata":s2_supported(d)?"stored_metadata":"unresolved");
        s2_string(&dict,"RegistrationState",s2_registration(d));
        s2_bool(&dict,"Connected",btd_device_is_connected(d->device));
        dbus_message_iter_close_container(&iter,&dict); return reply;
    }
    if (!s2_supported(d) || !d->observed) return s2_error(msg,"UnsupportedDevice");
    if (device_get_le_address_type(d->device)!=BDADDR_LE_PUBLIC ||
        btd_adapter_get_address_type(d->adapter)==BDADDR_LE_RANDOM)
        return s2_error(msg,"UnsupportedAddress");
    int availability=btd_switch2_availability(d->adapter);
    if (availability) return s2_error(msg,availability==-ERFKILL?"RadioBlocked":"PoweredOff");
    if (!d->capability) return s2_error(msg,"KernelCapabilityMissing");
    if (d->loading) return s2_error(msg,"Busy");
    if (!strcmp(s2_registration(d),"registered")) return s2_error(msg,"AlreadyRegistered");
    if (d->known || d->uncertain) return s2_error(msg,"RecoveryRequired");
    if (device_is_bonded(d->device,BDADDR_LE_PUBLIC)) return s2_error(msg,"AssociationExists");
    if (d->operation) return s2_error(msg,"Busy");
    if (s2_active_count()>=S2_MAX_ACTIVE || g_slist_length(s2_operations)>=S2_MAX_OPS)
        return s2_error(msg,"CapacityReached");
    op=s2_new(d,owner,request,timeout);
    op->owner_watch=g_dbus_add_disconnect_watch(s2_bus,owner,s2_owner_gone,op,NULL);
    if (!op->owner_watch) { s2_fail(op,"OwnerUnavailable"); }
    else {
        s2_publish(op,"connecting");
        /* Pin the storage directory before controller writes. Later writes use
         * this inode, never a replacement device directory at the same path. */
        s2_io_start(d,op,4);
    }
    return g_dbus_create_reply(msg,DBUS_TYPE_OBJECT_PATH,&op->path,DBUS_TYPE_INVALID);
}

static void s2_connect(struct s2_operation *op)
{
    struct s2_device *d=op->target;
    struct switch2_session *s=switch2_find_session(d->device);
    if (s && s->kernel_attached) {
        switch2_stop_session(s);
        device_request_disconnect(d->device,NULL);
    } else if (s) s2_try_session(s);
    else device_connect_le(d->device);
}

/* Credentials are requested asynchronously from the bus, never from caller
 * arguments. A dedicated service UID is required; desktop/game UID is denied. */
struct s2_auth { DBusMessage *request; DBusPendingCall *pending; };
static unsigned int s2_pending_auth;
static void s2_auth_done(DBusPendingCall *pending, void *data)
{
    struct s2_auth *auth=data;
    DBusMessage *credentials=dbus_pending_call_steal_reply(pending), *reply;
    uint32_t uid=UINT32_MAX;
    bool allowed=credentials && dbus_message_get_type(credentials)==DBUS_MESSAGE_TYPE_METHOD_RETURN &&
        dbus_message_get_args(credentials,NULL,DBUS_TYPE_UINT32,&uid,DBUS_TYPE_INVALID) &&
        (uid==0 || (s2_service_uid!=(uid_t)-1 && uid==s2_service_uid));
    s2_pending_auth--;
    reply=allowed && !s2_exiting?s2_handle(auth->request):s2_error(auth->request,"PermissionDenied");
    if (s2_bus) g_dbus_send_message(s2_bus,reply); else dbus_message_unref(reply);
    if(credentials) dbus_message_unref(credentials);
    dbus_message_unref(auth->request); dbus_pending_call_unref(auth->pending); g_free(auth);
}
static DBusMessage *s2_method(DBusConnection *conn, DBusMessage *msg, void *unused)
{
    const char *owner=dbus_message_get_sender(msg);
    DBusMessage *query;
    struct s2_auth *auth;
    (void)unused;
    if (!owner || owner[0]!=':') return s2_error(msg,"PermissionDenied");
    if (s2_pending_auth>=S2_MAX_OPS) return s2_error(msg,"CapacityReached");
    query=dbus_message_new_method_call(DBUS_SERVICE_DBUS,DBUS_PATH_DBUS,DBUS_INTERFACE_DBUS,"GetConnectionUnixUser");
    dbus_message_append_args(query,DBUS_TYPE_STRING,&owner,DBUS_TYPE_INVALID);
    auth=g_new0(struct s2_auth,1); auth->request=dbus_message_ref(msg);
    if (!dbus_connection_send_with_reply(conn,query,&auth->pending,3000) || !auth->pending) {
        dbus_message_unref(query); dbus_message_unref(auth->request); g_free(auth);
        return s2_error(msg,"PermissionDenied");
    }
    dbus_message_unref(query);
    s2_pending_auth++;
    dbus_pending_call_set_notify(auth->pending,s2_auth_done,auth,NULL);
    return NULL;
}
static gboolean s2_api_version(const GDBusPropertyTable *p, DBusMessageIter *iter, void *data)
{
    uint32_t version=1; (void)p; (void)data;
    return dbus_message_iter_append_basic(iter,DBUS_TYPE_UINT32,&version);
}
static gboolean s2_instance_property(const GDBusPropertyTable *p, DBusMessageIter *iter, void *data)
{
    (void)p; (void)data;
    return dbus_message_iter_append_basic(iter,DBUS_TYPE_STRING,&s2_instance);
}
static gboolean s2_capabilities(const GDBusPropertyTable *p, DBusMessageIter *iter, void *data)
{
    DBusMessageIter array;
    const char *cap="live_enrollment_v1";
    (void)p; (void)data;
    dbus_message_iter_open_container(iter,DBUS_TYPE_ARRAY,"s",&array);
    /* API implementation capability; Start additionally probes each adapter's
     * kernel support BEFORE any controller write. Absent adapter is availability. */
    dbus_message_iter_append_basic(&array,DBUS_TYPE_STRING,&cap);
    dbus_message_iter_close_container(iter,&array); return TRUE;
}
static const GDBusMethodTable s2_methods[] = {
    { GDBUS_ASYNC_METHOD("GetDeviceStatus",GDBUS_ARGS({"device","o"}),GDBUS_ARGS({"status","a{sv}"}),s2_method) },
    { GDBUS_ASYNC_METHOD("StartEnrollment",GDBUS_ARGS({"device","o"},{"request_id","s"},{"timeout_ms","u"}),GDBUS_ARGS({"operation","o"}),s2_method) },
    { GDBUS_ASYNC_METHOD("Cancel",GDBUS_ARGS({"operation","o"}),NULL,s2_method) },
    { GDBUS_ASYNC_METHOD("GetOperation",GDBUS_ARGS({"operation","o"}),GDBUS_ARGS({"state","a{sv}"}),s2_method) },
    { GDBUS_ASYNC_METHOD("ListOperations",NULL,GDBUS_ARGS({"operations","ao"}),s2_method) },
    { }
};
static const GDBusSignalTable s2_signals[] = {
    { GDBUS_SIGNAL("OperationChanged",GDBUS_ARGS({"operation","o"},{"state","a{sv}"})) }, { }
};
static const GDBusPropertyTable s2_properties[] = {
    {"ApiVersion","u",s2_api_version,NULL},
    {"InstanceId","s",s2_instance_property,NULL},
    {"Capabilities","as",s2_capabilities,NULL}, { }
};
static bool s2_init(void)
{
    struct passwd *principal=getpwnam("ns-controller");
    char *uuid=g_uuid_string_random();
    s2_instance=g_strdelimit(g_strdup_printf("i%s",uuid),"-",'_'); g_free(uuid);
    if (principal) s2_service_uid=principal->pw_uid;
    s2_bus=btd_get_dbus_connection();
    if (!g_dbus_register_interface(s2_bus,S2_PATH,S2_IFACE,s2_methods,s2_signals,s2_properties,NULL,NULL)) return false;
    s2_storage_pool=g_thread_pool_new(s2_io_worker,NULL,2,FALSE,NULL);
    if (!s2_storage_pool) return false;
    s2_tick_id=g_timeout_add(100,s2_tick,NULL);
    return true;
}
static void s2_exit(void)
{
    s2_exiting=true;
    if (s2_tick_id) g_source_remove(s2_tick_id);
    g_dbus_unregister_interface(s2_bus,S2_PATH,S2_IFACE);
    /* Daemon exit owns remaining asynchronous jobs. Never free their BlueZ
     * references before their completion; no module dlclose (built-in plugin). */
    while(s2_devices) s2_removed(((struct s2_device *)s2_devices->data)->device);
}

static void s2_observed(struct btd_adapter *adapter, struct btd_device *device, uint16_t product)
{
    s2_track(adapter, device);
    struct s2_device *d=s2_find(device);
    if (d) {
        d->observed=true;
        btd_device_set_pnpid(device,2,SWITCH2_VENDOR,product,0);
    }
}

static void s2_link_lost(struct btd_device *device)
{
    struct s2_device *d=s2_find(device);
    struct s2_operation *op=d?d->operation:NULL;
    if (op && op->step && !op->io_pending && !op->terminal)
        s2_fail(op,"Disconnected");
}
