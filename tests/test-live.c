/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Actual provider code, fake adapter/GATT/key backend; never opens Bluetooth. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>
#include "lib/bluetooth/bluetooth.h"
#include "src/adapter.h"
#include "src/device.h"
#include "switch2-pairing.h"
#define SWITCH2_VENDOR 0x057e
#define SWITCH2_LEFT_PRODUCT 0x2067
#define SWITCH2_RIGHT_PRODUCT 0x2066
struct btd_adapter { bdaddr_t address; };
struct btd_device { struct btd_adapter *adapter; bdaddr_t address; uint16_t product; bool connected,bonded; };
struct switch2_handles { int unused; };
struct switch2_session {
    struct btd_device *device;
    struct btd_adapter *adapter;
    void *gatt;
    struct switch2_handles handles;
    bool kernel_attached, reply_notify_ready, side_notify_ready, stopping, enroll_active;
    guint stop_source, enroll_write_id;
};
static struct btd_adapter adapter;
static struct btd_device devices[2];
static struct switch2_session fake_sessions[2];
static DBusConnection *bus;
static char storage[PATH_MAX];
static unsigned int writes, commits, installs, attaches;
static uint8_t last_step;
static bool activation_failure, auto_reply, auto_connect = true;
static const char *mode;
static void pump(unsigned int milliseconds);
const bdaddr_t *btd_adapter_get_address(struct btd_adapter *a) {return &a->address;}
uint8_t btd_adapter_get_address_type(struct btd_adapter *a) {(void)a;return BDADDR_LE_PUBLIC;}
const char *btd_adapter_get_storage_dir(struct btd_adapter *a) {(void)a;return "adapter";}
const char *adapter_get_path(struct btd_adapter *a) {(void)a;return "/org/bluez/hci0";}
int btd_switch2_availability(struct btd_adapter *a) {(void)a;return 0;}
bool btd_adapter_get_powered(struct btd_adapter *a) {(void)a;return true;}
struct btd_adapter *btd_adapter_ref(struct btd_adapter *a) {return a;}
void btd_adapter_unref(struct btd_adapter *a) {(void)a;}
struct btd_device *btd_device_ref(struct btd_device *d) {return d;}
void btd_device_unref(struct btd_device *d) {(void)d;}
struct btd_adapter *device_get_adapter(struct btd_device *d) {return d->adapter;}
const bdaddr_t *device_get_address(struct btd_device *d) {return &d->address;}
const char *device_get_path(const struct btd_device *d) {return d->product==SWITCH2_LEFT_PRODUCT?"/org/bluez/hci0/dev_06_05_04_03_02_01":"/org/bluez/hci0/dev_16_15_14_13_12_11";}
uint8_t device_get_le_address_type(struct btd_device *d) {(void)d;return BDADDR_LE_PUBLIC;}
uint16_t btd_device_get_vendor(struct btd_device *d) {(void)d;return SWITCH2_VENDOR;}
uint16_t btd_device_get_product(struct btd_device *d) {return d->product;}
bool btd_device_is_connected(struct btd_device *d) {return d->connected;}
bool device_is_bonded(struct btd_device *d,uint8_t type) {(void)type;return d->bonded;}
void device_set_paired(struct btd_device *d,uint8_t type) {(void)d;(void)type;}
void device_set_bonded(struct btd_device *d,uint8_t type) {(void)type;d->bonded=true;}
void device_set_ltk(struct btd_device *d,const uint8_t key[16],bool central,uint8_t enc_size) {(void)d;(void)key;assert(central&&enc_size==16);}
void btd_device_set_trusted(struct btd_device *d,gboolean trusted) {(void)d;assert(trusted);}
void btd_device_set_pnpid(struct btd_device *d,uint16_t source,uint16_t vendor,uint16_t product,uint16_t version) {(void)source;(void)vendor;(void)version;d->product=product;}
static struct switch2_session *switch2_find_session(struct btd_device *d) {return d->product==SWITCH2_LEFT_PRODUCT?&fake_sessions[0]:&fake_sessions[1];}
static void switch2_schedule_stop(struct switch2_session *s) {s->stop_source=1;}
static void switch2_stop_session(struct switch2_session *s) {s->kernel_attached=false;}
static void switch2_autoconnect_enable(struct btd_adapter *a,struct btd_device *d) {(void)a;(void)d;auto_connect=true;}
static void switch2_autoconnect_disable(struct btd_adapter *a,struct btd_device *d) {(void)a;(void)d;auto_connect=false;}
static bool switch2_find_handles(struct btd_device *d,struct switch2_handles *h) {(void)d;(void)h;return true;}
static void switch2_maybe_attach_kernel(struct switch2_session *s);
static void s2_try_session(struct switch2_session *s);
static gboolean reconnect_idle(void *data) {device_connect_le(data);return G_SOURCE_REMOVE;}
void device_request_disconnect(struct btd_device *d,DBusMessage *msg) {(void)msg;d->connected=false;if(auto_connect)g_idle_add(reconnect_idle,d);}
int device_connect_le(struct btd_device *d) {d->connected=true;s2_try_session(switch2_find_session(d));return 0;}

static int create_filename(char *path,size_t size,const char *format,...) {
    va_list ap; int n=snprintf(path,size,"%s",storage);
    va_start(ap,format);vsnprintf(path+n,size-n,format,ap);va_end(ap);return 0;
}
#include "src/switch2-key-install.h"
struct key_callback { btd_switch2_key_cb cb;void *data;GDestroyNotify destroy;int error; };
static gboolean key_done(void *data) {
    struct key_callback *k=data;k->cb(k->error,k->data);if(k->destroy)k->destroy(k->data);g_free(k);return G_SOURCE_REMOVE;
}
bool btd_switch2_key_probe(struct btd_adapter *a,btd_switch2_key_cb cb,void *data,GDestroyNotify destroy) {
    (void)a;struct key_callback *k=g_new0(struct key_callback,1);*k=(struct key_callback){cb,data,destroy,0};g_idle_add(key_done,k);return true;
}
bool btd_switch2_key_install(struct btd_device *d,const uint8_t key[16],btd_switch2_key_cb cb,void *data,GDestroyNotify destroy) {
    (void)d;(void)key;installs++;struct key_callback *k=g_new0(struct key_callback,1);
    *k=(struct key_callback){cb,data,destroy,activation_failure?-EIO:0};g_idle_add(key_done,k);return true;
}
struct bootstrap_callback {void (*cb)(bool,uint8_t,void*);void *data;};
static gboolean bootstrap_done(void *data) {
    struct bootstrap_callback *b=data;b->cb(true,0,b->data);g_free(b);return G_SOURCE_REMOVE;
}
static unsigned int bt_gatt_client_write_value(void *gatt,uint16_t handle,const uint8_t *value,uint16_t length,
        void (*cb)(bool,uint8_t,void*),void *data,void *destroy) {
    (void)gatt;(void)destroy;assert(handle==5 && length==2 && value[0]==1);
    struct bootstrap_callback *b=g_new0(struct bootstrap_callback,1);b->cb=cb;b->data=data;g_idle_add(bootstrap_done,b);writes++;return 1;
}
static gboolean reply_idle(void *data);
static gboolean cancel_idle(void *data);
static unsigned int bt_gatt_client_write_without_response(void *gatt,uint16_t handle,bool sign,const uint8_t *v,uint16_t length) {
    (void)sign;assert(handle==0x16 && length>=26 && v[17]==0x15);
    writes++;last_step=v[20];if(last_step==3)commits++;
    if(mode && !strcmp(mode,"cancel-after-commit") && last_step==3)g_idle_add(cancel_idle,gatt);
    if(mode && !strcmp(mode,"crash-commit") && last_step==3)_exit(91);
    if(auto_reply && !(mode && !strcmp(mode,"ack-lost") && last_step==3))g_idle_add(reply_idle,gatt);
    return 1;
}
static gboolean fixture_write(const char *path,const char *contents,gssize length,
        GFileSetContentsFlags flags,int permissions,GError **error) {
    if(mode && ((!strcmp(mode,"storage-failure-intent") && strstr(contents,"State=commit-pending")) ||
                (!strcmp(mode,"storage-failure-ack") && strstr(contents,"State=acknowledged")))) return false;
    if(mode && !strcmp(mode,"slow-storage"))g_usleep(250000);
    bool result=g_file_set_contents_full(path,contents,length,flags,permissions,error);
    if(result && mode && ((!strcmp(mode,"crash-intent") && strstr(contents,"State=commit-pending")) ||
                         (!strcmp(mode,"crash-ack") && strstr(contents,"State=acknowledged"))))_exit(90);
    return result;
}
#define g_file_set_contents_full fixture_write
#include "switch2-live.inc"
#undef g_file_set_contents_full
static gboolean cancel_idle(void *data) {
    struct switch2_session *session=data;struct s2_device *d=s2_find(session->device);
    if(d && d->operation)s2_cancel(d->operation);
    return G_SOURCE_REMOVE;
}
static void switch2_maybe_attach_kernel(struct switch2_session *s) {
    if(!switch2_enroll_begin(s)) {s->kernel_attached=true;attaches++;}
}
static gboolean reply_idle(void *data) {
    struct switch2_session *s=data;
    struct s2_device *d=s2_find(s->device);
    struct s2_operation *op=d?d->operation:NULL;
    uint8_t reply[25]={0x15,1,1,0,0x10,0x78,0,0,1};
    if(!op || op->terminal)return G_SOURCE_REMOVE;
    reply[3]=op->step;
    if(op->step==1) {reply[9]=4;reply[10]=1;memcpy(reply+11,device_get_address(s->device),6);}
    if(op->step==4)memset(reply+9,0x23,16);
    if(op->step==2) {uint8_t encrypted[16];assert(switch2_pair_encrypt_le(op->key,op->challenge,encrypted));for(int i=0;i<16;i++)reply[9+i]=encrypted[15-i];explicit_bzero(encrypted,16);}
    if(mode && !strcmp(mode,"bad-peer") && op->step==1)reply[11]^=1;
    if(mode && !strcmp(mode,"bad-challenge") && op->step==2)reply[9]^=1;
    if(mode && !strcmp(mode,"bad-ack") && op->step==3)reply[8]=0;
    uint8_t unrelated[]={0x07,0,0,0};
    switch2_enroll_reply(s,unrelated,sizeof(unrelated));
    switch2_enroll_reply(s,reply,op->step==1?17:op->step==3?9:25);
    return G_SOURCE_REMOVE;
}
static unsigned int input_ticks;
static uint64_t last_input_tick, largest_input_gap;
static gboolean simulated_input(void *unused) {
    (void)unused;uint64_t now=s2_now();
    if(last_input_tick && now-last_input_tick>largest_input_gap)largest_input_gap=now-last_input_tick;
    last_input_tick=now;input_ticks++;return G_SOURCE_CONTINUE;
}
static void pump(unsigned int milliseconds) {
    uint64_t deadline=s2_now()+milliseconds;
    do {while(g_main_context_iteration(NULL,false));g_usleep(1000);}while(s2_now()<deadline);
}
static DBusMessage *start(int side,const char *request,unsigned int timeout,const char *sender) {
    const char *path=device_get_path(&devices[side]);
    DBusMessage *msg=dbus_message_new_method_call("org.bluez",S2_PATH,S2_IFACE,"StartEnrollment");
    dbus_message_set_serial(msg,1);dbus_message_set_sender(msg,sender);
    dbus_message_append_args(msg,DBUS_TYPE_OBJECT_PATH,&path,DBUS_TYPE_STRING,&request,DBUS_TYPE_UINT32,&timeout,DBUS_TYPE_INVALID);
    DBusMessage *reply=s2_handle(msg);dbus_message_unref(msg);return reply;
}
int main(int argc,char **argv) {
    assert(argc>=2);snprintf(storage,sizeof(storage),"%s",argv[1]);
    bool serve=argc>2&&!strcmp(argv[2],"--serve");
    str2ba("A6:A5:A4:A3:A2:A1",&adapter.address);
    bus=g_dbus_setup_private(DBUS_BUS_SESSION,"org.bluez",NULL);assert(bus);set_dbus_connection(bus);assert(s2_init());
    for(int i=0;i<2;i++) {
        devices[i].adapter=&adapter;devices[i].product=i?SWITCH2_RIGHT_PRODUCT:SWITCH2_LEFT_PRODUCT;
        str2ba(i?"16:15:14:13:12:11":"06:05:04:03:02:01",&devices[i].address);
        char peer[18],*folder;ba2str(&devices[i].address,peer);folder=g_strdup_printf("%s/adapter/%s",storage,peer);
        assert(!g_mkdir_with_parents(folder,0700));g_free(folder);
        fake_sessions[i]=(struct switch2_session){.device=&devices[i],.adapter=&adapter,.reply_notify_ready=true,.side_notify_ready=true};
        fake_sessions[i].gatt=&fake_sessions[i];s2_observed(&adapter,&devices[i],devices[i].product);
    }
    mode=getenv("S2_FIXTURE_MODE");activation_failure=mode&&!strcmp(mode,"activation-failure");
    g_timeout_add(5,simulated_input,NULL);
    pump(100);auto_reply=!(mode && !strcmp(mode,"hold"));
    if(mode && !strcmp(mode,"capability-missing")) {
        s2_find(&devices[0])->capability=false;
        DBusMessage *r=start(0,"no-kernel",1000,dbus_bus_get_unique_name(bus));
        assert(dbus_message_is_error(r,"org.ns_os.Switch2Enrollment1.Error.KernelCapabilityMissing"));
        assert(!writes&&!commits&&!installs);dbus_message_unref(r);
        puts("PASS: missing kernel capability refuses before controller writes");return 0;
    }
    if(mode && !strcmp(mode,"malformed")) {
        struct s2_device *d=s2_find(&devices[0]);
        assert(d->uncertain && !strcmp(s2_registration(d),"recovery_required"));
        assert(!writes&&!installs);puts("PASS: malformed or insecure journal blocks enrollment");return 0;
    }
    if(mode && !strcmp(mode,"recover")) {
        pump(300);struct s2_device *d=s2_find(&devices[0]);
        assert(!writes&&!commits&&d->active&&d->durable&&d->acknowledged&&installs==1);
        puts("PASS: restart recovery activates the same acknowledged key without controller writes");return 0;
    }
    if(mode && !strcmp(mode,"recover-uncertain")) {
        pump(300);struct s2_device *d=s2_find(&devices[0]);
        assert(!writes&&!commits&&!installs&&!d->active&&d->uncertain);
        assert(!strcmp(s2_registration(d),"recovery_required"));
        puts("PASS: uncertain commit preserved without automatic enrollment or activation");return 0;
    }
    if(serve) {puts("READY");fflush(stdout);g_main_loop_run(g_main_loop_new(NULL,false));return 0;}
    DBusMessage *reply=start(0,"first",10000,dbus_bus_get_unique_name(bus));
    assert(dbus_message_get_type(reply)==DBUS_MESSAGE_TYPE_METHOD_RETURN);dbus_message_unref(reply);
    reply=start(0,"first",10000,dbus_bus_get_unique_name(bus));assert(dbus_message_get_type(reply)==DBUS_MESSAGE_TYPE_METHOD_RETURN);dbus_message_unref(reply);
    reply=start(0,"first",9999,dbus_bus_get_unique_name(bus));assert(dbus_message_get_type(reply)==DBUS_MESSAGE_TYPE_ERROR);dbus_message_unref(reply);
    struct s2_operation *op=s2_operations->data;
    if(mode && !strcmp(mode,"cancel-before")) s2_cancel(op);
    if(mode && !strcmp(mode,"cancel-during-intent")) {
        uint64_t limit=s2_now()+2000;
        while(!(op->io_pending && op->step==2) && !op->terminal && s2_now()<limit) g_main_context_iteration(NULL,true);
        assert(op->io_pending&&!op->transmitted);s2_cancel(op);
    }
    if(mode && !strcmp(mode,"remove-during-intent")) {
        uint64_t limit=s2_now()+2000;
        while(!(op->io_pending && op->step==2) && !op->terminal && s2_now()<limit)g_main_context_iteration(NULL,true);
        assert(op->io_pending&&!op->transmitted);
        char *directory=g_path_get_dirname(op->target->journal), *old=g_strconcat(directory,"-old",NULL);
        assert(!rename(directory,old));assert(!g_mkdir_with_parents(directory,0700));
        s2_removed(&devices[0]);s2_observed(&adapter,&devices[0],devices[0].product);
        pump(400);char *path=g_strconcat(directory,"/switch2-association",NULL);
        assert(!g_file_test(path,G_FILE_TEST_EXISTS)&&!commits&&!installs);
        assert(!strcmp(s2_registration(s2_find(&devices[0])),"unregistered"));
        g_free(path);g_free(old);g_free(directory);
        puts("PASS: stale storage jobs cannot write into replacement device directory");return 0;
    }
    if(mode && !strcmp(mode,"ack-lost"))op->deadline=s2_now()+100;
    pump(mode && !strcmp(mode,"slow-storage")?1200:400);
    if(mode) {
        assert(op->terminal);
        if(!strcmp(mode,"bad-peer")||!strcmp(mode,"bad-challenge")) {
            assert(!strcmp(op->phase,"failed")&&!commits&&!installs);
        } else if(!strcmp(mode,"bad-ack")) {
            assert(!strcmp(op->phase,"failed")&&commits==1&&!installs&&!op->acknowledged&&op->target->uncertain);
        } else if(!strcmp(mode,"slow-storage")) {
            assert(!strcmp(op->phase,"succeeded")&&input_ticks>100&&largest_input_gap<100);
            puts("PASS: simulated input dispatch continues during durable storage delays");return 0;
        } else if(!strcmp(mode,"cancel-before")||!strcmp(mode,"cancel-during-intent")) {
            assert(!strcmp(op->phase,"cancelled")&&!commits&&!installs&&!op->target->uncertain);
        } else if(!strcmp(mode,"cancel-after-commit")) {
            assert(!strcmp(op->phase,"succeeded")&&op->cancel&&commits==1&&installs==1);
        } else if(!strcmp(mode,"ack-lost")) {
            assert(!strcmp(op->phase,"timed_out")&&commits==1&&!installs&&op->target->uncertain);
        } else if(!strcmp(mode,"storage-failure-intent")) {
            assert(!strcmp(op->error,"StorageFailed")&&!commits&&!installs);
        } else if(!strcmp(mode,"storage-failure-ack")) {
            assert(!strcmp(op->error,"StorageFailed")&&commits==1&&!installs&&op->acknowledged&&!op->durable);
        } else if(!strcmp(mode,"activation-failure")) {
            assert(!strcmp(op->error,"ActivationFailed")&&op->acknowledged&&op->durable&&!op->active&&commits==1);
        } else abort();
        printf("PASS: %s\n",mode);return 0;
    }
    fprintf(stderr,"phase=%s error=%s step=%u writes=%u commits=%u installs=%u io=%d ack=%d durable=%d active=%d\n",op->phase,op->error?op->error:"",op->step,writes,commits,installs,op->io_pending,op->acknowledged,op->durable,op->active);
    assert(op->terminal&&!strcmp(op->phase,"succeeded")&&op->acknowledged&&op->durable&&op->active&&commits==1&&installs==1);
    assert(!strcmp(s2_registration(s2_find(&devices[0])),"registered"));
    reply=start(0,"other",10000,dbus_bus_get_unique_name(bus));assert(dbus_message_get_type(reply)==DBUS_MESSAGE_TYPE_ERROR);dbus_message_unref(reply);
    reply=start(1,"second",10000,dbus_bus_get_unique_name(bus));assert(dbus_message_get_type(reply)==DBUS_MESSAGE_TYPE_METHOD_RETURN);dbus_message_unref(reply);
    pump(300);assert(commits==2&&installs==2&&devices[1].bonded);
    s2_link_lost(&devices[0]);
    s2_exit();
    puts("PASS: both halves, asynchronous live activation, durable acknowledgement, deduplication, conflicting request rejection, AlreadyRegistered");
    return 0;
}
