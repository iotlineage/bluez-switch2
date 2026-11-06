#!/usr/bin/env python3
"""Private bus + actual provider with fake transports. Run in a user namespace."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

DBusGMainLoop(set_as_default=True)
BINARY = sys.argv[1]
PATH = '/org/bluez/ns_os/switch2'
IFACE = 'org.ns_os.Switch2Enrollment1'
LEFT = '/org/bluez/hci0/dev_06_05_04_03_02_01'
RIGHT = '/org/bluez/hci0/dev_16_15_14_13_12_11'
config = Path(__file__).with_name('private-bus.conf')
broker = subprocess.Popen(['dbus-daemon', '--nofork', '--print-address=1', '--config-file=' + str(config)], stdout=subprocess.PIPE, text=True)
address = broker.stdout.readline().strip()
os.environ['DBUS_SESSION_BUS_ADDRESS'] = address

def connection():
    return dbus.bus.BusConnection(address)

def interface(bus):
    return dbus.Interface(bus.get_object('org.bluez', PATH), IFACE)

def pump():
    context = GLib.MainContext.default()
    while context.pending():
        context.iteration(False)

def terminal(api, operation):
    end = time.monotonic() + 5
    while time.monotonic() < end:
        pump()
        state = api.GetOperation(operation)
        if state['Phase'] in ('succeeded', 'cancelled', 'failed', 'timed_out'):
            return state
        time.sleep(.01)
    raise AssertionError('operation did not terminate')

def error(call, code):
    try:
        call()
    except dbus.DBusException as exc:
        assert exc.get_dbus_name() == IFACE + '.Error.' + code, exc
    else:
        raise AssertionError('expected ' + code)

def server(root, mode=''):
    proc = subprocess.Popen([BINARY, root, '--serve'], env=dict(os.environ, S2_FIXTURE_MODE=mode), stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == 'READY'
    return proc

try:
    with tempfile.TemporaryDirectory() as root:
        proc = server(root, 'hold')
        try:
            owner = connection(); replacement = connection()
            api = interface(owner); other = interface(replacement)
            props = dbus.Interface(owner.get_object('org.bluez', PATH), 'org.freedesktop.DBus.Properties').GetAll(IFACE)
            assert int(props['ApiVersion']) == 1 and 'live_enrollment_v1' in props['Capabilities']
            status = api.GetDeviceStatus(LEFT)
            assert status['Supported'] and status['RegistrationState'] == 'unregistered'
            assert int(status['ProductId']) == 0x2067
            changes = []
            owner.add_signal_receiver(lambda operation, state: changes.append((str(operation), dict(state))), signal_name='OperationChanged', dbus_interface=IFACE, path=PATH)
            op = api.StartEnrollment(LEFT, 'request-one', dbus.UInt32(2000))
            assert api.StartEnrollment(LEFT, 'request-one', dbus.UInt32(2000)) == op
            error(lambda: api.StartEnrollment(LEFT, 'request-one', dbus.UInt32(1000)), 'InvalidArguments')
            error(lambda: other.Cancel(op), 'PermissionDenied')
            assert op in other.ListOperations()
            api.Cancel(op)
            state = terminal(other, op)
            assert state['Phase'] == 'cancelled' and state['CancelRequested'] and not state['ControllerAcknowledged']
            pump()
            revisions = [int(state['Revision']) for operation, state in changes if operation == op]
            assert revisions and revisions == sorted(set(revisions))
            assert all(not any(k in state for k in ('Key', 'KeyLE', 'Challenge', 'Packet')) for _, state in changes)
            op2 = api.StartEnrollment(RIGHT, 'owner-loss', dbus.UInt32(2000))
            owner.close()
            assert terminal(other, op2)['Phase'] == 'cancelled'
            error(lambda: other.GetOperation(PATH + '/old_instance/op1'), 'UnknownOperation')
            # 64 retained outcomes: never evict one to accept a later request.
            for n in range(62):
                current = other.StartEnrollment(LEFT, 'capacity-' + str(n), dbus.UInt32(2000))
                other.Cancel(current)
                assert terminal(other, current)['Phase'] == 'cancelled'
            error(lambda: other.StartEnrollment(LEFT, 'overflow', dbus.UInt32(2000)), 'CapacityReached')
            assert len(other.ListOperations()) == 64
            # A different mapped UID is allowed by the *fixture bus*, then denied
            # by the provider's method authorization (not merely bus policy).
            child = """import dbus,os
b=dbus.bus.BusConnection(os.environ['DBUS_SESSION_BUS_ADDRESS'])
a=dbus.Interface(b.get_object('org.bluez','/org/bluez/ns_os/switch2'),'org.ns_os.Switch2Enrollment1')
try: a.ListOperations()
except dbus.DBusException as e:
 assert e.get_dbus_name().endswith('.Error.PermissionDenied'),str(e)
else: raise AssertionError('unrelated user was authorized')
"""
            def nobody():
                os.setgroups([]); os.setgid(65534); os.setuid(65534)
            subprocess.run([sys.executable, '-c', child], preexec_fn=nobody, check=True, timeout=5)
            old_instance = str(props['InstanceId'])
        finally:
            proc.terminate(); proc.wait(timeout=5)
        proc = server(root)
        try:
            fresh = connection(); api = interface(fresh)
            props = dbus.Interface(fresh.get_object('org.bluez', PATH), 'org.freedesktop.DBus.Properties').GetAll(IFACE)
            assert str(props['InstanceId']) != old_instance
            error(lambda: api.GetOperation(op), 'UnknownOperation')
            op = api.StartEnrollment(LEFT, 'real-exchange', dbus.UInt32(2000))
            result = terminal(api, op)
            assert result['Phase'] == 'succeeded' and all(result[k] for k in ('ControllerAcknowledged', 'AssociationDurable', 'AssociationActive'))
            assert api.GetDeviceStatus(LEFT)['RegistrationState'] == 'registered'
            # Read fixture-only private material and search the entire public
            # outcome for both key byte orders, not only forbidden field names.
            journals=list(Path(root).rglob('switch2-association'))
            public=json.dumps(result,default=str).lower()
            for journal in journals:
                for line in journal.read_text().splitlines():
                    if line.startswith('KeyLE=') and len(line)==38:
                        key=line[6:].lower()
                        assert key not in public and bytes.fromhex(key)[::-1].hex() not in public

        finally:
            proc.terminate(); proc.wait(timeout=5)
    print(json.dumps({'passed': True, 'private_bus': True, 'hardware': False,
        'checks': ['introspection', 'status', 'async-start', 'deduplication', 'revision-signals', 'owner-only-cancel', 'owner-loss', 'retention-capacity', 'method-authorization', 'instance-replacement', 'public-secret-redaction', 'live-success']}))
finally:
    broker.terminate(); broker.wait(timeout=5)
