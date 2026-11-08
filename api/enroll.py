#!/usr/bin/env python3
"""Public-state enrollment client; root/ns-controller only. Never prints secrets."""
import argparse
import json
import signal
import sys
import time
import uuid

import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

PATH = '/org/bluez/ns_os/switch2'
IFACE = 'org.ns_os.Switch2Enrollment1'
TERMINAL = ('succeeded', 'cancelled', 'timed_out', 'failed')


def plain(value):
    if isinstance(value, dbus.Boolean):
        return bool(value)
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value


def emit(kind, value):
    print(json.dumps({'kind': kind, **plain(value)}, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('device', nargs='?', help='Selected org.bluez.Device1 object path')
    parser.add_argument('--list', action='store_true', help='List discovered Nintendo candidates and verified provider status; does not scan')
    parser.add_argument('--start', action='store_true', help='Enroll the selected controller; may replace its console association')
    parser.add_argument('--operation', help='Read a retained operation without repeating enrollment')
    parser.add_argument('--timeout-ms', type=int, default=120000)
    args = parser.parse_args()
    if sum((bool(args.device), args.list, bool(args.operation))) != 1:
        parser.error('choose a device, --list, or --operation PATH')
    if args.start and not args.device:
        parser.error('--start requires an explicit device path')
    if not 1 <= args.timeout_ms <= 180000:
        parser.error('--timeout-ms must be between 1 and 180000')
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    # Pin this daemon's unique owner: never replay a write against its replacement.
    owner = bus.get_name_owner('org.bluez')
    obj = bus.get_object(owner, PATH, introspect=False)
    api = dbus.Interface(obj, IFACE)
    props = dbus.Interface(obj, 'org.freedesktop.DBus.Properties').GetAll(IFACE)
    if int(props['ApiVersion']) != 1 or 'live_enrollment_v1' not in props['Capabilities']:
        raise RuntimeError('Live enrollment API v1 is unavailable')
    emit('provider', props)
    if args.operation:
        emit('operation', api.GetOperation(dbus.ObjectPath(args.operation)))
        return 0
    if args.list:
        objects = dbus.Interface(bus.get_object(owner, '/', introspect=False),
                                 'org.freedesktop.DBus.ObjectManager').GetManagedObjects()
        for path, interfaces in objects.items():
            device = interfaces.get('org.bluez.Device1')
            if device is None:
                continue
            # Name/UUID only selects candidates for a read; provider verifies identity.
            if not (str(device.get('Name', '')).startswith('Joy-Con 2') or
                    'ab7de9be-89fe-49ad-828f-118f09df7fd0' in device.get('UUIDs', [])):
                continue
            emit('device', api.GetDeviceStatus(dbus.ObjectPath(path)))
        return 0
    status = api.GetDeviceStatus(dbus.ObjectPath(args.device))
    emit('device', status)
    if not args.start:
        return 0
    operation = None
    revision = -1
    outcome = None
    loop = GLib.MainLoop()
    cancel_requested = False
    request = str(uuid.uuid4())
    emit('request', {'RequestId': request, 'Device': args.device})

    def display(which, state):
        nonlocal revision, outcome
        if str(which) != operation or int(state['Revision']) <= revision:
            return
        revision = int(state['Revision'])
        emit('operation', state)
        if str(state['Phase']) in TERMINAL:
            outcome = str(state['Phase'])
            loop.quit()

    bus.add_signal_receiver(display, signal_name='OperationChanged', dbus_interface=IFACE,
                            path=PATH, bus_name=owner)
    # If this reply is lost, do not retry: the emitted request ID and ListOperations
    # allow reconciliation. Closing the caller connection invokes provider cleanup.
    operation = str(api.StartEnrollment(dbus.ObjectPath(args.device), request,
                                       dbus.UInt32(args.timeout_ms)))
    deadline = time.monotonic() + args.timeout_ms / 1000 + 15

    def poll():
        nonlocal outcome
        try:
            if bus.get_name_owner('org.bluez') != owner:
                raise RuntimeError('BlueZ instance changed; inspect registration status before retrying')
            display(operation, api.GetOperation(dbus.ObjectPath(operation)))
            if outcome is None and time.monotonic() >= deadline:
                raise RuntimeError('Reconciliation deadline exceeded; inspect retained operation before retrying')
        except (dbus.DBusException, RuntimeError) as exc:
            emit('error', {'Error': str(exc), 'Operation': operation})
            outcome = 'failed'
            loop.quit()
        return outcome is None

    def cancel(*_):
        nonlocal cancel_requested
        if not cancel_requested:
            cancel_requested = True
            try:
                api.Cancel(dbus.ObjectPath(operation))
                emit('cancellation', {'Operation': operation, 'Message': 'Cancellation requested; waiting for truthful final state. Acknowledged associations are retained.'})
            except dbus.DBusException as exc:
                emit('error', {'Error': exc.get_dbus_name(), 'Operation': operation})
        return GLib.SOURCE_CONTINUE

    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGINT, cancel)
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, cancel)
    poll()
    if outcome is None:
        GLib.timeout_add(500, poll)
        loop.run()
    return 0 if outcome == 'succeeded' else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except dbus.DBusException as exc:
        # Public stable error name, never arbitrary remote payloads.
        emit('error', {'Error': exc.get_dbus_name()})
        sys.exit(1)
    except RuntimeError as exc:
        emit('error', {'Error': str(exc)})
        sys.exit(1)
