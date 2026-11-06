#!/usr/bin/env python3
"""Non-secret diagnostic client; run as root/ns-controller. Does not scan."""
import argparse
import uuid
import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

parser = argparse.ArgumentParser()
parser.add_argument('device', help='Selected current org.bluez.Device1 object path')
parser.add_argument('--start', action='store_true', help='Explicitly enroll this controller; may replace its console association')
args = parser.parse_args()
DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus()
path = '/org/bluez/ns_os/switch2'
interface = 'org.ns_os.Switch2Enrollment1'
api = dbus.Interface(bus.get_object('org.bluez', path), interface)
print(dict(api.GetDeviceStatus(dbus.ObjectPath(args.device))))
if args.start:
    loop = GLib.MainLoop()
    operation = None
    revision = -1
    def display(which, state):
        global revision
        if str(which) != operation or int(state['Revision']) <= revision:
            return
        revision = int(state['Revision'])
        print(dict(state), flush=True)
        if str(state['Phase']) in ('succeeded', 'cancelled', 'timed_out', 'failed'):
            loop.quit()
    bus.add_signal_receiver(display, signal_name='OperationChanged', dbus_interface=interface, path=path)
    operation = str(api.StartEnrollment(dbus.ObjectPath(args.device), str(uuid.uuid4()), dbus.UInt32(120000)))
    baseline = api.GetOperation(dbus.ObjectPath(operation))
    display(operation, baseline)
    if str(baseline['Phase']) not in ('succeeded', 'cancelled', 'timed_out', 'failed'):
        try:
            loop.run()
        except KeyboardInterrupt:
            api.Cancel(dbus.ObjectPath(operation))
            print('Cancellation requested; reconcile with GetOperation. An acknowledged association is retained.')
