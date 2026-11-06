# Live enrollment API v1 — experimental, hardware acceptance pending

The provider is built into **BlueZ 5.87**, including the core adapter patch in
`patches/bluez-5.87-live-keys.patch`. `switch2-live.inc` replaces the old request-file
workflow. Normal discovery does not enroll anything. The old development helper
must not be used to enroll with this version.

Introspection is published in `org.ns_os.Switch2Enrollment1.xml`. The bus name is
`org.bluez`, manager `/org/bluez/ns_os/switch2`, interface
`org.ns_os.Switch2Enrollment1`. `enroll.py DEVICE` reads status; `--start` explicitly
enrolls that currently selected Device1 object. It does not start discovery.
Controller-service owns discovery; Menu and games must never call this API.

## Authorization and consumer handoff

Install `policy/ns-controller.conf` with systemd-sysusers and the D-Bus policy in
`policy/org.ns_os.Switch2Enrollment1.conf`. Both bus policy and asynchronous
GetConnectionUnixUser checks restrict methods to root and **ns-controller**.
A desktop-UID service is not authorized. Run the consumer under this dedicated
principal, granting only its required evdev/uinput access and its own public IPC
policy. Do not authorize the entire desktop user or run Menu as root.

Operations belong to the actual unique bus sender; only that sender can cancel.
An authorized replacement service can list/read outcomes. Signals are directed to
the owner. Subscribe before baseline GetOperation, accept increasing Revision,
and invalidate cached provider paths on org.bluez owner/InstanceId changes.
Never turn a controller-service candidate hash into a BlueZ path by guessing.

Bounds: four active or pending-I/O operations, 64 retained outcomes, retention at
least 300 seconds, request IDs 1–128 bytes, timeouts 1–180000 ms. The API responds
asynchronously, including its credential lookup. CapacityReached preserves all
existing outcomes. Identical sender/request/arguments return the same operation.
Conflicting arguments return InvalidArguments. Device removal invalidates the
old generation; storage writes retain a directory fd across path replacement.

Capabilities describes implementation support. Start additionally requires the
adapter's successful UUID/version probe of the additive kernel operation. A
missing kernel extension returns KernelCapabilityMissing **before controller
writes**. A new adapter probes again. New BlueZ alone cannot enable enrollment.

## Persistence and activation

The built-in plugin owns `/var/lib/bluetooth/ADAPTER/PEER/switch2-association`:
root-owned 0600, version 1, Adapter/Peer bindings and KeyLE in private INI storage.
It is canonical BlueZ-owned association storage, separate from generic `info`.
Never copy it into normal logs, telemetry or issue attachments. Storage runs on
two worker threads; callbacks and BlueZ state updates run on the main context.

1. Validate Nintendo manufacturer/product metadata (057e:2067 left, 057e:2066
   right), public addresses, selected current object and expected GATT layout.
2. Run the existing bootstrap and 15/01, 15/04, 15/02 exchange. Verify returned
   peer address and cryptographic challenge. Metadata/GATT are not cryptographic
   manufacturer attestation; the peer-address/challenge checks bind this exchange.
3. Durably write `commit-pending` **before** the irreversible 15/03 command.
4. Validate acknowledgement, durably replace journal with `acknowledged`.
5. Disconnect only the selected target if needed; add its LTK using experimental
   management command 0x0100 with the mandatory UUID/version handshake. Never send
   LOAD_LONG_TERM_KEYS, reset the adapter, restart bluetoothd, or disconnect other
   devices during enrollment. Re-enable target autoconnect after activation.
6. Only then mark paired/bonded/trusted and report all three success flags true.

`registered` requires acknowledged + durable + active, independent of evdev
availability. The controller service must still verify real input separately.

The Linux patch is maintained in the **iotlineage/linux-switch2** fork at
`patches/linux-7.3-switch2-additive-ltk.patch`. It modifies Bluetooth core, not the
`/dev/switch2-gatt` ABI. The add-only command refuses a different existing key,
accepts an identical one idempotently, and refuses a new key while the target has
an LE connection. Other peer keys and connections are not replaced. SMP and
management LTK writers share a lock. Full-list loading is rejected while LE/ACL
connections exist, addressing the pointer-lifetime hazard described in
https://lkml.iu.edu/hypermail/linux/kernel/2610.1/12392.html . This is a project
extension, not an upstream Linux or BlueZ ABI.

## Recovery and cancellation

Before commit, cancellation aborts local work and records `aborted` if necessary.
After commit, cancellation is best effort: known acknowledgement still leads to
bounded persistence/activation. It never restores the previous console bond.

Restart reads journals without discovery or controller enrollment writes.
Acknowledged associations recover using the same key. A validated legacy
`switch2-enrollment` with State=complete is migrated locally. Commit-pending,
malformed, conflicting, insecure or incorrectly bound records are explicitly
`recovery_required`; they never trigger automatic re-enrollment or key rotation.
Lost acknowledgements currently require investigation of private evidence; this
version does **not** attempt speculative encryption to resolve an ambiguous key.
Timed-out operations retain their terminal outcome; late completed local I/O may
update durability/activation flags. No public state contains protocol payloads.

Rollback preserves both old and new journals. An older daemon cannot understand
the new canonical journal: keep the new binaries available to recover it; do not
expect stock BlueZ alone to reconnect newly enrolled Joy-Con 2 devices. Do not
use old helpers to clear or overwrite records as a rollback procedure.

## Stable error suffixes

Errors use `org.ns_os.Switch2Enrollment1.Error.` plus PermissionDenied,
InvalidArguments, UnknownOperation, UnsupportedDevice, UnsupportedAddress,
DeviceRemoved, AdapterRemoved, PoweredOff, RadioBlocked, Busy, CapacityReached,
KernelCapabilityMissing, AlreadyRegistered, AssociationExists, RecoveryRequired,
OwnerUnavailable, CryptoUnavailable, ProtocolBootstrapFailed,
ProtocolWriteFailed, ProtocolAcknowledgementFailed, PeerAddressMismatch,
ChallengeFailed, Disconnected, Timeout, StorageFailed or ActivationFailed.
ErrorMessage intentionally contains only the stable code. Consult retained flags
and RegistrationState to distinguish uncertain commit from safe precommit failure.

## Verification and limits

`make check` builds actual provider code against a private bus and fake GATT/key
backend. `tests/run-live.py` covers both identities, deduplication, cancellation,
lost ACK, durable I/O failures, actual process exit at journal/commit boundaries,
same-key restart recovery, invalid journals, device directory replacement, missing
kernel capability and simulated input dispatch during slow storage. Private-bus
tests exercise authorization, directed revision signals, owner loss, bounds and
instance replacement. No test opens a host Bluetooth socket.

These are **software fixtures**, not physical acceptance. Both halves still need
new-API enrollment, encrypted wake reconnect/input, restart/reboot, simultaneous
wireless-controller/audio/USB input, adapter removal and later Menu/game tests.
Kernel core module loading/ABI and recovery under real adapters also need host
validation. The controller-service consumer and its dedicated UID deployment are
separate work; this provider patch alone does not enable Menu's Register button.
