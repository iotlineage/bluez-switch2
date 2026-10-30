/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Included after transport teardown helpers. Pairing is opt-in via a root-only
 * request in BlueZ's device storage. Key installation is done by the guest
 * helper WITH BLUETOOTHD STOPPED, then normal startup loads the complete key
 * set. This first experiment needs no BlueZ-core or kernel ABI patch. */

static void switch2_enroll_path(struct switch2_session *s, char path[PATH_MAX],
		const char *name)
{
	create_filename(path, PATH_MAX, "/%s/%s/%s",
		btd_adapter_get_storage_dir(s->adapter), s->address, name);
}

static bool switch2_enroll_save(struct switch2_session *s, const char *state)
{
	char path[PATH_MAX], host[18], key[33];
	GKeyFile *file = g_key_file_new();
	GError *err = NULL;
	char *data;
	gsize length;
	unsigned int i;
	bool ok;

	ba2str(btd_adapter_get_address(s->adapter), host);
	g_key_file_set_string(file, "Enrollment", "Adapter", host);
	g_key_file_set_string(file, "Enrollment", "Peer", s->address);
	g_key_file_set_string(file, "Enrollment", "State", state);
	g_key_file_set_string(file, "Enrollment", "Build", SWITCH2_BUILD_ID);
	g_key_file_set_integer(file, "Enrollment", "Subcommand", s->enroll_step);
	g_key_file_set_int64(file, "Enrollment", "UpdatedUsec", g_get_real_time());
	if (s->enroll_key_ready) {
		for (i = 0; i < 16; i++)
			sprintf(key + 2 * i, "%02X", s->enroll_key[i]);
		g_key_file_set_string(file, "Enrollment", "KeyLE", key);
		explicit_bzero(key, sizeof(key));
	}
	data = g_key_file_to_data(file, &length, NULL);
	switch2_enroll_path(s, path, "switch2-enrollment");
	ok = g_file_set_contents_full(path, data, length,
		G_FILE_SET_CONTENTS_CONSISTENT | G_FILE_SET_CONTENTS_DURABLE,
		0600, &err);
	if (!ok) {
		error("switch2: enroll %s persistence failed: %s", s->address,
			err ? err->message : "unknown");
		g_clear_error(&err);
	}
	explicit_bzero(data, length);
	g_free(data);
	g_key_file_free(file);
	info("switch2: enroll %s state=%s step=0x%02x build=%s",
		s->address, state, s->enroll_step, SWITCH2_BUILD_ID);
	return ok;
}

static void switch2_enroll_fail(struct switch2_session *s, const char *reason)
{
	error("switch2: enroll %s failed step=0x%02x reason=%s",
		s->address, s->enroll_step, reason);
	switch2_enroll_save(s, reason);
	switch2_schedule_stop(s);
}

static gboolean switch2_enroll_timeout(gpointer data)
{
	struct switch2_session *s = data;
	s->enroll_timeout = 0;
	switch2_enroll_fail(s, "timeout");
	return G_SOURCE_REMOVE;
}

static void switch2_enroll_timer(struct switch2_session *s)
{
	if (s->enroll_timeout)
		g_source_remove(s->enroll_timeout);
	s->enroll_timeout = g_timeout_add(5000, switch2_enroll_timeout, s);
}

static bool switch2_enroll_send(struct switch2_session *s, uint8_t step,
		const uint8_t *data, size_t length)
{
	uint8_t packet[64];
	size_t size = switch2_pair_packet(packet, sizeof(packet), step, data, length);
	s->enroll_step = step;
	info("switch2: enroll %s tx cmd=0x15 sub=0x%02x bytes=%zu handle=0x0016",
		s->address, step, size);
	if (!size || !bt_gatt_client_write_without_response(s->gatt, 0x0016,
			false, packet, size)) {
		explicit_bzero(packet, sizeof(packet));
		switch2_enroll_fail(s, "write-failed");
		return false;
	}
	explicit_bzero(packet, sizeof(packet));
	switch2_enroll_timer(s);
	return true;
}

static void switch2_enroll_bootstrap(bool success, uint8_t ecode, void *data)
{
	struct switch2_session *s = data;
	uint8_t addresses[8] = { 0x00, 0x01 };
	s->enroll_write_id = 0;
	if (s->stopping)
		return;
	if (!success) {
		error("switch2: enroll %s bootstrap ATT error=0x%02x", s->address, ecode);
		switch2_enroll_fail(s, "bootstrap-failed");
		return;
	}
	memcpy(addresses + 2, btd_adapter_get_address(s->adapter), 6);
	switch2_enroll_send(s, 0x01, addresses, sizeof(addresses));
}

/* Return true while enrollment blocks kernel initialization. Consume a request
 * once; a crash/disconnect never automatically repeats controller flash writes. */
static bool switch2_enroll_begin(struct switch2_session *s)
{
	char path[PATH_MAX], claimed[PATH_MAX];
	struct stat st;
	static const uint8_t bootstrap[] = { 0x01, 0x00 };
	if (s->enroll_active)
		return true;
	if (s->enroll_checked)
		return false;
	s->enroll_checked = true;
	switch2_enroll_path(s, path, "switch2-enroll.request");
	if (lstat(path, &st) < 0)
		return false;
	if (!S_ISREG(st.st_mode) || st.st_uid || (st.st_mode & 077) ||
	    g_get_real_time() / G_USEC_PER_SEC - st.st_mtime > 300) {
		error("switch2: enroll %s ignored unsafe request permissions", s->address);
		return false;
	}
	switch2_enroll_path(s, claimed, "switch2-enroll.claimed");
	if (rename(path, claimed) < 0) {
		error("switch2: enroll %s could not claim request", s->address);
		return false;
	}
	s->enroll_active = true;
	if (btd_adapter_get_address_type(s->adapter) == BDADDR_LE_RANDOM ||
	    device_get_le_address_type(s->device) != BDADDR_LE_PUBLIC) {
		switch2_enroll_fail(s, "public-address-required");
		return true;
	}
	if (!switch2_pair_random(s->enroll_component) ||
	    !switch2_pair_random(s->enroll_challenge)) {
		switch2_enroll_fail(s, "crypto-unavailable");
		return true;
	}
	if (!switch2_enroll_save(s, "started")) {
		switch2_schedule_stop(s);
		return true;
	}
	info("switch2: enroll %s host=%s mtu=%u peer_type=%u",
		s->address, btd_adapter_get_storage_dir(s->adapter),
		bt_gatt_client_get_mtu(s->gatt), device_get_le_address_type(s->device));
	s->enroll_write_id = bt_gatt_client_write_value(s->gatt, 0x0005,
		bootstrap, sizeof(bootstrap), switch2_enroll_bootstrap, s, NULL);
	if (!s->enroll_write_id)
		switch2_enroll_fail(s, "bootstrap-write-failed");
	else
		switch2_enroll_timer(s);
	return true;
}

static void switch2_enroll_reply(struct switch2_session *s,
		const uint8_t *value, uint16_t length)
{
	uint8_t payload[17] = { 0 }, encrypted[16];
	size_t needed = s->enroll_step == 1 ? 9 :
			(s->enroll_step == 3 ? 1 : 17);
	/* Unrelated notifications must not advance a transaction. */
	if (s->stopping || s->stop_source || !s->enroll_step || length < 4 || value[0] != 0x15 ||
	    value[3] != s->enroll_step)
		return;
	info("switch2: enroll %s rx sub=0x%02x bytes=%u ack=0x%02x",
		s->address, s->enroll_step, length, length > 5 ? value[5] : 0);
	if (!switch2_pair_reply(value, length, s->enroll_step, needed)) {
		switch2_enroll_fail(s, "invalid-reply");
		return;
	}
	if (s->enroll_timeout) {
		g_source_remove(s->enroll_timeout);
		s->enroll_timeout = 0;
	}
	switch (s->enroll_step) {
	case 1:
		if (value[10] != 1 || memcmp(value + 11,
				device_get_address(s->device), 6)) {
			switch2_enroll_fail(s, "peer-address-mismatch");
			break;
		}
		memcpy(payload + 1, s->enroll_component, 16);
		switch2_enroll_send(s, 4, payload, sizeof(payload));
		break;
	case 4:
		switch2_pair_key(s->enroll_component, value + 9, s->enroll_key);
		s->enroll_key_ready = true;
		memcpy(payload + 1, s->enroll_challenge, 16);
		switch2_enroll_send(s, 2, payload, sizeof(payload));
		break;
	case 2:
		if (!switch2_pair_encrypt_le(s->enroll_key,
				s->enroll_challenge, encrypted) ||
		    !switch2_pair_challenge(encrypted, value + 9)) {
			switch2_enroll_fail(s, "challenge-mismatch");
			break;
		}
		/* Durable recovery key BEFORE committing controller storage. */
		if (!switch2_enroll_save(s, "commit-pending")) {
			switch2_schedule_stop(s);
			break;
		}
		switch2_enroll_send(s, 3, payload, 1);
		break;
	case 3:
		if (!switch2_enroll_save(s, "complete")) {
			switch2_schedule_stop(s);
			break;
		}
		s->enroll_active = false;
		info("switch2: enroll %s committed; guest helper must import key with daemon stopped", s->address);
		switch2_maybe_attach_kernel(s);
		break;
	}
	explicit_bzero(payload, sizeof(payload));
	explicit_bzero(encrypted, sizeof(encrypted));
}
