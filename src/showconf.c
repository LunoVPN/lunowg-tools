// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

#include "containers.h"
#include "encoding.h"
#include "ipc.h"
#include "subcommands.h"

static const char *masked_base64_key(const uint8_t key[static WG_KEY_LEN])
{
	static char base64[WG_KEY_LEN_BASE64];
	const char *var = getenv("WG_HIDE_KEYS");

	if (var && !strcmp(var, "never")) {
		key_to_base64(base64, key);
		return base64;
	}
	return "(hidden)";
}

int showconf_main(int argc, const char *argv[])
{
	char base64[WG_KEY_LEN_BASE64];
	struct wgdevice *device = NULL;
	struct wgpeer *peer;
	FILE *out = NULL;
	char *out_buf = NULL;
	size_t out_size = 0;
	int ret = 1;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s %s <interface>\n", PROG_NAME, argv[0]);
		return 1;
	}

	out = open_memstream(&out_buf, &out_size);
	if (!out) {
		perror("open_memstream");
		goto cleanup;
	}

	if (ipc_get_device(&device, argv[1])) {
		perror("Unable to access interface");
		goto cleanup;
	}

	fprintf(out, "[Interface]\n");
	if (device->listen_port)
		fprintf(out, "ListenPort = %u\n", device->listen_port);
	if (device->fwmark)
		fprintf(out, "FwMark = 0x%x\n", device->fwmark);
	if (device->flags & WGDEVICE_HAS_PRIVATE_KEY)
		fprintf(out, "PrivateKey = %s\n", masked_base64_key(device->private_key));
	if (device->flags & WGDEVICE_HAS_JC)
		fprintf(out, "Jc = %u\n", device->junk_packet_count);
	if (device->flags & WGDEVICE_HAS_JMIN)
		fprintf(out, "Jmin = %u\n", device->junk_packet_min_size);
	if (device->flags & WGDEVICE_HAS_JMAX)
		fprintf(out, "Jmax = %u\n", device->junk_packet_max_size);
	if (device->flags & WGDEVICE_HAS_S1)
		fprintf(out, "S1 = %u\n", device->init_packet_junk_size);
	if (device->flags & WGDEVICE_HAS_S2)
		fprintf(out, "S2 = %u\n", device->response_packet_junk_size);
	if (device->flags & WGDEVICE_HAS_S3)
		fprintf(out, "S3 = %u\n", device->cookie_reply_packet_junk_size);
	if (device->flags & WGDEVICE_HAS_S4)
		fprintf(out, "S4 = %u\n", device->transport_packet_junk_size);
	if (device->flags & WGDEVICE_HAS_H1)
		fprintf(out, "H1 = %s\n", device->init_packet_magic_header);
	if (device->flags & WGDEVICE_HAS_H2)
		fprintf(out, "H2 = %s\n", device->response_packet_magic_header);
	if (device->flags & WGDEVICE_HAS_H3)
		fprintf(out, "H3 = %s\n", device->underload_packet_magic_header);
	if (device->flags & WGDEVICE_HAS_H4)
		fprintf(out, "H4 = %s\n", device->transport_packet_magic_header);
	if (device->flags & WGDEVICE_HAS_I1)
		fprintf(out, "I1 = %s\n", device->i1);
	if (device->flags & WGDEVICE_HAS_I2)
		fprintf(out, "I2 = %s\n", device->i2);
	if (device->flags & WGDEVICE_HAS_I3)
		fprintf(out, "I3 = %s\n", device->i3);
	if (device->flags & WGDEVICE_HAS_I4)
		fprintf(out, "I4 = %s\n", device->i4);
	if (device->flags & WGDEVICE_HAS_I5)
		fprintf(out, "I5 = %s\n", device->i5);

	fprintf(out, "\n");
	for_each_wgpeer(device, peer) {
		key_to_base64(base64, peer->public_key);
		fprintf(out, "[Peer]\nPublicKey = %s\n", base64);
		if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
			fprintf(out, "PresharedKey = %s\n", masked_base64_key(peer->preshared_key));
		}
		if (peer->flags & WGPEER_HAS_AWG) {
			fprintf(out, "AdvancedSecurity = %s\n", peer->awg ? "on" : "off");
		}
		if (peer->first_allowedip)
			fprintf(out, "AllowedIPs = (hidden)\n");

		if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6)
			fprintf(out, "Endpoint = (hidden)\n");

		if (peer->persistent_keepalive_interval)
			fprintf(out, "PersistentKeepalive = %u\n", peer->persistent_keepalive_interval);

		if (peer->next_peer)
			fprintf(out, "\n");
	}
	ret = 0;

cleanup:
	if (out) {
		fflush(out);
		fclose(out);
	}
	if (!ret && out_buf && out_size) {
		fwrite(out_buf, 1, out_size, stdout);
	}
	free(out_buf);
	free_wgdevice(device);
	return ret;
}
