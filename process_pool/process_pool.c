/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/un.h>
#include <errno.h>
#include <systemd/sd-daemon.h>

#include <simple_util.h>

#include "process_pool.h"

#define TMP_PATH "/tmp"
#define LAUNCHPAD_TYPE ".launchpad-type"

#define MAX_PENDING_CONNECTIONS 10
#define CONNECT_RETRY_TIME 100 * 1000
#define CONNECT_RETRY_COUNT 3

int __listen_candidate_process(int type)
{
	struct sockaddr_un addr;
	int fd = -1;
	int listen_fds = 0;
	int i;

	_D("[launchpad] enter, type: %d", type);

	memset(&addr, 0x00, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, "%s/%s%d", TMP_PATH, LAUNCHPAD_TYPE, type);

	listen_fds = sd_listen_fds(0);
	if (listen_fds < 0) {
		_E("Invalid systemd environment");
		return -1;
	} else if (listen_fds > 0) {
		for (i = 0; i < listen_fds; i++) {
			fd = SD_LISTEN_FDS_START + i;
			if (sd_is_socket_unix(fd, SOCK_STREAM, 1, addr.sun_path, 0))
				return fd;
		}
		_E("Socket not found: %s", addr.sun_path);
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		_E("Socket error");
		goto error;
	}

	unlink(addr.sun_path);

	_D("bind to %s", addr.sun_path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		_E("bind error");
		goto error;
	}

	_D("chmod %s", addr.sun_path);
	if (chmod(addr.sun_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0) {
		_E("chmod error");
		goto error;
	}

	_D("listen to %s", addr.sun_path);
	if (listen(fd, MAX_PENDING_CONNECTIONS) == -1) {
		_E("listen error");
		goto error;
	}

	SECURE_LOGD("[launchpad] done, listen fd: %d", fd);
	return fd;

error:
	if (fd != -1)
		close(fd);

	return -1;
}

int __connect_to_launchpad(int type)
{
	struct sockaddr_un addr;
	int fd = -1;
	int retry = CONNECT_RETRY_COUNT;
	int send_ret = -1;
	int client_pid = getpid();

	_D("[launchpad] enter, type: %d", type);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		_E("socket error");
		goto error;
	}

	memset(&addr, 0x00, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, "%s/%s%d", TMP_PATH, LAUNCHPAD_TYPE, type);

	_D("connect to %s", addr.sun_path);
	while (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		if (errno != ETIMEDOUT || retry <= 0) {
			_E("connect error : %d", errno);
			goto error;
		}

		usleep(CONNECT_RETRY_TIME);
		--retry;
		_D("re-connect to %s (%d)", addr.sun_path, retry);
	}

	send_ret = send(fd, &client_pid, sizeof(client_pid), 0);
	_D("send(%d) : %d", client_pid, send_ret);

	if (send_ret == -1) {
		_E("send error");
		goto error;
	}

	SECURE_LOGD("[launchpad] done, connect fd: %d", fd);
	return fd;

error:
	if (fd != -1)
		close(fd);

	return -1;
}

int __accept_candidate_process(int server_fd, int* out_client_fd, int* out_client_pid)
{
	int client_fd = -1, client_pid = 0, recv_ret = 0;

	if (server_fd == -1 || out_client_fd == NULL || out_client_pid == NULL) {
		_E("arguments error!");
		goto error;
	}

	client_fd = accept(server_fd, NULL, NULL);

	if (client_fd == -1) {
		_E("accept error!");
		goto error;
	}

	recv_ret = recv(client_fd, &client_pid, sizeof(client_pid), MSG_WAITALL);

	if (recv_ret == -1) {
		_E("recv error!");
		goto error;
	}

	*out_client_fd = client_fd;
	*out_client_pid = client_pid;

	return *out_client_fd;

error:
	if (client_fd != -1)
		close(client_fd);

	return -1;
}

void __refuse_candidate_process(int server_fd)
{
	int client_fd = -1;

	if (server_fd == -1) {
		_E("arguments error!");
		goto error;
	}

	client_fd = accept(server_fd, NULL, NULL);
	if (client_fd == -1) {
		_E("accept error!");
		goto error;
	}

	close(client_fd);
	_D("refuse connection!");

error:
	return;
}

int __send_pkt_raw_data(int client_fd, app_pkt_t *pkt)
{
	int send_ret = 0;
	int pkt_size = 0;

	if (client_fd == -1 || pkt == NULL) {
		_E("arguments error!");
		goto error;
	}

	pkt_size = sizeof(pkt->cmd) + sizeof(pkt->len) + pkt->len;

	send_ret = send(client_fd, pkt, pkt_size, 0);
	_D("send(%d) : %d / %d", client_fd, send_ret, pkt_size);

	if (send_ret == -1) {
		_E("send error!");
		goto error;
	} else if (send_ret != pkt_size) {
		_E("send byte fail!");
		goto error;
	}

	return 0;

error:
	return -1;
}
