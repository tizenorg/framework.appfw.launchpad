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
#include <dlfcn.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <malloc.h>

#include <sqlite3.h>

#include <aul.h>
#include <Elementary.h>
#include <Ecore.h>
#include <bundle_internal.h>

#include "config.h" //should be included first

//including aul/launch
#include <access_control.h>
#include <app_sock.h>
#include <aul_util.h>
#include <menu_db_util.h>
#include <perf.h>
#include <simple_util.h>

#include "sigchild.h"

#include "process_pool.h"

#include "smack_util.h"

#define _static_ static inline
#define SQLITE_FLUSH_MAX	(1048576)	/* (1024*1024) */
#define AUL_POLL_CNT		15

#define EXEC_CANDIDATE_EXPIRED 5
#define EXEC_CANDIDATE_WAIT 1
#define DIFF(a,b) (((a)>(b))?(a)-(b):(b)-(a))
#define CANDIDATE_NONE 0

typedef struct
{
	int pid;
	int send_fd;
	int last_exec_time;
} candidate;

static int initialized = 0;
static candidate __candidate[LAUNCHPAD_TYPE_MAX] =
{
	{ CANDIDATE_NONE, -1, 0 },
	{ CANDIDATE_NONE, -1, 0 }
};
const char* const HOME = "HOME";
const char* const APP_HOME_PATH = "/opt/home/app";
const char* const ROOT_HOME_PATH = "/opt/home/root";

_static_ int __candidate_process_real_launch(int candidate_fd, app_pkt_t *pkt);
static inline int __parser(const char *arg, char *out, int out_size);
_static_ void __modify_bundle(bundle * kb, int caller_pid,
				app_info_from_db * menu_info, int cmd);
_static_ int __real_send(int clifd, int ret);
_static_ void __send_result_to_caller(int clifd, int ret, const char* app_path);
_static_ void __prepare_candidate_process(int type);
_static_ void __launchpad_main_loop(int launchpad_fd, int *pool_fd);
_static_ int __launchpad_pre_init(int argc, char **argv);
_static_ int __launchpad_post_init();

static app_info_from_db *_get_app_info_from_bundle_by_pkgname(
							const char *pkgname, bundle *kb);

_static_ int __candidate_process_real_launch(int candidate_fd, app_pkt_t *pkt)
{
	return __send_pkt_raw_data(candidate_fd, pkt);
}

/*
 * Parsing original app path to retrieve default bundle
 *
 * -1 : Invalid sequence
 * -2 : Buffer overflow
 *
 */
static inline int __parser(const char *arg, char *out, int out_size)
{
	register int i;
	int state = 1;
	char *start_out = out;

	if (arg == NULL || out == NULL) {
		/* Handles null buffer*/
		return 0;
	}

	for (i = 0; out_size > 1; i++) {
		switch (state) {
		case 1:
			switch (arg[i]) {
			case ' ':
			case '\t':
				state = 5;
				break;
			case '\0':
				state = 7;
				break;
			case '\"':
				state = 2;
				break;
			case '\\':
				state = 4;
				break;
			default:
				*out = arg[i];
				out++;
				out_size--;
				break;
			}
			break;
		case 2:	/* escape start*/
			switch (arg[i]) {
			case '\0':
				state = 6;
				break;
			case '\"':
				state = 1;
				break;
			default:
				*out = arg[i];
				out++;
				out_size--;
				break;
			}
			break;
		case 4:	/* character escape*/
			if (arg[i] == '\0') {
				state = 6;
			} else {
				*out = arg[i];
				out++;
				out_size--;
				state = 1;
			}
			break;
		case 5:	/* token*/
			if (out != start_out) {
				*out = '\0';
				out_size--;
				return i;
			}
			i--;
			state = 1;
			break;
		case 6:
			return -1;	/* error*/
		case 7:	/* terminate*/
			*out = '\0';
			out_size--;
			return 0;
		default:
			state = 6;
			break;	/* error*/
		}
	}

	if (out_size == 1)
		*out = '\0';

	/* Buffer overflow*/
	return -2;
}

_static_ void __modify_bundle(bundle * kb, int caller_pid,
				app_info_from_db * menu_info, int cmd)
{
	bundle_del(kb, AUL_K_PKG_NAME);
	bundle_del(kb, AUL_K_EXEC);
	bundle_del(kb, AUL_K_PACKAGETYPE);
	bundle_del(kb, AUL_K_HWACC);
	bundle_del(kb, AUL_K_TASKMANAGE);

	/* Parse app_path to retrieve default bundle*/
	if (cmd == APP_START
		|| cmd == APP_START_RES
		|| cmd == APP_OPEN
		|| cmd == APP_RESUME
		) {
		char *ptr;
		char exe[MAX_PATH_LEN];
		int flag;

		ptr = _get_original_app_path(menu_info);

		flag = __parser(ptr, exe, sizeof(exe));
		if (flag > 0) {
			char key[256];
			char value[256];

			ptr += flag;
			SECURE_LOGD("parsing app_path: EXEC - %s\n", exe);

			do {
				flag = __parser(ptr, key, sizeof(key));
				if (flag <= 0)
					break;
				ptr += flag;

				flag = __parser(ptr, value, sizeof(value));
				if (flag < 0)
					break;
				ptr += flag;

				/*bundle_del(kb, key);*/
				bundle_add(kb, key, value);
			} while (flag > 0);
		} else if (flag == 0)
			_D("parsing app_path: No arguments\n");
		else
			_D("parsing app_path: Invalid argument\n");
	}
}

_static_ int __real_send(int clifd, int ret)
{
	if (send(clifd, &ret, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
			close(clifd);
			return -1;
		}
		_E("send fail to client");
	}

	close(clifd);
	return 0;
}

_static_ void __send_result_to_caller(int clifd, int ret, const char* app_path)
{
	char *cmdline;
	int wait_count;
	int cmdline_changed = 0;
	int cmdline_exist = 0;
	int r;

	_W("Check app launching");

	if (clifd == -1)
		return;

	if (ret <= 1) {
		_E("launching failed");
		__real_send(clifd, ret);
		return;
	}
	/* check normally was launched?*/
	wait_count = 1;
	do {
		cmdline = __proc_get_cmdline_bypid(ret);
		if (cmdline == NULL) {
			_E("error founded when being launched with %d", ret);
			if (cmdline_exist || cmdline_changed) {
				_E("The app process might be terminated while we are wating %d", ret);
				break;
			}
		} else if (strcmp(cmdline, app_path) == 0) {
			/* Check app main loop is prepared or not */
			_D("-- now wait app mainloop creation --");
			free(cmdline);
			cmdline_changed = 1;

			char sock_path[UNIX_PATH_MAX] = { 0, };
			snprintf(sock_path, UNIX_PATH_MAX, "%s/%d", AUL_SOCK_PREFIX, ret);
			if (access(sock_path, F_OK) == 0)
				break;

		} else {
			_D("-- now wait cmdline changing --");
			cmdline_exist = 1;
			free(cmdline);
		}
		usleep(100 * 1000);	/* 100ms sleep*/
		wait_count++;

	} while (wait_count <= 50);	/* max 100*50ms will be sleep*/

	if ((!cmdline_exist) && (!cmdline_changed)) {
		__real_send(clifd, -1);	/* abnormally launched*/
		return;
	}

	if (!cmdline_changed)
		_E("process launched, but cmdline not changed");

	if(__real_send(clifd, ret) < 0) {
		r = kill(ret, SIGKILL);
		if (r == -1)
			_E("send SIGKILL: %s", strerror(errno));
	}

	return;
}

_static_ void __prepare_candidate_process(int type)
{
	int pid;

	__candidate[type].last_exec_time = time(NULL);

	pid = fork();

	if (pid == 0) { /* child */
		char type_str[2] = {0,};

		/* execute with very long (1024 bytes) argument in order to prevent argv overflow caused by dlopen */
		char *argv[] = {"/usr/bin/launchpad-loader", NULL,
"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ", NULL};
		__signal_unblock_sigchld();

		type_str[0] = '0' + type;
		argv[1] = type_str;
		if (execv(argv[0], argv) < 0)
			_E("Failed to prepare candidate_process");
		else
			_D("Succeeded to prepare candidate_process");

		exit(-1);
	}
}

static app_info_from_db *_get_app_info_from_bundle_by_pkgname(
			const char *pkgname, bundle *kb)
{
	app_info_from_db *menu_info;
	const char *ptr = NULL;

	menu_info = calloc(1, sizeof(app_info_from_db));
	if (menu_info == NULL)
		return NULL;

	menu_info->pkg_name = strdup(pkgname);
	ptr = bundle_get_val(kb, AUL_K_EXEC);
	if (ptr)
		menu_info->app_path = strdup(ptr);
	if (menu_info->app_path != NULL)
		menu_info->original_app_path = strdup(menu_info->app_path);
	ptr = bundle_get_val(kb, AUL_K_PACKAGETYPE);
	if (ptr)
		menu_info->pkg_type = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_HWACC);
	if (ptr)
		menu_info->hwacc = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_TASKMANAGE);
	if (ptr)
		menu_info->taskmanage = strdup(ptr);

	if (!_get_app_path(menu_info)) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	return menu_info;
}

_static_ void __sleep_safe(time_t sec)
{
	struct timespec delay, remain;
	delay.tv_sec = sec;
	delay.tv_nsec = 0;
	remain.tv_sec = 0;
	remain.tv_nsec = 0;

	while (nanosleep(&delay, &remain)) {
		if (errno == EINTR) {
			delay.tv_sec = remain.tv_sec;
			delay.tv_nsec = remain.tv_nsec;
		}
		else {
			_D("nanosleep() failed, errno: %d (%s)", errno, strerror(errno));
			break;
		}
	}
}

static int __send_launchpad_loader(int type, app_pkt_t *pkt, const char *app_path, int clifd)
{
	char sock_path[UNIX_PATH_MAX] = { 0, };
	int pid = -1;

	snprintf(sock_path, UNIX_PATH_MAX, "%s/%d", AUL_SOCK_PREFIX, __candidate[type].pid);
	unlink(sock_path);

	__candidate_process_real_launch(__candidate[type].send_fd, pkt);
	SECURE_LOGD("Request to candidate process, pid: %d, bin path: %s", __candidate[type].pid, app_path);

	pid = __candidate[type].pid;
	close(__candidate[type].send_fd);

	__candidate[type].pid = CANDIDATE_NONE;
	__candidate[type].send_fd = -1;

	/* Temporary log: launch time checking */
	//SECURE_LOG(LOG_DEBUG, "LAUNCH", "[%s:Platform:launchpad:done]", app_path);

	__send_result_to_caller(clifd, pid, app_path); //to AMD

	__sleep_safe(1); //1 sec
	__prepare_candidate_process(type);

	_D("Prepare another candidate process");
	return pid;
}

_static_ void __launchpad_main_loop(int launchpad_fd, int *pool_fd)
{
	bundle *kb = NULL;
	app_pkt_t *pkt = NULL;
	app_info_from_db *menu_info = NULL;

	const char *pkg_name = NULL;
	const char *internal_pool = NULL;
	const char *app_path = NULL;
	int pid = -1;
	int clifd = -1;
	struct ucred cr;
	int is_real_launch = 0;
	int type = -1;

	pkt = __app_recv_raw(launchpad_fd, &clifd, &cr);
	if (!pkt) {
		_E("packet is NULL");
		goto end;
	}

	kb = bundle_decode(pkt->data, pkt->len);
	if (!kb) {
		_E("bundle decode error");
		goto end;
	}

	INIT_PERF(kb);
	PERF("packet processing start");

	pkg_name = bundle_get_val(kb, AUL_K_PKG_NAME);
	SECURE_LOGD("pkg name : %s\n", pkg_name);

	menu_info = _get_app_info_from_bundle_by_pkgname(pkg_name, kb);
	if (menu_info == NULL) {
		_E("such pkg no found");
		goto end;
	}

	app_path = _get_app_path(menu_info);
	if(app_path == NULL) {
		_E("app_path is NULL");
		goto end;
	}
	if (app_path[0] != '/') {
		_E("app_path is not absolute path");
		goto end;
	}

	if (menu_info->hwacc == NULL) {
		_E("[launchpad] Failed to find H/W acceleration type");
		goto end;
	}

	internal_pool = bundle_get_val(kb, AUL_K_EXEC);
	SECURE_LOGD("exec : %s\n", internal_pool);
	internal_pool = bundle_get_val(kb, AUL_K_INTERNAL_POOL);
	SECURE_LOGD("internal pool : %s\n", internal_pool);
	SECURE_LOGD("hwacc : %s\n", menu_info->hwacc);
	type = __get_launchpad_type(internal_pool, menu_info->hwacc);
	if (type < 0) {
		_E("failed to get launchpad type");
		goto end;
	}

	__modify_bundle(kb, cr.pid, menu_info, pkt->cmd);
	pkg_name = _get_pkgname(menu_info);
	if (pkg_name == NULL){
		_E("unable to get pkg_name from menu_info");
		goto end;
	}

	PERF("get package information & modify bundle done");

	if ((type >= 0) && (type < LAUNCHPAD_TYPE_MAX) && (__candidate[type].pid != CANDIDATE_NONE)
		&& (DIFF(__candidate[type].last_exec_time, time(NULL)) > EXEC_CANDIDATE_WAIT))
	{
		_W("Launch on type-based process-pool");
		pid = __send_launchpad_loader(type, pkt, app_path, clifd);
		is_real_launch = 1;
	}
	else if ((__candidate[LAUNCHPAD_TYPE_COMMON].pid != CANDIDATE_NONE)
		&& (DIFF(__candidate[LAUNCHPAD_TYPE_COMMON].last_exec_time, time(NULL)) > EXEC_CANDIDATE_WAIT))
	{
		_W("Launch on common type process-pool");
		pid = __send_launchpad_loader(LAUNCHPAD_TYPE_COMMON, pkt, app_path, clifd);
		is_real_launch = 1;
	}
	else
	{
		// legacy logic(fork & exec) will be done in AMD
		_W("Candidate is not prepared, enter legacy logic");
		__send_result_to_caller(clifd, -ENOLAUNCHPAD, app_path);
	}
	clifd = -1;

end:
	if (clifd != -1)
		close(clifd);

	if (pid > 0) {
		if (is_real_launch)
			__send_app_launch_signal(pid, pkg_name);
	}

	if (menu_info != NULL)
		_free_app_info_from_db(menu_info);

	if (kb != NULL)
		bundle_free(kb);
	if (pkt != NULL)
		free(pkt);

	/* Active Flusing for Daemon */
	if (initialized > AUL_POLL_CNT) {
		sqlite3_release_memory(SQLITE_FLUSH_MAX);
		malloc_trim(0);
		initialized = 1;
	}
}

_static_ int __launchpad_pre_init(int argc, char **argv)
{
	int fd;

	/* signal init*/
	__signal_init();

	/* create launchpad sock */
	fd = __create_server_sock(PROCESS_POOL_LAUNCHPAD_PID);
	if (fd < 0) {
		_E("server sock error");
		return -1;
	}

	return fd;
}

_static_ int __launchpad_post_init()
{
	/* Setting this as a global variable to keep track
	of launchpad poll cnt */
	/* static int initialized = 0;*/

	if (initialized) {
		++initialized;
		return 0;
	}

	++initialized;

	return 0;
}

int main(int argc, char **argv)
{
	enum {
		LAUNCH_PAD = 0,
		POOL_TYPE = 1,
		CANDIDATE_TYPE = LAUNCHPAD_TYPE_MAX + 1,
		SIGCHLD_FD = LAUNCHPAD_TYPE_MAX * 2 + 1,
		POLLFD_MAX = LAUNCHPAD_TYPE_MAX * 2 + 2
	};
	int launchpad_fd = -1;
	int sigchld_fd = -1;
	int pool_fd[LAUNCHPAD_TYPE_MAX] = {
		-1
#ifdef _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING
		,-1
#endif // _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING
#ifdef _APPFW_FEATURE_PROCESS_POOL_COMMON
		,-1
#endif // _APPFW_FEATURE_PROCESS_POOL_COMMON
		};

	struct pollfd pfds[POLLFD_MAX];
	int i;

	memset(pfds, 0x00, sizeof(pfds));

	/* init without concerning X & EFL*/
	launchpad_fd = __launchpad_pre_init(argc, argv);
	if (launchpad_fd < 0) {
		_E("launchpad pre init failed");
		exit(-1);
	}
	pfds[LAUNCH_PAD].fd	 = launchpad_fd;
	pfds[LAUNCH_PAD].events  = POLLIN;
	pfds[LAUNCH_PAD].revents = 0;

	for (i = 0; i < LAUNCHPAD_TYPE_MAX; ++i) {
		pool_fd[i] = __listen_candidate_process(i);
		if (pool_fd[i] == -1) {
			_E("[launchpad] Listening the socket to the type %d candidate process failed.", i);
			goto error;
		}
		pfds[POOL_TYPE + i].fd	 = pool_fd[i];
		pfds[POOL_TYPE + i].events  = POLLIN;
		pfds[POOL_TYPE + i].revents = 0;
	}

	sigchld_fd = __signal_get_sigchld_fd();
	if (sigchld_fd == -1) {
		_E("failed to get sigchld fd");
		goto error;
	}
	pfds[SIGCHLD_FD].fd = sigchld_fd;
	pfds[SIGCHLD_FD].events = POLLIN;
	pfds[SIGCHLD_FD].revents = 0;

#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
	int res = setpriority(PRIO_PROCESS, 0, -12);
	if (res == -1) {
		SECURE_LOGE("Setting process (%d) priority to -12 failed, errno: %d (%s)",
				getpid(), errno, strerror(errno));
	}
#endif
	while (1) {
		for (i = 0; i < LAUNCHPAD_TYPE_MAX; ++i) {
			if (__candidate[i].pid == CANDIDATE_NONE) {
				pfds[CANDIDATE_TYPE + i].fd	  = -1;
				pfds[CANDIDATE_TYPE + i].events  = 0;
				pfds[CANDIDATE_TYPE + i].revents = 0;

				if (DIFF(__candidate[i].last_exec_time, time(NULL)) > EXEC_CANDIDATE_EXPIRED)
					__prepare_candidate_process(i);
			}
		}

		if (poll(pfds, POLLFD_MAX, -1) < 0)
			continue;

		_D("pfds[LAUNCH_PAD].revent  : 0x%x", pfds[LAUNCH_PAD].revents) ;
		for (i = 0; i < LAUNCHPAD_TYPE_MAX; ++i) {
			_D("pfds[POOL_TYPE + %d].revents : 0x%x", i, pfds[POOL_TYPE + i].revents) ;
			_D("pfds[CANDIDATE_TYPE + %d].revents : 0x%x", i, pfds[CANDIDATE_TYPE + i].revents);
		}

		/* init with concerning X & EFL (because of booting
		* sequence problem)*/
		if (__launchpad_post_init() < 0) {
			_E("launcpad post init failed");
			goto error;
		}

		if ((pfds[SIGCHLD_FD].revents & POLLIN) != 0) {
			struct signalfd_siginfo siginfo;
			ssize_t s;

			do {
				s = read(pfds[SIGCHLD_FD].fd, &siginfo, sizeof(struct signalfd_siginfo));
				if (s == 0)
					break;

				if (s != sizeof(struct signalfd_siginfo)) {
					_E("error reading sigchld info");
					break;
				}
				__launchpad_process_sigchld(&siginfo);
			} while (s > 0);
		}

		if ((pfds[LAUNCH_PAD].revents & POLLIN) != 0) {
			_D("pfds[LAUNCH_PAD].revents & POLLIN");
			__launchpad_main_loop(pfds[LAUNCH_PAD].fd, pool_fd);
		}

		for (i = 0; i < LAUNCHPAD_TYPE_MAX; ++i) {
			if ((pfds[POOL_TYPE + i].revents & POLLIN) != 0) {
				int server_fd, client_fd;
				int client_pid;

				server_fd = pfds[POOL_TYPE + i].fd;

				_D("pfds[POOL_TYPE + %d].revents & POLLIN", i);

				if (__candidate[i].pid == CANDIDATE_NONE) {
					__accept_candidate_process(server_fd, &client_fd, &client_pid);

					__candidate[i].pid = client_pid;
					__candidate[i].send_fd = client_fd;

					pfds[CANDIDATE_TYPE + i].fd	  = client_fd;
					pfds[CANDIDATE_TYPE + i].events  = POLLIN | POLLHUP;
					pfds[CANDIDATE_TYPE + i].revents = 0;

					SECURE_LOGD("Type %d candidate process was connected, pid: %d", i, __candidate[i].pid);
				} else {
					__refuse_candidate_process(server_fd);
					_E("Refused candidate process connection");
				}
			}

			if ((pfds[CANDIDATE_TYPE + i].revents & (POLLHUP | POLLNVAL)) != 0) {
				SECURE_LOGD("pfds[CANDIDATE_TYPE + %d].revents & (POLLHUP|POLLNVAL), pid: %d", i, __candidate[i].pid);

				if (pfds[CANDIDATE_TYPE + i].fd > -1)
					close(pfds[CANDIDATE_TYPE + i].fd);

				__candidate[i].pid = CANDIDATE_NONE;
				__candidate[i].send_fd = -1;

				pfds[CANDIDATE_TYPE + i].fd	  = -1;
				pfds[CANDIDATE_TYPE + i].events  = 0;
				pfds[CANDIDATE_TYPE + i].revents = 0;
			}
		}
	}

	return 0;

error:
	if (launchpad_fd != -1)
		close(launchpad_fd);

	for (i = 0; i < LAUNCHPAD_TYPE_MAX; ++i) {
		if (pool_fd[i] != -1)
			close(pool_fd[i]);
		if (__candidate[i].send_fd != -1)
			close(__candidate[i].send_fd);
	}

	return -1;
}
