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

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <X11/Xlib.h>
#include <sys/types.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/prctl.h>
#include <malloc.h>
#include <sys/resource.h>

#include "app_sock.h"
#include "aul.h"

#include "config.h"

#include "menu_db_util.h"
#include "simple_util.h"
#include "access_control.h"
#include "preload.h"
#include "preexec.h"
#include "perf.h"
#include "sigchild.h"
#include "aul_util.h"

#include "heap_dbg.h"

#include "util_x.h"

#include "gl.h"

#include <sqlite3.h>

#include "native_preload.h"

#define _static_ static inline
#define POLLFD_MAX 1
#define SQLITE_FLUSH_MAX	(1048576)	/* (1024*1024) */
#define AUL_POLL_CNT		15
#define AUL_PR_NAME			16


static char *launchpad_cmdline;
static char *__appid = NULL;
static int initialized = 0;

_static_ void __set_env(app_info_from_db * menu_info, bundle * kb);
_static_ int __prepare_exec(const char *pkg_name,
			    const char *app_path, app_info_from_db * menu_info,
			    bundle * kb);
_static_ int __fake_launch_app(int cmd, int pid, bundle * kb);
_static_ char **__create_argc_argv(bundle * kb, int *margc);
_static_ int __normal_fork_exec(int argc, char **argv);
_static_ void __real_launch(const char *app_path, bundle * kb);
static inline int __parser(const char *arg, char *out, int out_size);
_static_ void __modify_bundle(bundle * kb, int caller_pid,
			    app_info_from_db * menu_info, int cmd);
_static_ int __child_raise_win_by_x(int pid, void *priv);
_static_ int __raise_win_by_x(int pid);
_static_ int __send_to_sigkill(int pid);
_static_ int __term_app(int pid);
_static_ int __resume_app(int pid);
_static_ int __real_send(int clifd, int ret);
_static_ void __send_result_to_caller(int clifd, int ret);
_static_ void __launchpad_main_loop(int main_fd);
_static_ int __launchpad_pre_init(int argc, char **argv);
_static_ int __launchpad_post_init();

extern ail_error_e ail_db_close(void);

_static_ void __set_env(app_info_from_db * menu_info, bundle * kb)
{
	const char *str;

	setenv("PKG_NAME", _get_pkgname(menu_info), 1);

	USE_ENGINE("gl")

	str = bundle_get_val(kb, AUL_K_STARTTIME);
	if (str != NULL)
		setenv("APP_START_TIME", str, 1);

	if (menu_info->hwacc != NULL)
		setenv("HWACC", menu_info->hwacc, 1);
	if (menu_info->taskmanage != NULL)
		setenv("TASKMANAGE", menu_info->taskmanage, 1);
}

_static_ int __prepare_exec(const char *pkg_name,
			    const char *app_path, app_info_from_db * menu_info,
			    bundle * kb)
{
	char *file_name;
	char process_name[AUL_PR_NAME];
	int ret;

	/* Set new session ID & new process group ID*/
	/* In linux, child can set new session ID without check permission */
	/* TODO : should be add to check permission in the kernel*/
	setsid();

	__preexec_run(menu_info->pkg_type, pkg_name, app_path);

	/* SET PRIVILEGES*/
	SECURE_LOGD("pkg_name : %s / pkg_type : %s / app_path : %s ", pkg_name, menu_info->pkg_type, app_path);
	if ((ret = __set_access(pkg_name, menu_info->pkg_type, app_path)) < 0) {
		 _D("fail to set privileges - check your package's credential : %d\n", ret);
		return -1;
	}
	/* SET DUMPABLE - for coredump*/
	prctl(PR_SET_DUMPABLE, 1);

	/* SET PROCESS NAME*/
	if (app_path == NULL) {
		_D("app_path should not be NULL - check menu db");
		return -1;
	}
	file_name = strrchr(app_path, '/') + 1;
	if (file_name == NULL) {
		_D("can't locate file name to execute");
		return -1;
	}
	memset(process_name, '\0', AUL_PR_NAME);
	snprintf(process_name, AUL_PR_NAME, "%s", file_name);
	prctl(PR_SET_NAME, process_name);

	/* SET ENVIROMENT*/
	__set_env(menu_info, kb);

	return 0;
}

_static_ int __fake_launch_app(int cmd, int pid, bundle * kb)
{
	int datalen;
	int ret;
	bundle_raw *kb_data;

	bundle_encode(kb, &kb_data, &datalen);
	if ((ret = __app_send_raw(pid, cmd, kb_data, datalen)) < 0)
		_E("error request fake launch - error code = %d", ret);
	free(kb_data);
	return ret;
}

_static_ char **__create_argc_argv(bundle * kb, int *margc)
{
	char **argv;
	int argc;

	argc = bundle_export_to_argv(kb, &argv);

	*margc = argc;
	return argv;
}

_static_ int __normal_fork_exec(int argc, char **argv)
{
	_D("start real fork and exec\n");

#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
	int res = setpriority(PRIO_PROCESS, 0, 0);
	if (res == -1)
	{
		SECURE_LOGE("Setting process (%d) priority to 0 failed, errno: %d (%s)",
				getpid(), errno, strerror(errno));
	}
#endif
	if (execv(argv[0], argv) < 0) {	/* Flawfinder: ignore */
		if (errno == EACCES)
			_E("such a file is no executable - %s", argv[0]);
		else
			_E("unknown executable error - %s", argv[0]);
		return -1;
	}
	/* never reach*/
	return 0;
}

_static_ void __real_launch(const char *app_path, bundle * kb)
{
	int app_argc;
	char **app_argv;
	int i;

	app_argv = __create_argc_argv(kb, &app_argc);
	app_argv[0] = strdup(app_path);

	for (i = 0; i < app_argc; i++) {
		if( (i%2) == 1)
			continue;
		SECURE_LOGD("input argument %d : %s##", i, app_argv[i]);
	}

	PERF("setup argument done");

	/* Temporary log: launch time checking */
	SECURE_LOG(LOG_DEBUG, "LAUNCH", "[%s:Platform:launchpad:done]", app_path);

	__preload_exec(app_argc, app_argv);

	__normal_fork_exec(app_argc, app_argv);
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

	if (out_size == 1) {
		*out = '\0';
	}
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
		|| cmd == APP_START_ASYNC
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
		|| cmd == APP_START_MULTI_INSTANCE
#endif
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
		} else if (flag == 0) {
			_D("parsing app_path: No arguments\n");
		} else {
			_D("parsing app_path: Invalid argument\n");
		}
	}
}

_static_ int __child_raise_win_by_x(int pid, void *priv)
{
	return x_util_raise_win(pid);
}

_static_ int __raise_win_by_x(int pid)
{
	int pgid;
	if (x_util_raise_win(pid) == 0)
		return 0;

	/* support app launched by shell script*/
	pgid = getpgid(pid);
	_D("X raise failed. try to find first child & raise it - c:%d p:%d\n",
	   pgid, pid);

	if (pgid <= 1)
		return -1;
	if (__proc_iter_pgid(pgid, __child_raise_win_by_x, NULL) < 0)
		return -1;

	return 0;
}

_static_ int __send_to_sigkill(int pid)
{
	int pgid;

	pgid = getpgid(pid);
	if (pgid <= 1)
		return -1;

	if (killpg(pgid, SIGKILL) < 0)
		return -1;

	return 0;
}

_static_ int __term_app(int pid)
{
	int dummy;
	if (__app_send_raw
	    (pid, APP_TERM_BY_PID, (unsigned char *)&dummy, sizeof(int)) < 0) {
		_D("terminate packet send error - use SIGKILL");
		if (__send_to_sigkill(pid) < 0) {
			_E("fail to killing - %d\n", pid);
			return -1;
		}
	}
	_D("term done\n");
	return 0;
}

_static_ int __resume_app(int pid)
{
	int dummy;
	int ret;
	if ((ret =
	     __app_send_raw(pid, APP_RESUME_BY_PID, (unsigned char *)&dummy,
			    sizeof(int))) < 0) {
		if (ret == -EAGAIN)
			_E("resume packet timeout error");
		else {
			_D("resume packet send error - use raise win");
			if (__raise_win_by_x(pid) < 0) {
				_E("raise failed - %d resume fail\n", pid);
				_E("we will term the app - %d\n", pid);
				__send_to_sigkill(pid);
				ret = -1;
			} else
				ret = 0;
		}
	}
	_D("resume done\n");
	return ret;
}

static int __get_caller_pid(bundle *kb)
{
	const char *pid_str;
	int pid;

	pid_str = bundle_get_val(kb, AUL_K_ORG_CALLER_PID);
	if(pid_str)
		goto end;

	pid_str = bundle_get_val(kb, AUL_K_CALLER_PID);
	if (pid_str == NULL)
		return -1;

end:
	pid = atoi(pid_str);
	if (pid <= 1)
		return -1;

	return pid;
}

_static_ int __foward_cmd(int cmd, bundle *kb, int cr_pid)
{
	int pid;
	char tmp_pid[MAX_PID_STR_BUFSZ];
	int datalen;
	bundle_raw *kb_data;
	int res;

	if ((pid = __get_caller_pid(kb)) < 0)
			return AUL_R_ERROR;

	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", cr_pid);

	bundle_add(kb, AUL_K_CALLEE_PID, tmp_pid);

	bundle_encode(kb, &kb_data, &datalen);
	if ((res = __app_send_raw_with_noreply(pid, cmd, kb_data, datalen)) < 0)
		res = AUL_R_ERROR;

	free(kb_data);

	return res;
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

_static_ void __send_result_to_caller(int clifd, int ret)
{
	char *cmdline;
	int wait_count;
	int cmdline_changed = 0;
	int cmdline_exist = 0;
	int r;

	if (clifd == -1)
		return;

	if (ret <= 1) {
		__real_send(clifd, ret);
		return;
	}
	/* check normally was launched?*/
	wait_count = 1;
	do {
		cmdline = __proc_get_cmdline_bypid(ret);
		if (cmdline == NULL) {
			_E("error founded when being launched with %d", ret);

		} else if (strcmp(cmdline, launchpad_cmdline)) {
			free(cmdline);
			cmdline_changed = 1;
			break;
		} else {
			cmdline_exist = 1;
			free(cmdline);
		}

		_D("-- now wait to change cmdline --");
		usleep(100 * 1000);	/* 50ms sleep*/
		wait_count++;
	} while (wait_count <= 20);	/* max 100*20ms will be sleep*/

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

static app_info_from_db *_get_app_info_from_bundle_by_pkgname(
							const char *pkgname, bundle *kb)
{
	app_info_from_db *menu_info;

	menu_info = calloc(1, sizeof(app_info_from_db));
	if (menu_info == NULL) {
		return NULL;
	}

	menu_info->pkg_name = strdup(pkgname);
	menu_info->app_path = strdup(bundle_get_val(kb, AUL_K_EXEC));
	if (menu_info->app_path != NULL)
		menu_info->original_app_path = strdup(menu_info->app_path);
	menu_info->pkg_type = strdup(bundle_get_val(kb, AUL_K_PACKAGETYPE));
	menu_info->hwacc = strdup(bundle_get_val(kb, AUL_K_HWACC));
	menu_info->taskmanage = strdup(bundle_get_val(kb, AUL_K_TASKMANAGE));

	if (!_get_app_path(menu_info)) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	return menu_info;
}

static void __release_appid_at_exit(void)
{
	if (__appid != NULL) {
		free(__appid);
	}
}

_static_ void __launchpad_main_loop(int main_fd)
{
	bundle *kb = NULL;
	app_pkt_t *pkt = NULL;
	app_info_from_db *menu_info = NULL;

	const char *pkg_name = NULL;
	const char *app_path = NULL;
	int pid = -1;
	int clifd = -1;
	struct ucred cr;
	int is_real_launch = 0;

	char sock_path[UNIX_PATH_MAX] = {0,};

	pkt = __app_recv_raw(main_fd, &clifd, &cr);
	if (!pkt) {
		_D("packet is NULL");
		goto end;
	}

	kb = bundle_decode(pkt->data, pkt->len);
	if (!kb) {
		_D("bundle decode error");
		goto end;
	}

	INIT_PERF(kb);
	PERF("packet processing start");

	pkg_name = bundle_get_val(kb, AUL_K_PKG_NAME);
	SECURE_LOGD("pkg name : %s\n", pkg_name);

	menu_info = _get_app_info_from_bundle_by_pkgname(pkg_name, kb);
	if (menu_info == NULL) {
		_D("such pkg no found");
		goto end;
	}

	app_path = _get_app_path(menu_info);
	if(app_path == NULL) {
		_E("app_path is NULL");
		goto end;
	}
	if (app_path[0] != '/') {
		_D("app_path is not absolute path");
		goto end;
	}

	__modify_bundle(kb, cr.pid, menu_info, pkt->cmd);
	pkg_name = _get_pkgname(menu_info);

	PERF("get package information & modify bundle done");

	{
		pid = fork();
		if (pid == 0) {
			PERF("fork done");
			_D("lock up test log(no error) : fork done");

			close(clifd);
			close(main_fd);
			__signal_unset_sigchld();
			__signal_fini();

			snprintf(sock_path, UNIX_PATH_MAX, "%s/%d", AUL_SOCK_PREFIX, getpid());
			unlink(sock_path);

			PERF("prepare exec - first done");
			_D("lock up test log(no error) : prepare exec - first done");

			__appid = strdup(pkg_name);
			aul_set_preinit_appid(__appid);
			atexit(__release_appid_at_exit);

			if (__prepare_exec(pkg_name, app_path,
					   menu_info, kb) < 0) {
				SECURE_LOGE("preparing work fail to launch - "
				   "can not launch %s\n", pkg_name);
				exit(-1);
			}

			PERF("prepare exec - second done");
			_D("lock up test log(no error) : prepare exec - second done");

			__real_launch(app_path, kb);

			exit(-1);
		}
		SECURE_LOGD("==> real launch pid : %d %s\n", pid, app_path);
		is_real_launch = 1;
	}

 end:
	__send_result_to_caller(clifd, pid);

	if (pid > 0) {
		if (is_real_launch) {
			/*TODO: retry*/
			__signal_block_sigchld();
			__send_app_launch_signal(pid);
			__signal_unblock_sigchld();
		}
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

	/* get my(launchpad) command line*/
	launchpad_cmdline = __proc_get_cmdline_bypid(getpid());
	if (launchpad_cmdline == NULL) {
		_E("launchpad cmdline fail to get");
		return -1;
	}
	_D("launchpad cmdline = %s", launchpad_cmdline);

	/* create launchpad sock        */
	fd = __create_server_sock(NATIVE_LAUNCHPAD_PID);
	if (fd < 0) {
		_E("server sock error");
		return -1;
	}

	__preload_init(argc, argv);

	__preload_init_for_native();

	__preexec_init(argc, argv);

	return fd;
}

_static_ int __launchpad_post_init()
{
	/* Setting this as a global variable to keep track
	of launchpad poll cnt */
	/* static int initialized = 0;*/

	if (initialized) {
		initialized++;
		return 0;
	}

	if (__signal_set_sigchld() < 0)
		return -1;

	initialized++;

	return 0;
}

int main(int argc, char **argv)
{
	int main_fd;
	struct pollfd pfds[POLLFD_MAX];
	int i;

	/* init without concerning X & EFL*/
	main_fd = __launchpad_pre_init(argc, argv);
	if (main_fd < 0) {
		_E("launchpad pre init failed");
		exit(-1);
	}

	pfds[0].fd = main_fd;
	pfds[0].events = POLLIN;
	pfds[0].revents = 0;

#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
	int res = setpriority(PRIO_PROCESS, 0, -12);
	if (res == -1)
	{
		SECURE_LOGE("Setting process (%d) priority to -12 failed, errno: %d (%s)",
				getpid(), errno, strerror(errno));
	}
#endif
	while (1) {
		if (poll(pfds, POLLFD_MAX, -1) < 0)
			continue;

		/* init with concerning X & EFL (because of booting
		sequence problem)*/
		if (__launchpad_post_init() < 0) {
			_E("launcpad post init failed");
			exit(-1);
		}

		for (i = 0; i < POLLFD_MAX; i++) {
			if ((pfds[i].revents & POLLIN) != 0) {
				__launchpad_main_loop(pfds[i].fd);
			}
		}
	}
}

