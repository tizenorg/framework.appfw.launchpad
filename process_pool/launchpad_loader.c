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
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>

#include <sqlite3.h>

#include <aul.h>
#include <Elementary.h>
#include <Ecore.h>
#include <bundle_internal.h>

#include "config.h" //should be included first

//including aul/launch
#include <access_control.h>
#include <app_sock.h>
#include <menu_db_util.h>
#include <perf.h>
#include <simple_util.h>

#include "preload.h"

#include "process_pool.h"
#include "process_pool_preload.h"
#include "preexec.h"

#include "smack_util.h"

#define AUL_PR_NAME			16

#define LOWEST_PRIO 20

static char *__appid = NULL;
static char *__pkgid = NULL;

const char* const HOME = "HOME";
const char* const APP_HOME_PATH = "/opt/home/app";
const char* const ROOT_HOME_PATH = "/opt/home/root";
#define APP_UID 5000
#define ROOT_UID 0

static inline void __set_uid(uid_t uid);
static inline void __set_env(app_info_from_db *menu_info, bundle *kb);
static inline char **__create_argc_argv(bundle *kb, int *margc);
static inline int __parser(const char *arg, char *out, int out_size);
static inline void __modify_bundle(bundle * kb, int caller_pid,
				app_info_from_db * menu_info, int cmd);

static app_info_from_db *_get_app_info_from_bundle_by_pkgname(
			const char *pkgname, bundle *kb);

static inline void __init_group(uid_t uid)
{
	int res;
	struct passwd *pw;

	pw = getpwuid(uid);
	if (!pw) {
		_E("failed to get pw from uid: %d: %s", uid, strerror(errno));
		return;
	}

	res = initgroups(pw->pw_name, pw->pw_gid);
	if (res == -1)
		_E("failed to initgroups for uid: %d: %s", uid, strerror(errno));
}

static inline void __set_uid(uid_t uid)
{
	int res;

	if (uid != ROOT_UID)
		__init_group(uid);

	res = setresuid(uid, uid, ROOT_UID);
	if (res == -1) {
		_E("failed to set user id to %d: %s", uid, strerror(errno));
		return;
	}

	if (uid == ROOT_UID)
		__init_group(uid);
}

static inline void __set_env(app_info_from_db * menu_info, bundle * kb)
{
	const char *str;

	setenv("PKG_NAME", _get_pkgname(menu_info), 1);

	str = bundle_get_val(kb, AUL_K_STARTTIME);
	if (str != NULL)
		setenv("APP_START_TIME", str, 1);

	if (menu_info->hwacc != NULL)
		setenv("HWACC", menu_info->hwacc, 1);
	if (menu_info->taskmanage != NULL)
		setenv("TASKMANAGE", menu_info->taskmanage, 1);
}

static inline char **__create_argc_argv(bundle * kb, int *margc)
{
	char **argv;
	int argc;

	argc = bundle_export_to_argv(kb, &argv);

	*margc = argc;
	return argv;
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

static inline void __modify_bundle(bundle * kb, int caller_pid,
			app_info_from_db * menu_info, int cmd)
{
	bundle_del(kb, AUL_K_PKG_NAME);
	bundle_del(kb, AUL_K_EXEC);
	bundle_del(kb, AUL_K_PACKAGETYPE);
	bundle_del(kb, AUL_K_HWACC);
	bundle_del(kb, AUL_K_TASKMANAGE);
	bundle_del(kb, AUL_K_PKGID);

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

static inline int __candidate_process_prepare_exec(const char *pkg_name,
			const char *app_path, app_info_from_db *menu_info,
			bundle *kb, int type)
{
	const char *file_name = NULL;
	char process_name[AUL_PR_NAME] = { 0, };
	int ret = 0;

	if (set_app_smack_label(app_path, type) != 0)
		_E("set_app_smack_label() failed");

	__preexec_run(menu_info->pkg_type, pkg_name, app_path);

	/* SET PRIVILEGES*/
	SECURE_LOGD("[candidata] pkg_name : %s / pkg_type : %s / app_path : %s",
			pkg_name, menu_info->pkg_type, app_path);
	if ((ret = __set_access(pkg_name, menu_info->pkg_type, app_path)) < 0) {
		_D("fail to set privileges - check your package's credential : %d\n", ret);
		return -1;
	}

	/*
	 * SET DUMPABLE - for coredump
	 * This dumpable flag should be set after calling perm_app_set_privilege()
	 */
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

static bundle *_s_bundle = NULL;
static void __at_exit_to_release_bundle()
{
	if (_s_bundle) {
		bundle_free(_s_bundle);
		_s_bundle = NULL;
	}
}

static void __release_appid_at_exit(void)
{
	if (__appid != NULL) {
		free(__appid);
	}
	if (__pkgid != NULL) {
		free(__pkgid);
	}
}

static inline void __candidate_process_launchpad_main_loop(app_pkt_t* pkt,
			char* out_app_path, int* out_argc, char ***out_argv,
			int type)
{
	bundle *kb = NULL;
	app_info_from_db *menu_info = NULL;

	const char *app_id = NULL;
	const char *app_path = NULL;
	const char *pkg_id = NULL;

	kb = bundle_decode(pkt->data, pkt->len);
	if (!kb) {
		_E("bundle decode error");
		exit(-1);
	}

	if (_s_bundle != NULL)
		bundle_free(_s_bundle);

	_s_bundle = kb;
	atexit(__at_exit_to_release_bundle);

	app_id = bundle_get_val(kb, AUL_K_PKG_NAME);
	if (app_id == NULL) {
		_E("Unable to get app_id");
		exit(-1);
	}

	menu_info = _get_app_info_from_bundle_by_pkgname(app_id, kb);
	if (menu_info == NULL) {
		_D("such pkg no found");
		exit(-1);
	}

	if (type < 0) {
		_E("Invalid launchpad type: %d", type);
		exit(-1);
	}

	SECURE_LOGD("app id: %s, launchpad type: %d", app_id, type);

	app_path = _get_app_path(menu_info);
	if (app_path == NULL) {
		_E("app_path is NULL");
		exit(-1);
	}

	if (app_path[0] != '/') {
		_E("app_path is not absolute path");
		exit(-1);
	}

	__modify_bundle(kb, /*cr.pid - unused parameter*/ 0, menu_info, pkt->cmd);

	// caching appid
	app_id = _get_pkgname(menu_info);
	if (app_id == NULL) {
		_E("unable to get app_id from menu_info");
		exit(-1);
	}
	SECURE_LOGD("app id: %s", app_id);

	__appid = strdup(app_id);
	if (__appid == NULL) {
		_E("Out of memory");
		exit(-1);
	}
	aul_set_preinit_appid(__appid);

	// caching pkgid
	pkg_id = _get_pkgid(menu_info);
	if (pkg_id == NULL) {
		_E("unable to get pkg_id from menu_info");
		exit(-1);
	}
	SECURE_LOGD("pkg id: %s", pkg_id);

	__pkgid = strdup(pkg_id);
	if (__pkgid == NULL) {
		_E("Out of memory");
		exit(-1);
	}
	aul_set_preinit_pkgid(__pkgid);

	atexit(__release_appid_at_exit);

#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
	const char *high_priority = bundle_get_val(kb, AUL_K_HIGHPRIORITY);
	_D("high_priority: %s", high_priority);

	if(strncmp(high_priority, "true", 4) == 0) {
		int res = setpriority(PRIO_PROCESS, 0, -10);
		if (res == -1) {
			SECURE_LOGE("Setting process (%d) priority to -10 failed, errno: %d (%s)",
				getpid(), errno, strerror(errno));
		}
	}
	bundle_del(kb, AUL_K_HIGHPRIORITY);
#endif

	if (__candidate_process_prepare_exec(app_id, app_path, menu_info, kb, type) < 0) {
		_E("__candidate_process_prepare_exec() failed");
		if (access(app_path, F_OK | R_OK)) {
			SECURE_LOGE("access() failed for file: \"%s\", error: %d (%s)",
				app_path, errno, strerror(errno));
		}
		exit(-1);
	}

	if (out_app_path != NULL && out_argc != NULL && out_argv != NULL) {
		int i = 0;

		memset(out_app_path, '\0', strlen(out_app_path));
		sprintf(out_app_path, "%s", app_path);

		*out_argv = __create_argc_argv(kb, out_argc);
		(*out_argv)[0] = out_app_path;

		for (i = 0; i < *out_argc; i++)
			SECURE_LOGD("input argument %d : %s##", i, (*out_argv)[i]);
	} else
		exit(-1);

	if (menu_info != NULL)
		_free_app_info_from_db(menu_info);
}

static Eina_Bool __candidate_proces_fd_handler(void* data,
			Ecore_Fd_Handler *handler)
{
	int type = data ? *((int *)data) : LAUNCHPAD_TYPE_UNSUPPORTED;
	int fd = ecore_main_fd_handler_fd_get(handler);

	/* recover to root to process privileged operations */
	__set_uid(ROOT_UID);

	if (fd == -1) {
		_D("[candidate] ECORE_FD_GET");
		exit(-1);
	}

	if (ecore_main_fd_handler_active_get(handler, ECORE_FD_ERROR)) {
		_D("[candidate] ECORE_FD_ERROR");
		close(fd);
		exit(-1);
	}

	if (ecore_main_fd_handler_active_get(handler, ECORE_FD_READ)) {
		_D("[candidate] ECORE_FD_READ");
		app_pkt_t* pkt = (app_pkt_t*) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
		if (!pkt) {
			_D("[candidate] out of memory1");
			exit(-1);
		}
		memset(pkt, 0, AUL_SOCK_MAXBUFF);

		int recv_ret = recv(fd, pkt, AUL_SOCK_MAXBUFF, 0);
		close(fd);
		if (recv_ret == -1) {
			_D("[condidate] recv error!");
			free(pkt);
			exit(-1);
		}
		_D("[candidate] recv_ret: %d, pkt->len: %d", recv_ret, pkt->len);

		ecore_main_fd_handler_del(handler);

		__candidate_process_launchpad_main_loop(pkt, g_argv[0], &g_argc, &g_argv, type);
		SECURE_LOGD("[candidate] real app argv[0]: %s, real app argc: %d", g_argv[0], g_argc);
		free(pkt);

		ecore_main_loop_quit();
		_D("[candidate] ecore main loop quit");
	}

	return ECORE_CALLBACK_CANCEL;
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
	ptr = bundle_get_val(kb, AUL_K_PKGID);
	if (ptr)
		menu_info->pkg_id= strdup(ptr);

	if (!_get_app_path(menu_info)) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	return menu_info;
}

int main(int argc, char **argv)
{
	static int type = LAUNCHPAD_TYPE_UNSUPPORTED;
	int elm_init_cnt = 0;
	Ecore_Fd_Handler *fd_handler = NULL;
	void *handle = NULL;
	int (*dl_main)(int, char **);
	int client_fd;
	int res;

	if (argc < 2) {
		_E("too few argument.");
		return -1;
	}

	type = argv[1][0] - '0';
	if (type < 0 || type >= LAUNCHPAD_TYPE_MAX) {
		_E("invalid argument. (type: %d)", type);
		return -1;
	}

	//temp - this requires some optimization.
	sleep(1);
	_D("sleeping 1 sec...");

	__preload_init(argc, argv);
	__preload_init_for_process_pool();
	__preexec_init(argc, argv);

	res = setpriority(PRIO_PROCESS, 0, LOWEST_PRIO);
	if (res == -1) {
		SECURE_LOGE("Setting process (%d) priority to %d failed, errno: %d (%s)",
				getpid(), LOWEST_PRIO, errno, strerror(errno));
	}
	_D("[candidate] Another candidate process was forked.");

	/* Set new session ID & new process group ID*/
	/* In linux, child can set new session ID without check permission */
	/* TODO : should be add to check permission in the kernel*/
	setsid();

	client_fd = __connect_to_launchpad(type);
	if (client_fd == -1) {
		_D("Connecting to candidate process was failed.");
		return -1;
	}

	{
		/* dummy code for hacking dbus setuid issue. */
		DBusError err;
		dbus_error_init(&err);
		DBusConnection *tmp_con = dbus_bus_get_private(DBUS_BUS_SYSTEM, &err);
		dbus_connection_set_exit_on_disconnect(tmp_con, FALSE);
		dbus_connection_close(tmp_con);
		dbus_connection_unref(tmp_con);
	}

	/* elementary related initialization is needed to be run as the app user */
	__set_uid(APP_UID);

	/* Temporarily change HOME path to app
	   This change is needed for getting elementary profile
	   /opt/home/app/.elementary/config/mobile/base.cfg */
	setenv(HOME, APP_HOME_PATH, 1);

	elm_init_cnt = elm_init(g_argc, g_argv);
	_D("[candidate] elm init, returned: %d", elm_init_cnt);

#ifdef _APPFW_FEATURE_PROCESS_POOL_SW_RENDERING
	if (type == LAUNCHPAD_TYPE_SW) {
		elm_config_accel_preference_set("none");
	}
#endif // _APPFW_FEATURE_PROCESS_POOL_SW_RENDERING
#ifdef _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING
	if (type == LAUNCHPAD_TYPE_HW) {
		elm_config_accel_preference_set("hw");
	}
#endif // _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING
#ifdef _APPFW_FEATURE_PROCESS_POOL_COMMON
	if (type != LAUNCHPAD_TYPE_COMMON)
#endif // _APPFW_FEATURE_PROCESS_POOL_COMMON
	{
		Evas_Object *win = elm_win_add(NULL, "package_name", ELM_WIN_BASIC);
		if (win) {
			aul_set_preinit_window(win);

			Evas_Object *bg = elm_bg_add(win);
			if (bg) {
				evas_object_size_hint_weight_set(bg, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
				elm_win_resize_object_add(win, bg);
				aul_set_preinit_background(bg);
			} else {
				_E("[candidate] elm_bg_add() failed");
			}

			Evas_Object *conform = elm_conformant_add(win);
			if (conform) {
				evas_object_size_hint_weight_set(conform, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
				elm_win_resize_object_add(win, conform);
				aul_set_preinit_conformant(conform);
			} else {
				_E("elm_conformant_add() failed");
			}
		} else {
			_E("[candidate] elm_win_add() failed");
		}
	}
#ifdef _APPFW_FEATURE_PROCESS_POOL_COMMON
	else {
		char *theme = elm_theme_list_item_path_get(
			eina_list_data_get(elm_theme_list_get(NULL)), NULL);
		Eina_Bool is_exist = edje_file_group_exists(theme, "*");
		if (!is_exist)
			_D("theme path: %s", theme);

		if (theme)
			free(theme);
	}
#endif //_APPFW_FEATURE_PROCESS_POOL_COMMON

	fd_handler = ecore_main_fd_handler_add(client_fd,
			(Ecore_Fd_Handler_Flags)(ECORE_FD_READ|ECORE_FD_ERROR),
			__candidate_proces_fd_handler, &type, NULL, NULL);
	if (fd_handler == NULL) {
		_D("fd_handler is NULL");
		return -1;
	}

	_D("[candidate] ecore handler add");

	/* recover to root to process privileged operations */
	__set_uid(ROOT_UID);

	res = setpriority(PRIO_PGRP, 0, 0);
	if (res == -1) {
		SECURE_LOGE("Setting process (%d) priority to 0 failed, errno: %d (%s)",
			getpid(), errno, strerror(errno));
	}

	/* set uid to app again to finish elementary related initialization in the main loop */
	__set_uid(APP_UID);

	_D("[candidate] ecore main loop begin");
	ecore_main_loop_begin();

	SECURE_LOGD("[candidate] Launch real application (%s)", g_argv[0]);
	handle = dlopen(g_argv[0], RTLD_LAZY | RTLD_GLOBAL);
	if (handle == NULL) {
		_E("dlopen failed(%s). Please complile with -fPIE and link with -pie flag", dlerror());
		goto do_exec;
	}

	dlerror();

	dl_main = dlsym(handle, "main");
	if (dl_main != NULL)
		res = dl_main(g_argc, g_argv);
	else {
		_E("dlsym not founded(%s). Please export 'main' function", dlerror());
		dlclose(handle);
		goto do_exec;
	}

	dlclose(handle);
	return res;

do_exec:
	if (access(g_argv[0], F_OK | R_OK)) {
		SECURE_LOGE("access() failed for file: \"%s\", error: %d (%s)",
			g_argv[0], errno, strerror(errno));
	} else {
		SECURE_LOGD("[candidate] Exec application (%s)", g_argv[0]);
		if (execv(g_argv[0], g_argv) < 0) {
			SECURE_LOGE("execv() failed for file: \"%s\", error: %d (%s)",
				g_argv[0], errno, strerror(errno));
		}
	}
	return -1;
}
