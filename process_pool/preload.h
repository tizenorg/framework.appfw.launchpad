/*
 *  aul
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>, Jaeho Lee <jaeho81.lee@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */


#ifdef PRELOAD_ACTIVATE

#include <dlfcn.h>
#define PRELOAD_FILE SHARE_PREFIX"/preload_list.txt"

#define EFL_PREINIT_FUNC	"elm_quicklaunch_init"
#define EFL_SHUTDOWN_FUNC	"elm_quicklaunch_shutdown"

static int preload_initialized = 0;
static int g_argc;
static char **g_argv;
static int max_cmdline_size = 0;

static int (*dl_einit) () = NULL;
static int (*dl_efini) () = NULL;

static inline void __preload_init(int argc, char **argv)
{
	void *handle = NULL;
	char soname[MAX_LOCAL_BUFSZ];
	FILE *preload_list;
	int (*func)() = NULL;
	int i;

	g_argc = argc;
	g_argv = argv;
	for (i = 0; i < argc; i++) {
		max_cmdline_size += (strlen(argv[i]) + 1);
	}
	_D("max_cmdline_size = %d", max_cmdline_size);

	preload_list = fopen(PRELOAD_FILE, "rt");
	if (preload_list == NULL) {
		_E("no preload\n");
		return;
	}

	while (fgets(soname, MAX_LOCAL_BUFSZ, preload_list) > 0) {
		soname[strlen(soname) - 1] = 0;
		handle = dlopen((const char *) soname, RTLD_NOW);
		if (handle == NULL)
			continue;
		_D("preload %s# - handle : %x\n", soname, handle);

		func = dlsym(handle, EFL_PREINIT_FUNC);
		if (func != NULL) {
			_D("get pre-initialization function\n");
			dl_einit = func;
			func = dlsym(handle, EFL_SHUTDOWN_FUNC);
			if (func != NULL) {
				_D("get shutdown function\n");
				dl_efini = func;
			}
		}
	}

	fclose(preload_list);
	preload_initialized = 1;
}

static inline int preinit_init()
{
	if (dl_einit != NULL)
		dl_einit(0, NULL);
	_D("pre-initialzation on");
	return 0;
}

static inline int preinit_fini()
{
	if (dl_efini != NULL)
		dl_efini();
	_D("pre-initialization off");
	return 0;
}

/* TODO : how to set cmdline gracefully ?? */
static inline int __change_cmdline(char *cmdline)
{
	if (strlen(cmdline) > max_cmdline_size + 1) {
		_E("cmdline exceed max size : %d", max_cmdline_size);
		return -1;
	}

	memset(g_argv[0], '\0', max_cmdline_size);
	snprintf(g_argv[0], max_cmdline_size, "%s", cmdline);

	return 0;
}

static inline void __preload_exec(int argc, char **argv)
{
	void *handle = NULL;
	int (*dl_main) (int, char **);
	char *error = NULL;

	if (!preload_initialized)
		return;

	handle = dlopen(argv[0], RTLD_LAZY | RTLD_GLOBAL);
	if (handle == NULL) {
		_E("dlopen(\"%s\") failed", argv[0]);
		if ((error = dlerror()) != NULL) {
			_E("dlopen error: %s", error);
		}
		return;
	}

	dlerror();

	dl_main = dlsym(handle, "main");
	if (dl_main != NULL) {
		if (__change_cmdline(argv[0]) < 0) {
			_E("change cmdline fail");
			dlclose(handle);
			return;
		}

#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
		int res = setpriority(PRIO_PROCESS, 0, 0);
		if (res == -1)
		{
			SECURE_LOGE("Setting process (%d) priority to 0 failed, errno: %d (%s)",
					getpid(), errno, strerror(errno));
		}
#endif
		dl_main(argc, argv);
	} else {
		_E("dlsym not founded. bad preloaded app - check fpie pie");
		if ((error = dlerror()) != NULL) {
			_E("dlsym error: %s", error);
		}
		dlclose(handle);
		return;
	}

	exit(0);
}

#else

static inline void __preload_init();
static inline void __preload_exec(int argc, char **argv);

#endif

