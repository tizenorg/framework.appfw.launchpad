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

#ifndef __NATIVE_PRELOAD_H__
#define __NATIVE_PRELOAD_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#define NATIVE_PRELOAD_FILE SHARE_PREFIX"/launchpad-native-preload-list.txt"

static int g_dlopen_size = 5;
static int g_dlopen_count = 0;
static void** g_dlopen_handle_list = NULL;

static inline int __preload_save_dlopen_handle(void *handle)
{
    if (!handle) {
        return 1;
    }
    if (g_dlopen_count == g_dlopen_size || !g_dlopen_handle_list) {
        void** tmp =
            realloc(g_dlopen_handle_list, 2 * g_dlopen_size * sizeof(void *));
        if (NULL == tmp) {
            _E("out of memory\n");
            dlclose(handle);
            return 1;
        }
        g_dlopen_size *= 2;
        g_dlopen_handle_list = tmp;
    }
    g_dlopen_handle_list[g_dlopen_count++] = handle;
    return 0;
}

static inline void __preload_fini_for_native(void)
{
    int i = 0;
    if (!g_dlopen_handle_list) {
        return;
    }
    for (i = 0; i < g_dlopen_count; ++i)
    {
        void *handle = g_dlopen_handle_list[i];
        if (handle) {
            if (0 != dlclose(handle)) {
                _E("dlclose failed\n");
            }
        }
    }
    free(g_dlopen_handle_list);
    g_dlopen_handle_list = NULL;
    g_dlopen_size = 5;
    g_dlopen_count = 0;
}

static inline void __preload_init_for_native(void)
{
    if (atexit(__preload_fini_for_native) != 0) {
        _E("Cannot register atexit callback. Libraries will not be unloaded");
    }

	void *handle = NULL;
	char soname[MAX_LOCAL_BUFSZ] = { 0, };
	FILE *preload_list = NULL;

	preload_list = fopen(NATIVE_PRELOAD_FILE, "rt");
	if (preload_list == NULL) {
		_E("no preload\n");
		return;
	}

	while (fgets(soname, MAX_LOCAL_BUFSZ, preload_list) > 0) {
        size_t len = strnlen(soname, MAX_LOCAL_BUFSZ);
        if (len > 0) {
            soname[len - 1] = '\0';
        }
		handle = dlopen((const char *) soname, RTLD_NOW);
		if (handle == NULL) {
            _E("dlopen(\"%s\") was failed!", soname);
            continue;
        }

        if (__preload_save_dlopen_handle(handle) != 0) {
            _E("Cannot save handle, no more preloads");
            break;
        }
        _D("preload %s# - handle : %x\n", soname, handle);
	}

	fclose(preload_list);
}

#endif //__NATIVE_PRELOAD_H__
