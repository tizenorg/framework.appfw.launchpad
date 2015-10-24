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
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/smack.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>

#include <simple_util.h>

#include "process_pool.h"
#include "smack_util.h"

#define SMACK_LABEL_LEN	255
#define FILE_MAX_LEN 1024
#define MAX_RETRY_CNT 1000
#define UID_ROOT 0

static char s_smack_label[SMACK_LABEL_LEN + 1] = {0,};
static int signal_cnt = 0;
static struct sigaction old_act;

static int smack_set_label_for_tid(const char *label)
{
	int len, fd, ret;
	char curren_path[FILE_MAX_LEN + 1] = {0,};

	len = strnlen(label, SMACK_LABEL_LEN + 1);
	if (len > SMACK_LABEL_LEN)
		return -1;

	snprintf(curren_path, sizeof(curren_path), "/proc/%d/attr/current",
		(int)syscall(SYS_gettid));
	fd = open(curren_path, O_WRONLY);
	if (fd < 0) {
		_E("open() failed. path: %s, errno: %d (%s)",
			curren_path, errno, strerror(errno));
		return -1;
	}

	ret = write(fd, label, len);
	close(fd);

	return (ret < 0) ? -1 : 0;
}

static void SIGUSR1_handler(int signo)
{
	if (smack_set_label_for_tid(s_smack_label) != 0)
		_E("smack_set_label_for_tid() failed!");

	SECURE_LOGD("tid: %d, signo: %d", (int)syscall(SYS_gettid), signo);
	++signal_cnt;
}

static int set_SIGUSR1_handler(void)
{
	struct sigaction new_act;

	sigemptyset(&new_act.sa_mask);
	new_act.sa_handler = SIGUSR1_handler;
	new_act.sa_flags = SA_RESTART;

	if (sigaction(SIGUSR1, &new_act, &old_act) == -1) {
		_E("sigaction(SIGUSR1) failed.");
		return -1;
	}

	return 0;
}

static int set_SIGUSR1_to_default(void)
{
	if (sigaction(SIGUSR1, &old_act, NULL) == -1) {
		_E("sigaction(SIGUSR1) failed.");
		return -1;
	}

	return 0;
}

static int send_SIGUSR1_to_threads(void)
{
	int ret;
	DIR *dir;
	struct dirent entry, *result;
	char proc_self_task_path[FILE_MAX_LEN + 1] = {0, };
	int main_tid = (int)syscall(SYS_gettid);
	int thr_cnt = 0;

	sprintf(proc_self_task_path, "/proc/self/task");

	dir = opendir(proc_self_task_path);
	if (dir) {
		for (ret = readdir_r(dir, &entry, &result);
				result != NULL && ret == 0;
				ret = readdir_r(dir, &entry, &result)) {
			if (strncmp(entry.d_name, ".", 2) == 0 ||
				strncmp(entry.d_name, "..", 3) == 0)
				continue;

			int tid = atoi(entry.d_name);
			if (main_tid != tid) {
				SECURE_LOGD("SIGUSR1 signal to the sub-thread (%d) is sent.", tid);
				if (syscall(SYS_tkill, tid, SIGUSR1) != 0) {
					_E("Sending SIGUSR1 singnal to sub-thread (%d) failed.", tid);
					closedir(dir);
					return -1;
				}
				++thr_cnt;
			}
		}

		closedir(dir);
	} else {
		_E("opendir(/proc/self/task) failed!");
		return -1;
	}

	return thr_cnt;
}

int set_app_smack_label(const char* app_path, int type)
{
	int thr_cnt = 0; // except main thread
	int i = 0;

	if (UID_ROOT != getuid() || app_path == NULL) {
		_E("parameter error!");
		return -1;
	}

	// set SIGUSR1 signal handler
	if (set_SIGUSR1_handler() != 0) {
		_E("Setting signal hanlder failed.");
		return -1;
	}

	// get smack label from app_path
	char *smack_label = NULL;

	if (smack_lgetlabel(app_path, &smack_label, SMACK_LABEL_EXEC) != 0) {
		_E("smack_lgetlabel() failed!");
		goto end;
	}

	if (smack_label) {
		strncpy(s_smack_label, smack_label, sizeof(s_smack_label));
		s_smack_label[SMACK_LABEL_LEN] = '\0';

		free(smack_label);
		smack_label = NULL;
	} else {
		_E("smack_label is NULL!");
		strcpy(s_smack_label, "");
	}

	signal_cnt = 0;

	thr_cnt = send_SIGUSR1_to_threads();
	if (thr_cnt < 0)
		goto end;
	else if (thr_cnt == 0) {
		set_SIGUSR1_to_default();
		return 0;
	}

	// wait for labeling on each tasks.
	for (i = 0; signal_cnt < thr_cnt && i < MAX_RETRY_CNT; ++i)
		usleep(1000); // 1 ms

	if (i == MAX_RETRY_CNT)
		_E("Thread subject label update failed.");

	_D("signal count: %d, launchpad type: %d", signal_cnt, type);

	// set SIGUSR1 signal default handler
	set_SIGUSR1_to_default();

	return 0;

end:
	set_SIGUSR1_to_default();

	return -1;
}
