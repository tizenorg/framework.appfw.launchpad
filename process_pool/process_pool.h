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

#ifndef __PROCESS_POOL_H_
#define __PROCESS_POOL_H_

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include <app_sock.h>
#include <vconf.h>

int  __listen_candidate_process(int type);
int  __connect_to_launchpad(int type);
int  __accept_candidate_process(int server_fd, int* out_client_fd, int* out_client_pid);
void __refuse_candidate_process(int server_fd);
int  __send_pkt_raw_data(int client_fd, app_pkt_t* pkt);

enum LAUNCHPAD_TYPE {
	LAUNCHPAD_TYPE_UNSUPPORTED = -1,
#ifdef _APPFW_FEATURE_PROCESS_POOL_COMMON
	LAUNCHPAD_TYPE_COMMON,
#endif /* _APPFW_FEATURE_PROCESS_POOL_COMMON */
#ifdef _APPFW_FEATURE_PROCESS_POOL_SW_RENDERING
	LAUNCHPAD_TYPE_SW,
#endif /* _APPFW_FEATURE_PROCESS_POOL_SW_RENDERING */
#ifdef _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING
	LAUNCHPAD_TYPE_HW,
#endif /* _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING */
	LAUNCHPAD_TYPE_MAX
};

static inline int __get_launchpad_type(const char* internal_pool, const char* hwacc)
{
#if defined(_APPFW_FEATURE_PROCESS_POOL_SW_RENDERING) || defined(_APPFW_FEATURE_PROCESS_POOL_HW_RENDERING)
	if (internal_pool && strncmp(internal_pool, "true", 4) == 0 && hwacc) {
#ifdef _APPFW_FEATURE_PROCESS_POOL_SW_RENDERING
		if (strncmp(hwacc, "NOT_USE", 7) == 0) {
			_D("[launchpad] launchpad type: S/W(%d)", LAUNCHPAD_TYPE_SW);
			return LAUNCHPAD_TYPE_SW;
		}
#endif /* _APPFW_FEATURE_PROCESS_POOL_SW_RENDERING */
#ifdef _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING
		if (strncmp(hwacc, "USE", 3) == 0) {
			_D("[launchpad] launchpad type: H/W(%d)", LAUNCHPAD_TYPE_HW);
			return LAUNCHPAD_TYPE_HW;
		}
#endif /* _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING */

		if (strncmp(hwacc, "SYS", 3) == 0) {
			int r;
			int sys_hwacc = -1;

			r = vconf_get_int(VCONFKEY_SETAPPL_APP_HW_ACCELERATION, &sys_hwacc);
			if (r != VCONF_OK)
				_E("failed to get vconf int: %s", VCONFKEY_SETAPPL_APP_HW_ACCELERATION);

			SECURE_LOGD("sys hwacc: %d", sys_hwacc);

#ifdef _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING
			if (sys_hwacc == SETTING_HW_ACCELERATION_ON) {
				_D("[launchpad] launchpad type: H/W(%d)", LAUNCHPAD_TYPE_HW);
				return LAUNCHPAD_TYPE_HW;
			}
#endif /* _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING */
#ifdef _APPFW_FEATURE_PROCESS_POOL_SW_RENDERING
			if (sys_hwacc == SETTING_HW_ACCELERATION_OFF) {
				_D("[launchpad] launchpad type: S/W(%d)", LAUNCHPAD_TYPE_SW);
				return LAUNCHPAD_TYPE_SW;
			}
#endif /* _APPFW_FEATURE_PROCESS_POOL_SW_RENDERING */
		}
	}
#endif /* defined(_APPFW_FEATURE_PROCESS_POOL_SW_RENDERING) || defined(_APPFW_FEATURE_PROCESS_POOL_HW_RENDERING) */

#ifdef _APPFW_FEATURE_PROCESS_POOL_COMMON
	_D("[launchpad] launchpad type: COMMON(%d)", LAUNCHPAD_TYPE_COMMON);
	return LAUNCHPAD_TYPE_COMMON;
#else /* _APPFW_FEATURE_PROCESS_POOL_COMMON */
	_D("[launchpad] unsupported launchpad type, use legacy way");
	return LAUNCHPAD_TYPE_UNSUPPORTED;
#endif /* _APPFW_FEATURE_PROCESS_POOL_COMMON */
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PROCESS_POOL_H_ */
