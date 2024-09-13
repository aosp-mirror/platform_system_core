/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

__BEGIN_DECLS

void trusty_gatekeeper_set_dev_name(const char* device_name);
int trusty_gatekeeper_connect();
int trusty_gatekeeper_call(uint32_t cmd, void *in, uint32_t in_size, uint8_t *out,
                           uint32_t *out_size);
void trusty_gatekeeper_disconnect();

__END_DECLS
