/* libs/diskconfig/write_lst.c
 *
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "write_lst"
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cutils/log.h>

#include <diskconfig/diskconfig.h>

struct write_list *
alloc_wl(uint32_t data_len)
{
    struct write_list *item;

    if (!(item = malloc(sizeof(struct write_list) + data_len))) {
        LOGE("Unable to allocate memory.");
        return NULL;
    }

    item->len = data_len;
    return item;
}

void
free_wl(struct write_list *item)
{
    if (item)
        free(item);
}

struct write_list *
wlist_add(struct write_list **lst, struct write_list *item)
{
    item->next = (*lst);
    *lst = item;
    return item;
}

void
wlist_free(struct write_list *lst)
{
    struct write_list *temp_wr;
    while (lst) {
        temp_wr = lst->next;
        free_wl(lst);
        lst = temp_wr;
    }
}

int
wlist_commit(int fd, struct write_list *lst, int test)
{
    for(; lst; lst = lst->next) {
        if (lseek64(fd, lst->offset, SEEK_SET) != (loff_t)lst->offset) {
            LOGE("Cannot seek to the specified position (%lld).", lst->offset);
            goto fail;
        }

        if (!test) {
            if (write(fd, lst->data, lst->len) != (int)lst->len) {
                LOGE("Failed writing %u bytes at position %lld.", lst->len,
                     lst->offset);
                goto fail;
            }
        } else
            LOGI("Would write %d bytes @ offset %lld.", lst->len, lst->offset);
    }

    return 0;

fail:
    return -1;
}
