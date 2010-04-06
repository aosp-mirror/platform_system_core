/* libs/diskconfig/diskconfig.c
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

#define LOG_TAG "config_mbr"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <cutils/log.h>

#include <diskconfig/diskconfig.h>


/* start and len are in LBA units */
static void
cfg_pentry(struct pc_partition *pentry, uint8_t status, uint8_t type,
           uint32_t start, uint32_t len)
{
    if (len > 0) {
        /* seems that somes BIOSens can get wedged on boot while verifying
         * the mbr if these are 0 */
        memset(&pentry->start, 0xff, sizeof(struct chs));
        memset(&pentry->end, 0xff, sizeof(struct chs));
    } else {
        /* zero out the c/h/s entries.. they are not used */
        memset(&pentry->start, 0, sizeof(struct chs));
        memset(&pentry->end, 0, sizeof(struct chs));
    }

    pentry->status = status;
    pentry->type = type;
    pentry->start_lba = start;
    pentry->len_lba = len;

    LOGI("Configuring pentry. status=0x%x type=0x%x start_lba=%u len_lba=%u",
         pentry->status, pentry->type, pentry->start_lba, pentry->len_lba);
}


static inline uint32_t
kb_to_lba(uint32_t len_kb, uint32_t sect_size)
{
    uint64_t lba;

    lba = (uint64_t)len_kb * 1024;
    /* bump it up to the next LBA boundary just in case  */
    lba = (lba + (uint64_t)sect_size - 1) & ~((uint64_t)sect_size - 1);
    lba /= (uint64_t)sect_size;
    if (lba >= 0xffffffffULL)
        LOGE("Error converting kb -> lba. 32bit overflow, expect weirdness");
    return (uint32_t)(lba & 0xffffffffULL);
}


static struct write_list *
mk_pri_pentry(struct disk_info *dinfo, struct part_info *pinfo, int pnum,
              uint32_t *lba)
{
    struct write_list *item;
    struct pc_partition *pentry;

    if (pnum >= PC_NUM_BOOT_RECORD_PARTS) {
        LOGE("Maximum number of primary partition exceeded.");
        return NULL;
    }

    if (!(item = alloc_wl(sizeof(struct pc_partition)))) {
        LOGE("Unable to allocate memory for partition entry.");
        return NULL;
    }

    {
        /* DO NOT DEREFERENCE */
        struct pc_boot_record *mbr = (void *)PC_MBR_DISK_OFFSET; 
        /* grab the offset in mbr where to write this partition entry. */
        item->offset = (loff_t)((uint32_t)((uint8_t *)(&mbr->ptable[pnum])));
    }

    pentry = (struct pc_partition *) &item->data;

    /* need a standard primary partition entry */
    if (pinfo) {
        /* need this to be 64 bit in case len_kb is large */
        uint64_t len_lba; 

        if (pinfo->len_kb != (uint32_t)-1) {
            /* bump it up to the next LBA boundary just in case */
            len_lba = ((uint64_t)pinfo->len_kb * 1024);
            len_lba += ((uint64_t)dinfo->sect_size - 1);
            len_lba &= ~((uint64_t)dinfo->sect_size - 1);
            len_lba /= (uint64_t)dinfo->sect_size;
        } else {
            /* make it fill the rest of disk */
            len_lba = dinfo->num_lba - *lba;
        }

        cfg_pentry(pentry, ((pinfo->flags & PART_ACTIVE_FLAG) ?
                            PC_PART_ACTIVE : PC_PART_NORMAL),
                   pinfo->type, *lba, (uint32_t)len_lba);

        pinfo->start_lba = *lba;
        *lba += (uint32_t)len_lba;
    } else {
        /* this should be made an extended partition, and should take
         * up the rest of the disk as a primary partition */
        cfg_pentry(pentry, PC_PART_NORMAL, PC_PART_TYPE_EXTENDED,
                   *lba, dinfo->num_lba - *lba);

        /* note that we do not update the *lba because we now have to
         * create a chain of extended partition tables, and first one is at
         * *lba */
    }

    return item;
}


/* This function configures an extended boot record at the beginning of an
 * extended partition. This creates a logical partition and a pointer to
 * the next EBR.
 *
 * ext_lba == The start of the toplevel extended partition (pointed to by the
 * entry in the MBR).
 */
static struct write_list *
mk_ext_pentry(struct disk_info *dinfo, struct part_info *pinfo, uint32_t *lba,
              uint32_t ext_lba, struct part_info *pnext)
{
    struct write_list *item;
    struct pc_boot_record *ebr;
    uint32_t len; /* in lba units */

    if (!(item = alloc_wl(sizeof(struct pc_boot_record)))) {
        LOGE("Unable to allocate memory for EBR.");
        return NULL;
    }

    /* we are going to write the ebr at the current LBA, and then bump the
     * lba counter since that is where the logical data partition will start */
    item->offset = (*lba) * dinfo->sect_size;
    (*lba)++;

    ebr = (struct pc_boot_record *) &item->data;
    memset(ebr, 0, sizeof(struct pc_boot_record));
    ebr->mbr_sig = PC_BIOS_BOOT_SIG;

    if (pinfo->len_kb != (uint32_t)-1)
        len = kb_to_lba(pinfo->len_kb, dinfo->sect_size);
    else {
        if (pnext) {
            LOGE("Only the last partition can be specified to fill the disk "
                 "(name = '%s')", pinfo->name);
            goto fail;
        }
        len = dinfo->num_lba - *lba;
        /* update the pinfo structure to reflect the new size, for
         * bookkeeping */
        pinfo->len_kb =
            (uint32_t)(((uint64_t)len * (uint64_t)dinfo->sect_size) /
                       ((uint64_t)1024));
    }

    cfg_pentry(&ebr->ptable[PC_EBR_LOGICAL_PART], PC_PART_NORMAL,
               pinfo->type, 1, len);

    pinfo->start_lba = *lba;
    *lba += len;

    /* If this is not the last partition, we have to create a link to the
     * next extended partition.
     *
     * Otherwise, there's nothing to do since the "pointer entry" is
     * already zero-filled.
     */
    if (pnext) {
        /* The start lba for next partition is an offset from the beginning
         * of the top-level extended partition */
        uint32_t next_start_lba = *lba - ext_lba;
        uint32_t next_len_lba;
        if (pnext->len_kb != (uint32_t)-1)
            next_len_lba = 1 + kb_to_lba(pnext->len_kb, dinfo->sect_size);
        else
            next_len_lba = dinfo->num_lba - *lba;
        cfg_pentry(&ebr->ptable[PC_EBR_NEXT_PTR_PART], PC_PART_NORMAL,
                   PC_PART_TYPE_EXTENDED, next_start_lba, next_len_lba);
    }

    return item;

fail:
    free_wl(item);
    return NULL;
}


struct write_list *
config_mbr(struct disk_info *dinfo)
{
    struct part_info *pinfo;
    uint32_t cur_lba = dinfo->skip_lba;
    uint32_t ext_lba = 0;
    struct write_list *wr_list = NULL;
    struct write_list *temp_wr = NULL;
    int cnt = 0;
    int extended = 0;

    if (!dinfo->part_lst)
        return NULL;

    for (cnt = 0; cnt < dinfo->num_parts; ++cnt) {
        pinfo = &dinfo->part_lst[cnt];

        /* Should we create an extedned partition? */
        if (cnt == (PC_NUM_BOOT_RECORD_PARTS - 1)) {
            if (cnt + 1 < dinfo->num_parts) {
                extended = 1;
                ext_lba = cur_lba;
                if ((temp_wr = mk_pri_pentry(dinfo, NULL, cnt, &cur_lba)))
                    wlist_add(&wr_list, temp_wr);
                else {
                    LOGE("Cannot create primary extended partition.");
                    goto fail;
                }
            }
        }

        /* if extended, need 1 lba for ebr */
        if ((cur_lba + extended) >= dinfo->num_lba)
            goto nospace;
        else if (pinfo->len_kb != (uint32_t)-1) {
            uint32_t sz_lba = (pinfo->len_kb / dinfo->sect_size) * 1024;
            if ((cur_lba + sz_lba + extended) > dinfo->num_lba)
                goto nospace;
        }

        if (!extended)
            temp_wr = mk_pri_pentry(dinfo, pinfo, cnt, &cur_lba);
        else {
            struct part_info *pnext;
            pnext = cnt + 1 < dinfo->num_parts ? &dinfo->part_lst[cnt+1] : NULL;
            temp_wr = mk_ext_pentry(dinfo, pinfo, &cur_lba, ext_lba, pnext);
        }

        if (temp_wr)
            wlist_add(&wr_list, temp_wr);
        else {
            LOGE("Cannot create partition %d (%s).", cnt, pinfo->name);
            goto fail;
        }
    }

    /* fill in the rest of the MBR with empty parts (if needed). */
    for (; cnt < PC_NUM_BOOT_RECORD_PARTS; ++cnt) {
        struct part_info blank;
        cur_lba = 0;
        memset(&blank, 0, sizeof(struct part_info));
        if (!(temp_wr = mk_pri_pentry(dinfo, &blank, cnt, &cur_lba))) {
            LOGE("Cannot create blank partition %d.", cnt);
            goto fail;
        }
        wlist_add(&wr_list, temp_wr);
    }

    return wr_list;

nospace:
    LOGE("Not enough space to add parttion '%s'.", pinfo->name);

fail:
    wlist_free(wr_list);
    return NULL;
}


/* Returns the device path of the partition referred to by 'name'
 * Must be freed by the caller.
 */
char *
find_mbr_part(struct disk_info *dinfo, const char *name)
{
    struct part_info *plist = dinfo->part_lst;
    int num = 0;
    char *dev_name = NULL;
    int has_extended = (dinfo->num_parts > PC_NUM_BOOT_RECORD_PARTS);

    for(num = 1; num <= dinfo->num_parts; ++num) {
        if (!strcmp(plist[num-1].name, name))
            break;
    }

    if (num > dinfo->num_parts)
        return NULL;

    if (has_extended && (num >= PC_NUM_BOOT_RECORD_PARTS))
        num++;

    if (!(dev_name = malloc(MAX_NAME_LEN))) {
        LOGE("Cannot allocate memory.");
        return NULL;
    }

    num = snprintf(dev_name, MAX_NAME_LEN, "%s%d", dinfo->device, num);
    if (num >= MAX_NAME_LEN) {
        LOGE("Device name is too long?!");
        free(dev_name);
        return NULL;
    }

    return dev_name;
}
