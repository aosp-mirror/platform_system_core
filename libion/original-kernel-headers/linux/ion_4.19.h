/*
 * Adapted from drivers/staging/android/uapi/ion.h
 *
 * Copyright (C) 2019 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _UAPI_LINUX_ION_NEW_H
#define _UAPI_LINUX_ION_NEW_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define ION_NUM_HEAP_IDS (sizeof(unsigned int) * 8)

enum ion_heap_type_ext {
    ION_HEAP_TYPE_CUSTOM_EXT = 16,
    ION_HEAP_TYPE_MAX = 31,
};

/**
 * ion_heap_id - list of standard heap ids that Android can use
 *
 * @ION_HEAP_SYSTEM		Id for the ION_HEAP_TYPE_SYSTEM
 * @ION_HEAP_SYSTEM_CONTIG	Id for the ION_HEAP_TYPE_SYSTEM_CONTIG
 * @ION_HEAP_CHUNK		Id for the ION_HEAP_TYPE_CHUNK
 * @ION_HEAP_CARVEOUT_START	Start of reserved id range for heaps of type
 *				ION_HEAP_TYPE_CARVEOUT
 * @ION_HEAP_CARVEOUT_END	End of reserved id range for heaps of type
 *				ION_HEAP_TYPE_CARVEOUT
 * @ION_HEAP_DMA_START 		Start of reserved id range for heaps of type
 *				ION_HEAP_TYPE_DMA
 * @ION_HEAP_DMA_END		End of reserved id range for heaps of type
 *				ION_HEAP_TYPE_DMA
 * @ION_HEAP_CUSTOM_START	Start of reserved id range for heaps of custom
 *				type
 * @ION_HEAP_CUSTOM_END		End of reserved id range for heaps of custom
 *				type
 */
enum ion_heap_id {
    ION_HEAP_SYSTEM = (1 << ION_HEAP_TYPE_SYSTEM),
    ION_HEAP_SYSTEM_CONTIG = (ION_HEAP_SYSTEM << 1),
    ION_HEAP_CARVEOUT_START = (ION_HEAP_SYSTEM_CONTIG << 1),
    ION_HEAP_CARVEOUT_END = (ION_HEAP_CARVEOUT_START << 4),
    ION_HEAP_CHUNK = (ION_HEAP_CARVEOUT_END << 1),
    ION_HEAP_DMA_START = (ION_HEAP_CHUNK << 1),
    ION_HEAP_DMA_END = (ION_HEAP_DMA_START << 7),
    ION_HEAP_CUSTOM_START = (ION_HEAP_DMA_END << 1),
    ION_HEAP_CUSTOM_END = (ION_HEAP_CUSTOM_START << 15),
};

#define ION_NUM_MAX_HEAPS (32)

/**
 * DOC: Ion Userspace API
 *
 * create a client by opening /dev/ion
 * most operations handled via following ioctls
 *
 */

/**
 * struct ion_new_allocation_data - metadata passed from userspace for allocations
 * @len:		size of the allocation
 * @heap_id_mask:	mask of heap ids to allocate from
 * @flags:		flags passed to heap
 * @handle:		pointer that will be populated with a cookie to use to
 *			refer to this allocation
 *
 * Provided by userspace as an argument to the ioctl - added _new to denote
 * this belongs to the new ION interface.
 */
struct ion_new_allocation_data {
    __u64 len;
    __u32 heap_id_mask;
    __u32 flags;
    __u32 fd;
    __u32 unused;
};

#define MAX_HEAP_NAME 32

/**
 * struct ion_heap_data - data about a heap
 * @name - first 32 characters of the heap name
 * @type - heap type
 * @heap_id - heap id for the heap
 */
struct ion_heap_data {
    char name[MAX_HEAP_NAME];
    __u32 type;
    __u32 heap_id;
    __u32 reserved0;
    __u32 reserved1;
    __u32 reserved2;
};

/**
 * struct ion_heap_query - collection of data about all heaps
 * @cnt - total number of heaps to be copied
 * @heaps - buffer to copy heap data
 */
struct ion_heap_query {
    __u32 cnt;       /* Total number of heaps to be copied */
    __u32 reserved0; /* align to 64bits */
    __u64 heaps;     /* buffer to be populated */
    __u32 reserved1;
    __u32 reserved2;
};

#define ION_IOC_MAGIC 'I'

/**
 * DOC: ION_IOC_NEW_ALLOC - allocate memory
 *
 * Takes an ion_allocation_data struct and returns it with the handle field
 * populated with the opaque handle for the allocation.
 * TODO: This IOCTL will clash by design; however, only one of
 *  ION_IOC_ALLOC or ION_IOC_NEW_ALLOC paths will be exercised,
 *  so this should not conflict.
 */
#define ION_IOC_NEW_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_new_allocation_data)

/**
 * DOC: ION_IOC_FREE - free memory
 *
 * Takes an ion_handle_data struct and frees the handle.
 *
 * #define ION_IOC_FREE		_IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
 * This will come from the older kernels, so don't redefine here
 */

/**
 * DOC: ION_IOC_SHARE - creates a file descriptor to use to share an allocation
 *
 * Takes an ion_fd_data struct with the handle field populated with a valid
 * opaque handle.  Returns the struct with the fd field set to a file
 * descriptor open in the current address space.  This file descriptor
 * can then be passed to another process.  The corresponding opaque handle can
 * be retrieved via ION_IOC_IMPORT.
 *
 * #define ION_IOC_SHARE		_IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
 * This will come from the older kernels, so don't redefine here
 */

/**
 * DOC: ION_IOC_HEAP_QUERY - information about available heaps
 *
 * Takes an ion_heap_query structure and populates information about
 * available Ion heaps.
 */
#define ION_IOC_HEAP_QUERY _IOWR(ION_IOC_MAGIC, 8, struct ion_heap_query)

/**
 * DOC: ION_IOC_HEAP_ABI_VERSION - return ABI version
 *
 * Returns ABI version for this driver
 */
#define ION_IOC_ABI_VERSION _IOR(ION_IOC_MAGIC, 9, __u32)

#endif /* _UAPI_LINUX_ION_NEW_H */
