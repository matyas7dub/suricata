/* Copyright (C) 2021 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Lukas Sismis <lukas.sismis@gmail.com>
 */

#ifndef SURICATA_SOURCE_DPDK_H
#define SURICATA_SOURCE_DPDK_H

#include "suricata-common.h"
#include "util-dpdk.h"

#ifdef HAVE_DPDK
#include <rte_ethdev.h>
#endif

typedef enum { DPDK_COPY_MODE_NONE, DPDK_COPY_MODE_TAP, DPDK_COPY_MODE_IPS } DpdkCopyModeEnum;

#define DPDK_BURST_TX_WAIT_US 1

/* DPDK Flags */
// General flags
#define DPDK_PROMISC   (1 << 0) /**< Promiscuous mode */
#define DPDK_MULTICAST (1 << 1) /**< Enable multicast packets */
#define DPDK_IRQ_MODE  (1 << 2) /**< Interrupt mode */
// Offloads
#define DPDK_RX_CHECKSUM_OFFLOAD (1 << 4) /**< Enable chsum offload */

void DPDKSetTimevalOfMachineStart(void);

typedef struct DPDKWorkerSync_ {
    uint16_t worker_cnt;
    SC_ATOMIC_DECLARE(uint16_t, worker_checked_in);
} DPDKWorkerSync;

typedef struct DPDKIfaceConfig_ {
#ifdef HAVE_DPDK
    char iface[RTE_ETH_NAME_MAX_LEN];
    uint16_t port_id;
    int32_t socket_id;
    uint16_t threads;
    /* IPS mode */
    DpdkCopyModeEnum copy_mode;
    const char *out_iface;
    uint16_t out_port_id;
    /* DPDK flags */
    uint32_t flags;
    ChecksumValidationMode checksum_mode;
    uint64_t rss_hf;
    /* set maximum transmission unit of the device in bytes */
    uint16_t mtu;
    bool vlan_strip_enabled;
    uint16_t nb_rx_queues;
    uint16_t nb_rx_desc;
    uint16_t nb_tx_queues;
    uint16_t nb_tx_desc;
    uint32_t queue_mempool_size;
    uint32_t mempool_cache_size;
    bool mempool_cache_size_auto; // auto cache size based on mempool size
    DPDKDeviceResources *pkt_mempools;
    uint16_t linkup_timeout; // in seconds how long to wait for link to come up
    SC_ATOMIC_DECLARE(uint16_t, ref);
    /* threads bind queue id one by one */
    SC_ATOMIC_DECLARE(uint16_t, queue_id);
    SC_ATOMIC_DECLARE(uint16_t, inconsistent_numa_cnt);
    DPDKWorkerSync *workers_sync;
    void (*DerefFunc)(void *);

    struct rte_flow *flow[100];
#endif
} DPDKIfaceConfig;

#ifdef PM_OFFLOAD

/* defined by the NIC FW */
#define PM_DATA_SIZE 48

/** All data is currently stuffed into PmData, because the dummy unit in the
 *  testing NIC doesn't fill in the other fields of PmMetadata. In the future
 *  PmData should be reduced down to the smaller struct. */
typedef struct __rte_packed_begin PmData_ {
    uint8_t overflow : 1;
    uint8_t count : 7;
    struct __rte_packed_begin {
        uint16_t id;
        uint8_t sgh;
    } __rte_packed_end data [(PM_DATA_SIZE - 1)/3];
    uint8_t padding[2]; // pad to 48 bytes total
} __rte_packed_end PmData;

static_assert(sizeof(PmData) == PM_DATA_SIZE, "Wrong PmData alignment");

typedef struct __rte_packed_begin PmMetadata_ {
    struct {
        uint8_t flag : 1;
        uint8_t marked : 1;
        uint8_t reserved : 6;
    } flags;
    uint32_t markdata;
    uint8_t reserved[3];
    PmData data;
} __rte_packed_end PmMetadata;

static_assert(sizeof(PmMetadata) == PM_DATA_SIZE + 8, "Wrong PmMetadata alignment");

#endif

/**
 * \brief per packet DPDK vars
 *
 * This structure is used by the release data system and for IPS
 */
typedef struct DPDKPacketVars_ {
    struct rte_mbuf *mbuf;
#ifdef PM_OFFLOAD
    const PmMetadata *pm_metadata;
#endif
    uint16_t out_port_id;
    uint16_t out_queue_id;
    DpdkCopyModeEnum copy_mode;
} DPDKPacketVars;

void TmModuleReceiveDPDKRegister(void);
void TmModuleDecodeDPDKRegister(void);

#endif /* SURICATA_SOURCE_DPDK_H */
