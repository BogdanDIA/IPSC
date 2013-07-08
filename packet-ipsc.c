/* packet-ipsc.c
 * Routines for MotoTrbo IPSC packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * By Bogdan Diaconescu <yo3ii@yo3iiu.ro> 
 * Copyright 2013 Bogdan Diaconescu
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/arptypes.h>
#include <epan/addr_resolv.h>
#include <epan/emem.h>
#include "packet-arp.h"
#include <epan/etypes.h>
#include <epan/arcnet_pids.h>
#include <epan/ax25_pids.h>
#include <epan/prefs.h>
#include <epan/expert.h>

static int proto_ipsc = -1;

static int hf_ipsc_type = -1;
static int hf_ipsc_rpt_id = -1;
static int hf_ipsc_linking_id = -1;
static int hf_ipsc_linking_peer_op_id = -1;
static int hf_ipsc_linking_peer_mode_id = -1;
static int hf_ipsc_linking_ipsc_slot1_id = -1;
static int hf_ipsc_linking_ipsc_slot2_id = -1;
static int hf_ipsc_service_flags_id = -1;
static int hf_ipsc_service_flags_byte1_id = -1;
static int hf_ipsc_service_flags_byte2_id = -1;
static int hf_ipsc_service_flags_byte3_id = -1;
static int hf_ipsc_service_flags_byte3_rdac_id = -1;
static int hf_ipsc_service_flags_byte3_unk1_id = -1;
static int hf_ipsc_service_flags_byte3_3rdpy_id = -1;
static int hf_ipsc_service_flags_byte3_unk2_id = -1;
static int hf_ipsc_service_flags_byte4_id = -1;
static int hf_ipsc_service_flags_byte4_unk1_id = -1;
static int hf_ipsc_service_flags_byte4_auth_id = -1;
static int hf_ipsc_service_flags_byte4_voice_id = -1;
static int hf_ipsc_service_flags_byte4_data_id = -1;
static int hf_ipsc_service_flags_byte4_unk2_id = -1;
static int hf_ipsc_service_flags_byte4_master_id = -1;
static int hf_ipsc_version_id = -1;
static int hf_ipsc_seq_no_id = -1;
static int hf_ipsc_src_id = -1;
static int hf_ipsc_dst_id = -1;
static int hf_ipsc_prio_v_d_id = -1;
static int hf_ipsc_call_ctrl_id = -1;
static int hf_ipsc_call_ctrl_info_id = -1;
static int hf_ipsc_call_ctrl_src_id = -1;
static int hf_ipsc_payload_type_id = -1;
static int hf_ipsc_call_seq_no_id = -1;
static int hf_ipsc_timestamp_id = -1;
static int hf_ipsc_sync_src_id = -1;
static int hf_ipsc_data_type_voice_hdr_id = -1;
static int hf_ipsc_rssi_threshold_and_parity_id = -1;
static int hf_ipsc_length_to_follow_id = -1;
static int hf_ipsc_length_to_follow2_id = -1;
static int hf_ipsc_rssi_status_id = -1;
static int hf_ipsc_slot_type_sync_id = -1;
static int hf_ipsc_data_size_id = -1;
static int hf_ipsc_data_id = -1;
static int hf_ipsc_digest_id = -1;

static int hf_ipsc_unk1_id = -1;

static gint ett_ipsc = -1;

void proto_register_ipsc(void);
void proto_reg_handoff_ipsc(void);

void
dissect_short_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ipsc_item = NULL;
    proto_tree *ipsc_tree = NULL;

    ipsc_item = proto_tree_add_item(tree, proto_ipsc, tvb, 0, -1, ENC_NA);
    ipsc_tree = proto_item_add_subtree(ipsc_item, ett_ipsc);

    /* Type */
    proto_tree_add_item(ipsc_tree, hf_ipsc_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* SRC_ID */
    proto_tree_add_item(ipsc_tree, hf_ipsc_rpt_id, tvb, 1, 4, ENC_BIG_ENDIAN);

    /* Auth Digest */
    proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 14, 10, ENC_BIG_ENDIAN);
}

void
dissect_CALL_CTL_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ipsc_item = NULL;
    proto_tree *ipsc_tree = NULL;

    ipsc_item = proto_tree_add_item(tree, proto_ipsc, tvb, 0, -1, ENC_NA);
    ipsc_tree = proto_item_add_subtree(ipsc_item, ett_ipsc);

    /* Type */
    proto_tree_add_item(ipsc_tree, hf_ipsc_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* SRC_ID */
    proto_tree_add_item(ipsc_tree, hf_ipsc_rpt_id, tvb, 1, 4, ENC_BIG_ENDIAN);

    /* SRC_ID */
    proto_tree_add_item(ipsc_tree, hf_ipsc_rpt_id, tvb, 5, 4, ENC_BIG_ENDIAN);

    /* Unk_17_Byte */
    proto_tree_add_item(ipsc_tree, hf_ipsc_unk1_id, tvb, 9, 17, ENC_BIG_ENDIAN);

    /* Auth Digest */
    proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 26, 10, ENC_BIG_ENDIAN);
}

void
dissect_CALL_CTL_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ipsc_item = NULL;
    proto_tree *ipsc_tree = NULL;

    ipsc_item = proto_tree_add_item(tree, proto_ipsc, tvb, 0, -1, ENC_NA);
    ipsc_tree = proto_item_add_subtree(ipsc_item, ett_ipsc);

    /* Type */
    proto_tree_add_item(ipsc_tree, hf_ipsc_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* SRC_ID */
    proto_tree_add_item(ipsc_tree, hf_ipsc_rpt_id, tvb, 1, 4, ENC_BIG_ENDIAN);

    /* Unk_2_Byte */
    proto_tree_add_item(ipsc_tree, hf_ipsc_unk1_id, tvb, 5, 2, ENC_BIG_ENDIAN);

    /* Auth Digest */
    proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 7, 10, ENC_BIG_ENDIAN);
}

void
dissect_CALL_CTL_3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ipsc_item = NULL;
    proto_tree *ipsc_tree = NULL;

    ipsc_item = proto_tree_add_item(tree, proto_ipsc, tvb, 0, -1, ENC_NA);
    ipsc_tree = proto_item_add_subtree(ipsc_item, ett_ipsc);

    /* Type */
    proto_tree_add_item(ipsc_tree, hf_ipsc_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* SRC_ID */
    proto_tree_add_item(ipsc_tree, hf_ipsc_rpt_id, tvb, 1, 4, ENC_BIG_ENDIAN);

    /* Unk 1 Byte */
    proto_tree_add_item(ipsc_tree, hf_ipsc_unk1_id, tvb, 5, 1, ENC_BIG_ENDIAN);

    /* Auth Digest */
    proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 6, 10, ENC_BIG_ENDIAN);
}

void
dissect_PVT_DATA(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ipsc_item = NULL;
    proto_tree *ipsc_tree = NULL;

    ipsc_item = proto_tree_add_item(tree, proto_ipsc, tvb, 0, -1, ENC_NA);
    ipsc_tree = proto_item_add_subtree(ipsc_item, ett_ipsc);

    guint16 length_to_follow = 0;

    /* Type */
    proto_tree_add_item(ipsc_tree, hf_ipsc_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* RPT_ID */
    proto_tree_add_item(ipsc_tree, hf_ipsc_rpt_id, tvb, 1, 4, ENC_BIG_ENDIAN);

    /* SEQ NO */
    proto_tree_add_item(ipsc_tree, hf_ipsc_seq_no_id, tvb, 5, 1, ENC_BIG_ENDIAN);

    /* Src Id */
    proto_tree_add_item(ipsc_tree, hf_ipsc_src_id, tvb, 6, 3, ENC_BIG_ENDIAN);

    /* Dst Id */
    proto_tree_add_item(ipsc_tree, hf_ipsc_dst_id, tvb, 9, 3, ENC_BIG_ENDIAN);

    /* Prio V/D */
    proto_tree_add_item(ipsc_tree, hf_ipsc_prio_v_d_id, tvb, 12, 1, ENC_BIG_ENDIAN);

    /* Call Ctrl */
    proto_tree_add_item(ipsc_tree, hf_ipsc_call_ctrl_id, tvb, 13, 4, ENC_BIG_ENDIAN);

    /* Call Ctrl Info */
    proto_tree_add_item(ipsc_tree, hf_ipsc_call_ctrl_info_id, tvb, 17, 1, ENC_BIG_ENDIAN);

    /* Call Ctrl Src */
    proto_tree_add_item(ipsc_tree, hf_ipsc_call_ctrl_src_id, tvb, 18, 1, ENC_BIG_ENDIAN);

    /* Payload Type */
    proto_tree_add_item(ipsc_tree, hf_ipsc_payload_type_id, tvb, 19, 1, ENC_BIG_ENDIAN);

    /* Call Seq No */
    proto_tree_add_item(ipsc_tree, hf_ipsc_call_seq_no_id, tvb, 20, 2, ENC_BIG_ENDIAN);

    /* Timestamp */
    proto_tree_add_item(ipsc_tree, hf_ipsc_timestamp_id, tvb, 22, 4, ENC_BIG_ENDIAN);

    /* Sync Src Id */
    proto_tree_add_item(ipsc_tree, hf_ipsc_sync_src_id, tvb, 26, 4, ENC_BIG_ENDIAN);

    /* Data Type Voice Hdr */
    proto_tree_add_item(ipsc_tree, hf_ipsc_data_type_voice_hdr_id, tvb, 30, 1, ENC_BIG_ENDIAN);

    /* RSSI Threshold and Parity */
    proto_tree_add_item(ipsc_tree, hf_ipsc_rssi_threshold_and_parity_id, tvb, 31, 1, ENC_BIG_ENDIAN);

    /* Length to Follow */
    proto_tree_add_item(ipsc_tree, hf_ipsc_length_to_follow_id, tvb, 32, 2, ENC_BIG_ENDIAN);

    /* 
     * Decide how the rest of data looks like
     * based on length_to_follow
     */
    if (length_to_follow = tvb_get_ntohs(tvb, 32))
    {
      /* RSSI Status */
      proto_tree_add_item(ipsc_tree, hf_ipsc_rssi_status_id, tvb, 34, 1, ENC_BIG_ENDIAN);

      /* Slot Type Sync */
      proto_tree_add_item(ipsc_tree, hf_ipsc_slot_type_sync_id, tvb, 35, 1, ENC_BIG_ENDIAN);

      /* Data Size - in words of 2bytes*/
      proto_tree_add_item(ipsc_tree, hf_ipsc_data_size_id, tvb, 36, 2, ENC_BIG_ENDIAN);

      /* Data */
      proto_tree_add_item(ipsc_tree, hf_ipsc_data_id, tvb, 38, 2 * length_to_follow - 4, ENC_BIG_ENDIAN);

      /* Auth Digest */
      proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 38 + (2 * length_to_follow - 4), 10, ENC_BIG_ENDIAN);
    }
    else
    {
      /* Auth Digest */
      proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 34, 10, ENC_BIG_ENDIAN);
    }
}

void
dissect_GROUP_VOICE(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ipsc_item = NULL;
    proto_tree *ipsc_tree = NULL;

    ipsc_item = proto_tree_add_item(tree, proto_ipsc, tvb, 0, -1, ENC_NA);
    ipsc_tree = proto_item_add_subtree(ipsc_item, ett_ipsc);

    guint16 length_to_follow = 0;

    /* Type */
    proto_tree_add_item(ipsc_tree, hf_ipsc_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* RPT_ID */
    proto_tree_add_item(ipsc_tree, hf_ipsc_rpt_id, tvb, 1, 4, ENC_BIG_ENDIAN);

    /* SEQ NO */
    proto_tree_add_item(ipsc_tree, hf_ipsc_seq_no_id, tvb, 5, 1, ENC_BIG_ENDIAN);

    /* Src Id */
    proto_tree_add_item(ipsc_tree, hf_ipsc_src_id, tvb, 6, 3, ENC_BIG_ENDIAN);

    /* Dst Id */
    proto_tree_add_item(ipsc_tree, hf_ipsc_dst_id, tvb, 9, 3, ENC_BIG_ENDIAN);

    /* Prio V/D */
    proto_tree_add_item(ipsc_tree, hf_ipsc_prio_v_d_id, tvb, 12, 1, ENC_BIG_ENDIAN);

    /* Call Ctrl */
    proto_tree_add_item(ipsc_tree, hf_ipsc_call_ctrl_id, tvb, 13, 4, ENC_BIG_ENDIAN);

    /* Call Ctrl Info */
    proto_tree_add_item(ipsc_tree, hf_ipsc_call_ctrl_info_id, tvb, 17, 1, ENC_BIG_ENDIAN);

    /* Call Ctrl Src */
    proto_tree_add_item(ipsc_tree, hf_ipsc_call_ctrl_src_id, tvb, 18, 1, ENC_BIG_ENDIAN);

    /* Payload Type */
    proto_tree_add_item(ipsc_tree, hf_ipsc_payload_type_id, tvb, 19, 1, ENC_BIG_ENDIAN);

    /* Call Seq No */
    proto_tree_add_item(ipsc_tree, hf_ipsc_call_seq_no_id, tvb, 20, 2, ENC_BIG_ENDIAN);

    /* Timestamp */
    proto_tree_add_item(ipsc_tree, hf_ipsc_timestamp_id, tvb, 22, 4, ENC_BIG_ENDIAN);

    /* Sync Src Id */
    proto_tree_add_item(ipsc_tree, hf_ipsc_sync_src_id, tvb, 26, 4, ENC_BIG_ENDIAN);

    /* Data Type Voice Hdr */
    proto_tree_add_item(ipsc_tree, hf_ipsc_data_type_voice_hdr_id, tvb, 30, 1, ENC_BIG_ENDIAN);

    /* TODO - Don't know what this is */
    if ((0x0a == tvb_get_guint8(tvb, 30)) || (0x8a == tvb_get_guint8(tvb, 30)))
    {
      /* lengt to folow is in bytes */
      length_to_follow = tvb_get_guint8(tvb, 31);

      /* Length to Follow */
      proto_tree_add_item(ipsc_tree, hf_ipsc_length_to_follow2_id, tvb, 31, 1, ENC_BIG_ENDIAN);

      /* Data */
      proto_tree_add_item(ipsc_tree, hf_ipsc_data_id, tvb, 32, length_to_follow, ENC_BIG_ENDIAN);

      /* Auth Digest */
      proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 32 + length_to_follow, 10, ENC_BIG_ENDIAN);
    }
    else
    {
      /* RSSI Threshold and Parity */
      proto_tree_add_item(ipsc_tree, hf_ipsc_rssi_threshold_and_parity_id, tvb, 31, 1, ENC_BIG_ENDIAN);

      /* Length to Follow */
      proto_tree_add_item(ipsc_tree, hf_ipsc_length_to_follow_id, tvb, 32, 2, ENC_BIG_ENDIAN);

      /* 
       * Decide how the rest of data looks like
       * based on length_to_follow (words of 2 bytes each)
       */
      if (length_to_follow = tvb_get_ntohs(tvb, 32))
      {
        /* RSSI Status */
        proto_tree_add_item(ipsc_tree, hf_ipsc_rssi_status_id, tvb, 34, 1, ENC_BIG_ENDIAN);

        /* Slot Type Sync */
        proto_tree_add_item(ipsc_tree, hf_ipsc_slot_type_sync_id, tvb, 35, 1, ENC_BIG_ENDIAN);

        /* Data Size - in words of 2bytes*/
        proto_tree_add_item(ipsc_tree, hf_ipsc_data_size_id, tvb, 36, 2, ENC_BIG_ENDIAN);

        /* Data */
        proto_tree_add_item(ipsc_tree, hf_ipsc_data_id, tvb, 38, 2 * length_to_follow - 4, ENC_BIG_ENDIAN);

        /* Auth Digest */
        proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 38 + (2 * length_to_follow - 4), 10, ENC_BIG_ENDIAN);
      }
      else
      {
        /* Auth Digest */
        proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 34, 10, ENC_BIG_ENDIAN);
      }
    }
}

void
dissect_XCMP_XNL(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ipsc_item = NULL;
    proto_tree *ipsc_tree = NULL;

    ipsc_item = proto_tree_add_item(tree, proto_ipsc, tvb, 0, -1, ENC_NA);
    ipsc_tree = proto_item_add_subtree(ipsc_item, ett_ipsc);

    /* Type */
    proto_tree_add_item(ipsc_tree, hf_ipsc_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* SRC_ID */
    proto_tree_add_item(ipsc_tree, hf_ipsc_rpt_id, tvb, 1, 4, ENC_BIG_ENDIAN);

    /* Unk 28 Byte */
    /* There seems to be messages of various lengths */
    proto_tree_add_item(ipsc_tree, hf_ipsc_unk1_id, tvb, 5, 28, ENC_BIG_ENDIAN);

    /* Auth Digest */
    proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 23, 10, ENC_BIG_ENDIAN);
}


void
dissect_RPT_WAKE_UP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ipsc_item = NULL;
    proto_tree *ipsc_tree = NULL;

    ipsc_item = proto_tree_add_item(tree, proto_ipsc, tvb, 0, -1, ENC_NA);
    ipsc_tree = proto_item_add_subtree(ipsc_item, ett_ipsc);

    /* Type */
    proto_tree_add_item(ipsc_tree, hf_ipsc_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* SRC_ID */
    proto_tree_add_item(ipsc_tree, hf_ipsc_rpt_id, tvb, 1, 4, ENC_BIG_ENDIAN);

    /* Auth Digest */
    //proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 14, 10, ENC_BIG_ENDIAN);
}



void
dissect_long_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ipsc_item = NULL;
    proto_tree *ipsc_tree = NULL;
    proto_item *ipsc_linking_item = NULL;
    proto_tree *ipsc_linking_tree = NULL;
    proto_item *ipsc_service_flags_item = NULL;
    proto_tree *ipsc_service_flags_tree = NULL;
    proto_item *ipsc_service_flags_byte3_item = NULL;
    proto_tree *ipsc_service_flags_byte3_tree = NULL;
    proto_item *ipsc_service_flags_byte4_item = NULL;
    proto_tree *ipsc_service_flags_byte4_tree = NULL;

    ipsc_item = proto_tree_add_item(tree, proto_ipsc, tvb, 0, -1, ENC_NA);
    ipsc_tree = proto_item_add_subtree(ipsc_item, ett_ipsc);

    /* Type */
    proto_tree_add_item(ipsc_tree, hf_ipsc_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* SRC_ID */
    proto_tree_add_item(ipsc_tree, hf_ipsc_rpt_id, tvb, 1, 4, ENC_BIG_ENDIAN);

    /* Linking */
    ipsc_linking_item = proto_tree_add_item(ipsc_tree, hf_ipsc_linking_id, tvb, 5, 1, ENC_BIG_ENDIAN);
    ipsc_linking_tree = proto_item_add_subtree(ipsc_linking_item, ett_ipsc);
    /* Peer Opperation */
    proto_tree_add_item(ipsc_linking_tree, hf_ipsc_linking_peer_op_id, tvb, 5, 1, ENC_BIG_ENDIAN);
    /* Peer Mode */
    proto_tree_add_item(ipsc_linking_tree, hf_ipsc_linking_peer_mode_id, tvb, 5, 1, ENC_BIG_ENDIAN);
    /* IPSC Slot 1 */
    proto_tree_add_item(ipsc_linking_tree, hf_ipsc_linking_ipsc_slot1_id, tvb, 5, 1, ENC_BIG_ENDIAN);
    /* IPSC Slot 2 */
    proto_tree_add_item(ipsc_linking_tree, hf_ipsc_linking_ipsc_slot2_id, tvb, 5, 1, ENC_BIG_ENDIAN);

    /* Service FLAGS */
    ipsc_service_flags_item = proto_tree_add_item(ipsc_tree, hf_ipsc_service_flags_id, tvb, 6, 4, ENC_BIG_ENDIAN);
    ipsc_service_flags_tree = proto_item_add_subtree(ipsc_service_flags_item, ett_ipsc);
    /* Service FLAGS Byte 1 */
    proto_tree_add_item(ipsc_service_flags_tree, hf_ipsc_service_flags_byte1_id, tvb, 6, 1, ENC_BIG_ENDIAN);
    /* Service FLAGS Byte 2 */
    proto_tree_add_item(ipsc_service_flags_tree, hf_ipsc_service_flags_byte2_id, tvb, 7, 1, ENC_BIG_ENDIAN);
    /* Service FLAGS Byte 3 */
    ipsc_service_flags_byte3_item = proto_tree_add_item(ipsc_service_flags_tree, hf_ipsc_service_flags_byte3_id, tvb, 8, 1, ENC_BIG_ENDIAN);
    ipsc_service_flags_byte3_tree = proto_item_add_subtree(ipsc_service_flags_byte3_item, ett_ipsc);
    /* Service FLAGS Byte 3 - RDAC bit */
    proto_tree_add_item(ipsc_service_flags_byte3_tree, hf_ipsc_service_flags_byte3_rdac_id, tvb, 8, 1, ENC_BIG_ENDIAN);
    /* Service FLAGS Byte 3 - Unknown bit */
    proto_tree_add_item(ipsc_service_flags_byte3_tree, hf_ipsc_service_flags_byte3_unk1_id, tvb, 8, 1, ENC_BIG_ENDIAN);
    /* Service FLAGS Byte 3 - 3rd Party App */
    proto_tree_add_item(ipsc_service_flags_byte3_tree, hf_ipsc_service_flags_byte3_3rdpy_id, tvb, 8, 1, ENC_BIG_ENDIAN);
    /* Service FLAGS Byte 3 - Unk2 */
    proto_tree_add_item(ipsc_service_flags_byte3_tree, hf_ipsc_service_flags_byte3_unk2_id, tvb, 8, 1, ENC_BIG_ENDIAN);
    /* Service FLAGS Byte 4 */
    ipsc_service_flags_byte4_item = proto_tree_add_item(ipsc_service_flags_tree, hf_ipsc_service_flags_byte4_id, tvb, 9, 1, ENC_BIG_ENDIAN);
    ipsc_service_flags_byte4_tree = proto_item_add_subtree(ipsc_service_flags_byte4_item, ett_ipsc);
    /* Service FLAGS Byte 4 - Unk1 */
    proto_tree_add_item(ipsc_service_flags_byte4_tree, hf_ipsc_service_flags_byte4_unk1_id, tvb, 9, 1, ENC_BIG_ENDIAN);
    /* Service FLAGS Byte 4 - Authenticated packets */
    proto_tree_add_item(ipsc_service_flags_byte4_tree, hf_ipsc_service_flags_byte4_auth_id, tvb, 9, 1, ENC_BIG_ENDIAN);
    /* Service FLAGS Byte 4 - Voice calls supported */
    proto_tree_add_item(ipsc_service_flags_byte4_tree, hf_ipsc_service_flags_byte4_voice_id, tvb, 9, 1, ENC_BIG_ENDIAN);
    /* Service FLAGS Byte 4 - Data calls supported */
    proto_tree_add_item(ipsc_service_flags_byte4_tree, hf_ipsc_service_flags_byte4_data_id, tvb, 9, 1, ENC_BIG_ENDIAN);
    /* Service FLAGS Byte 4 - Unk2 */
    proto_tree_add_item(ipsc_service_flags_byte4_tree, hf_ipsc_service_flags_byte4_unk2_id, tvb, 9, 1, ENC_BIG_ENDIAN);
    /* Service FLAGS Byte 4 - Master */
    proto_tree_add_item(ipsc_service_flags_byte4_tree, hf_ipsc_service_flags_byte4_master_id, tvb, 9, 1, ENC_BIG_ENDIAN);

    /* Version */
    proto_tree_add_item(ipsc_tree, hf_ipsc_version_id, tvb, 10, 4, ENC_BIG_ENDIAN);

    /* Auth Digest */
    proto_tree_add_item(ipsc_tree, hf_ipsc_digest_id, tvb, 14, 10, ENC_BIG_ENDIAN);
}

static void
dissect_ipsc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /*
     Clear the Info column so that, if we throw an exception, it
     shows up as a short or malformed ARP frame. */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPSC");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    int val;

    switch (val = tvb_get_guint8(tvb, 0))
    {
      case 0x61:
        dissect_CALL_CTL_1(tvb, pinfo, tree);
        break;
      case 0x62:
        dissect_CALL_CTL_2(tvb, pinfo, tree);
        break;
      case 0x63:
        dissect_CALL_CTL_3(tvb, pinfo, tree);
        break;
      case 0x70:
        dissect_XCMP_XNL(tvb, pinfo, tree);
        break;
      case 0x80:
        dissect_GROUP_VOICE(tvb, pinfo, tree);
        break;
      case 0x84:
        dissect_PVT_DATA(tvb, pinfo, tree);
        break;
      case 0x85:
        dissect_RPT_WAKE_UP(tvb, pinfo, tree);
        break;

      case 0x90:
      case 0x91:
      case 0x94:
      case 0x95:
      case 0x96:
      case 0x97:
      case 0x98:
      case 0x99:
        dissect_long_messages(tvb, pinfo, tree);
        break;

      case 0x92:
        dissect_short_messages(tvb, pinfo, tree);
        break;

      default:
        ;
    }

  }
}

void
proto_register_ipsc(void)
{
  static const value_string valstring_type[] = {
    { 0x61, "CALL_CTL_1" },
    { 0x62, "CALL_CTL_2" },
    { 0x63, "CALL_CTL_3" },
    { 0x70, "XCMP_XNL" },
    { 0x80, "GROUP_VOICE" },
    { 0x83, "GROUP_DATA" },
    { 0x84, "PVT_DATA" },
    { 0x85, "RPT_WAKE_UP" },
    { 0x90, "MASTER_REG_REQ" },
    { 0x91, "MASTER_REG_REPLY"},
    { 0x92, "PEER_LIST_REQ"},
    { 0x91, "PEER_LIST_REPLY"},
    { 0x94, "PEER_REG_REQ"},
    { 0x96, "MASTER_ALIVE_REQ"},
    { 0x97, "MASTER_ALIVE_REPLY"},
    { 0x98, "PEER_ALIVE_REQ"},
    { 0x99, "PEER_ALIVE_REPLY"},
    { 0x9a, "DE_REG_REQ"},
    { 0x9b, "DE_REG_REPLY"},
    { 0, "NULL"}
  };

  static const value_string valstring_linking_peer_op[] = {
    { 0x00, "Unknown" },
    { 0x01, "Peer Operational" },
    { 0x02, "Unknown" },
    { 0x03, "Unknown" },
    { 0, NULL },
  };

  static const value_string valstring_linking_peer_mode[] = {
    { 0x00, "No Radio" },
    { 0x01, "Analog Radio" },
    { 0x02, "Digital Radio" },
    { 0x03, "Unknown" },
    { 0, NULL },
  };

  static const value_string valstring_linking_ipsc_slot[] = {
    { 0x00, "Unknown" },
    { 0x01, "OFF" },
    { 0x02, "ON" },
    { 0x03, "Unknown" },
    { 0, NULL },
  };

  static const true_false_string valstring_service_flags_rdac = {
    "RDAC call",
    "Not a RADAC call"
  };

  static const true_false_string valstring_service_flags_unk1 = {
    "1",
    "0"
  };

  static const true_false_string valstring_service_flags_3rdpy = {
    "3rd Party App",
    "Not a 3rd Party App"
  };

  static const true_false_string valstring_service_flags_auth = {
    "Yes",
    "No"
  };

  static const true_false_string valstring_service_flags_voice = {
    "Yes",
    "No"
  };

  static const true_false_string valstring_service_flags_data = {
    "Yes",
    "No"
  };

  static const true_false_string valstring_service_flags_unk2 = {
    "Yes",
    "No"
  };


  static const true_false_string valstring_service_flags_master = {
    "Yes",
    "No"
  };


  static hf_register_info hf[] = {
    { &hf_ipsc_type, 
      { "Type", "ipsc.type", FT_UINT8, BASE_HEX, VALS(valstring_type), 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_rpt_id, 
      { "Rpt Id", "ipsc.src_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_linking_id, 
      { "Linking", "ipsc.linking", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_linking_peer_op_id, 
      { "Peer Op", "ipsc.linking.peer_op", FT_UINT8, BASE_HEX, VALS(valstring_linking_peer_op), 0xc0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_linking_peer_mode_id, 
      { "Peer Mode", "ipsc.linking.peer_mode", FT_UINT8, BASE_HEX, VALS(valstring_linking_peer_mode), 0x30, NULL, HFILL }
    }
    ,
    { &hf_ipsc_linking_ipsc_slot1_id, 
      { "IPSC Slot 1", "ipsc.linking.ipsc_slot1", FT_UINT8, BASE_HEX, VALS(valstring_linking_ipsc_slot), 0x0c, NULL, HFILL }
    }
    ,
    { &hf_ipsc_linking_ipsc_slot2_id, 
      { "IPSC Slot 2", "ipsc.linking.ipsc_slot2", FT_UINT8, BASE_HEX, VALS(valstring_linking_ipsc_slot), 0x03, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_id, 
      { "Service FLAGS", "ipsc.service_flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte1_id, 
      { "BYTE 1", "ipsc.service_flags.byte1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte2_id, 
      { "BYTE 2", "ipsc.service_flags.byte2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte3_id, 
      { "BYTE 3", "ipsc.service_flags.byte3", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte3_rdac_id, 
      { "RDAC call", "ipsc.service_flags.byte3.rdac", FT_BOOLEAN, 8, TFS(&valstring_service_flags_rdac), 0x80, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte3_unk1_id, 
      { "Unk1", "ipsc.service_flags.byte3.unk1", FT_BOOLEAN, 8, TFS(&valstring_service_flags_unk1), 0x40, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte3_3rdpy_id, 
      { "3rd Party", "ipsc.service_flags.byte3.3rdpy", FT_BOOLEAN, 8, TFS(&valstring_service_flags_3rdpy), 0x20, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte3_unk2_id, 
      { "Unk2", "ipsc.service_flags.byte3.3rdpy", FT_UINT8, BASE_HEX, NULL, 0x1f, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte4_id, 
      { "BYTE 4", "ipsc.service_flags.byte4", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte4_unk1_id, 
      { "Unk 1", "ipsc.service_flags.byte4.unk1", FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte4_auth_id, 
      { "Authenticated packets", "ipsc.service_flags.byte4.auth", FT_BOOLEAN, 8, TFS(&valstring_service_flags_auth), 0x10, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte4_voice_id, 
      { "Voice enabled", "ipsc.service_flags.byte4.voice", FT_BOOLEAN, 8, TFS(&valstring_service_flags_voice), 0x08, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte4_data_id, 
      { "Data enabled", "ipsc.service_flags.byte4.data", FT_BOOLEAN, 8, TFS(&valstring_service_flags_data), 0x04, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte4_unk2_id, 
      { "Unk 2", "ipsc.service_flags.byte4.unk2", FT_BOOLEAN, 8, TFS(&valstring_service_flags_unk2), 0x02, NULL, HFILL }
    }
    ,
    { &hf_ipsc_service_flags_byte4_master_id, 
      { "Master", "ipsc.service_flags.byte4.master", FT_BOOLEAN, 8, TFS(&valstring_service_flags_master), 0x01, NULL, HFILL }
    }
    ,
    { &hf_ipsc_version_id, 
      { "Version", "ipsc.version", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_seq_no_id, 
      { "Seq No", "ipsc.seq_no", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_src_id, 
      { "Src Id", "ipsc.src_id", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_dst_id, 
      { "Dst Id", "ipsc.dst_id", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_prio_v_d_id, 
      { "Priority Voice/Data", "ipsc.prio_v_d", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_call_ctrl_id, 
      { "Call Ctrl", "ipsc.call_ctrl", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_call_ctrl_info_id, 
      { "Call Ctrl Info", "ipsc.call_ctrl_info", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_call_ctrl_src_id, 
      { "Call Ctrl Src", "ipsc.call_ctrl_src", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_payload_type_id, 
      { "Payload Type", "ipsc.payload_type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_call_seq_no_id, 
      { "Call Seq No", "ipsc.call_seq_no", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_timestamp_id, 
      { "Timestamp", "ipsc.timestamp", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_sync_src_id, 
      { "Sync Src", "ipsc.sync_src", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_data_type_voice_hdr_id, 
      { "Data Type Voice Hdr", "ipsc.data_type_voice_hdr", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_rssi_threshold_and_parity_id, 
      { "RSSI Threshold and Parity", "ipsc.rssi_threshold_and_parity", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_length_to_follow_id, 
      { "Length to Follow - in 2byte words", "ipsc.length_to_follow", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_length_to_follow2_id, 
      { "Length to Follow 2 - in bytes", "ipsc.length_to_follow2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_rssi_status_id, 
      { "RSSI Status", "ipsc.rssi_status", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_slot_type_sync_id, 
      { "Slot Type Sync", "ipsc.slot_type_sync", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_data_size_id, 
      { "Data Size", "ipsc.data_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_data_id, 
      { "Data", "ipsc.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_digest_id, 
      { "Auth Digest", "ipsc.digest", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_ipsc_unk1_id, 
      { "Unk_1_Byte", "ipsc.unk1", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }
  };

  static gint *ett[] = {
    &ett_ipsc
  };

  proto_ipsc = proto_register_protocol("MotoTrbo IP Site Connect",
                                      "IPSC", "ipsc");
  proto_register_field_array(proto_ipsc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("ipsc", dissect_ipsc, proto_ipsc);
}

void
proto_reg_handoff_ipsc(void)
{
  dissector_handle_t ipsc_handle;

  ipsc_handle = find_dissector("ipsc");

  dissector_add_uint("udp.port", 51001, ipsc_handle);
}
