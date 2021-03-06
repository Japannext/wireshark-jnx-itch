/* jnx_itch.c
 * Routines for JNX ITCH Protocol dissection
 *
 * Copyright 1998 Gerald Combs <gerald@wireshark.org>
 * Copyright 2007,2008 Didier Gautheron <dgautheron@magic.fr>
 * Copyright 2013-2021 Japannext Co., Ltd. <https://www.japannext.co.jp/>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Documentation:
 * https://www.japannext.co.jp/library/
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/proto.h>
#include <ws_attributes.h>

#ifndef VERSION
#define VERSION "1.6.0"
#endif

#define DLL_PUBLIC __attribute__((__visibility__("default")))

DLL_PUBLIC const gchar plugin_version[] = VERSION;
DLL_PUBLIC const gchar plugin_release[] = VERSION_RELEASE;

DLL_PUBLIC void plugin_register(void);

#define TIMESTAMP_SECONDS_MSG_LEN 5
#define SYSTEM_EVENT_MSG_LEN 10
#define PRICE_TICK_SIZE_MSG_LEN 17
#define ORDERBOOK_DIRECTORY_MSG_LEN 45
#define TRADING_STATE_MSG_LEN 14
#define SHORT_SELLING_PRICE_RESTRICTION_STATE_MSG_LEN 14
#define ADD_ORDER_MSG_LEN 30
#define ADD_ORDER_WITH_ATTRIBUTES_MSG_LEN 35
#define ORDER_EXECUTED_MSG_LEN 25
#define ORDER_DELETED_MSG_LEN 13
#define ORDER_REPLACED_MSG_LEN 29
#define END_OF_SNAPSHOT_MSG_LEN 9

// 8 byte Quantity fields
#define ORDERBOOK_DIRECTORY_MSG_LEN_64 53
#define ADD_ORDER_MSG_LEN_64 34
#define ADD_ORDER_WITH_ATTRIBUTES_MSG_LEN_64 39
#define ORDER_EXECUTED_MSG_LEN_64 29
#define ORDER_REPLACED_MSG_LEN_64 33

static const value_string message_types_val[] = {
 { 'T', "Timestamp - Seconds" },
 { 'L', "Price Tick Size" },
 { 'R', "Orderbook Directory" },
 { 'H', "Trading State" },
 { 'Y', "Short Selling Price Restriction State" },
 { 'A', "Order Added" },
 { 'F', "Order Added with Attributes" },
 { 'E', "Order Executed" },
 { 'D', "Order Deleted" },
 { 'U', "Order Replaced" },
 { 'S', "System Event" },
 { 'G', "End of Snapshot" },
 { 0, NULL }
};

static const value_string system_event_val[] = {
 { 'O', "Start of Messages" },
 { 'S', "Start of System hours" },
 { 'Q', "Start of Market hours" },
 { 'M', "End of Market hours" },
 { 'E', "End of System hours" },
 { 'C', "End of Messages" },
 { 0, NULL }
};

static const value_string trading_state_val[] = {
 { 'T', "Trading" },
 { 'V', "Suspended" },
 { 0, NULL }
};

static const value_string price_restriction_state_val[] = {
 { '0', "No price restriction" },
 { '1', "Price restriction in effect" },
 { 0, NULL }
};

static const value_string buy_sell_val[] = {
 { 'B', "Buy" },
 { 'S', "Sell" },
 { 0, NULL}
};

/* Initialize the protocol and registered fields */
static int proto_jnx_itch = -1;
static dissector_handle_t jnx_itch_handle;

/* Initialize the subtree pointers */
static gint ett_jnx_itch = -1;

static int hf_jnx_itch_message_type = -1;
static int hf_jnx_itch_group = -1;
static int hf_jnx_itch_isin = -1;
static int hf_jnx_itch_orderbook = -1;
static int hf_jnx_itch_round_lot_size = -1;
static int hf_jnx_itch_round_lot_size_64 = -1;
static int hf_jnx_itch_tick_size_table = -1;
static int hf_jnx_itch_tick_size = -1;
static int hf_jnx_itch_price_start = -1;
static int hf_jnx_itch_price_decimals = -1;
static int hf_jnx_itch_quantity_decimals = -1;
static int hf_jnx_itch_upper_price_limit = -1;
static int hf_jnx_itch_lower_price_limit = -1;

static int hf_jnx_itch_system_event = -1;
static int hf_jnx_itch_second = -1;
static int hf_jnx_itch_nanoseconds = -1;

static int hf_jnx_itch_trading_state = -1;
static int hf_jnx_itch_price_restriction_state = -1;
static int hf_jnx_itch_order_reference_number = -1;
static int hf_jnx_itch_original_order_reference_number = -1;
static int hf_jnx_itch_new_order_reference_number = -1;
static int hf_jnx_itch_buy_sell = -1;
static int hf_jnx_itch_quantity = -1;
static int hf_jnx_itch_quantity_64 = -1;
static int hf_jnx_itch_price = -1;
static int hf_jnx_itch_attribution = -1;
static int hf_jnx_itch_order_type = -1;
static int hf_jnx_itch_executed = -1;
static int hf_jnx_itch_executed_64 = -1;
static int hf_jnx_itch_match_number = -1;
static int hf_jnx_itch_sequence_number = -1;

static int hf_jnx_itch_message = -1;

static range_t *global_soupbintcp_port_range = NULL;
static range_t *soupbintcp_port_range = NULL;
static range_t *global_moldudp64_udp_range = NULL;
static range_t *moldudp64_udp_range = NULL;

/* -------------------------- */
static gboolean
detect_32bit_message(tvbuff_t *tvb)
{
    guint8 msg_type = tvb_get_guint8(tvb, 0);
    guint msg_len = tvb_reported_length(tvb);

    switch (msg_type) {
    case 'T':
        return msg_len == TIMESTAMP_SECONDS_MSG_LEN;
    case 'S':
        return msg_len == SYSTEM_EVENT_MSG_LEN;
    case 'L':
        return msg_len == PRICE_TICK_SIZE_MSG_LEN;
    case 'R':
        return msg_len == ORDERBOOK_DIRECTORY_MSG_LEN;
    case 'H':
        return msg_len == TRADING_STATE_MSG_LEN;
    case 'Y':
        return msg_len == SHORT_SELLING_PRICE_RESTRICTION_STATE_MSG_LEN;
    case 'A':
        return msg_len == ADD_ORDER_MSG_LEN;
    case 'F':
        return msg_len == ADD_ORDER_WITH_ATTRIBUTES_MSG_LEN;
    case 'E' :
        return msg_len == ORDER_EXECUTED_MSG_LEN;
    case 'D' :
        return msg_len == ORDER_DELETED_MSG_LEN;
    case 'U':
        return msg_len == ORDER_REPLACED_MSG_LEN;
    case 'G':
        return msg_len == END_OF_SNAPSHOT_MSG_LEN;
    default:
        break;
    }
    return FALSE;
}

/* -------------------------- */
static gboolean
detect_64bit_message(tvbuff_t *tvb)
{
    guint8 msg_type = tvb_get_guint8(tvb, 0);
    guint16 msg_len = tvb_reported_length(tvb);

    switch (msg_type) {
    case 'R':
        return msg_len == ORDERBOOK_DIRECTORY_MSG_LEN_64;
    case 'A':
        return msg_len == ADD_ORDER_MSG_LEN_64;
    case 'F':
        return msg_len == ADD_ORDER_WITH_ATTRIBUTES_MSG_LEN_64;
    case 'U':
        return msg_len == ORDER_REPLACED_MSG_LEN_64;
    case 'E':
        return msg_len == ORDER_EXECUTED_MSG_LEN_64;
    default:
        break;
    }
    return FALSE;
}

/* ---------------------- */
static int
order_ref_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_itch_tree, int offset, int col)
{
  if (jnx_itch_tree) {
      guint64 value = tvb_get_ntoh64(tvb, offset);

      proto_tree_add_uint64(jnx_itch_tree, col, tvb, offset, 8, value);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %lu", value);
  }
  return offset + 8;
}

/* ---------------------- */
static int
match_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_itch_tree, int offset, int col)
{
  if (jnx_itch_tree) {
      guint64 value = tvb_get_ntoh64(tvb, offset);

      proto_tree_add_uint64(jnx_itch_tree, col, tvb, offset, 8, value);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %lu", value);
  }
  return offset + 8;
}

/* -------------------------- */
static int
timestamp(tvbuff_t *tvb, proto_tree *jnx_itch_tree, int id, int offset)
{

  if (jnx_itch_tree) {
      guint32 value = tvb_get_ntohl(tvb, offset);
      proto_tree_add_uint(jnx_itch_tree, id, tvb, offset, 4, value);
  }
  return offset + 4;
}

/* -------------------------- */
static int
quantity(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_itch_tree, int id, int id_64, int offset)
{
    if (jnx_itch_tree) {
        if (detect_64bit_message(tvb)) {
            guint64 value = tvb_get_ntoh64(tvb, offset);

            proto_tree_add_uint64(jnx_itch_tree, id_64, tvb, offset, 8, value);
            col_append_fstr(pinfo->cinfo, COL_INFO, " qty %lu", value);
            offset += 8;
        }
        else {
            guint32 value = tvb_get_ntohl(tvb, offset);

            proto_tree_add_uint(jnx_itch_tree, id, tvb, offset, 4, value);
            col_append_fstr(pinfo->cinfo, COL_INFO, " qty %u", value);
            offset += 4;
        }
    }
    return offset;
}

/* -------------------------- */
static int
price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_itch_tree, int id, int offset)
{
  if (jnx_itch_tree) {
      guint32 value = tvb_get_ntohl(tvb, offset);

      proto_tree_add_uint(jnx_itch_tree, id, tvb, offset, 4, value);
      col_append_fstr(pinfo->cinfo, COL_INFO, " price %u", value);
  }
  return offset + 4;
}

/* -------------------------- */
static int
orderbook(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_itch_tree, int offset)
{
  if (jnx_itch_tree) {
      guint32 orderbook_id = tvb_get_ntohl(tvb, offset);

      proto_tree_add_uint(jnx_itch_tree, hf_jnx_itch_orderbook, tvb, offset, 4, orderbook_id);
      col_append_fstr(pinfo->cinfo, COL_INFO, " <%d>", orderbook_id);
  }
  return offset + 4;
}

/* -------------------------- */
static int
proto_tree_add_char(proto_tree *jnx_tree, int hf_field, tvbuff_t *tvb, int offset, const value_string *v_str)
{
  char *vl;

  vl = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 1, ENC_ASCII);
  proto_tree_add_string_format_value(jnx_tree, hf_field, tvb,
        offset, 1, vl, "%s (%s)", vl, val_to_str_const(*vl, v_str, "Unknown"));

  return offset + 1;
}

/* -------------------------- */
static int
order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_itch_tree, int offset)
{
  offset = order_ref_number(tvb, pinfo, jnx_itch_tree, offset, hf_jnx_itch_order_reference_number);

  col_append_fstr(pinfo->cinfo, COL_INFO, " %c", tvb_get_guint8(tvb, offset));
  offset = proto_tree_add_char(jnx_itch_tree, hf_jnx_itch_buy_sell, tvb, offset, buy_sell_val);

  offset = quantity(tvb, pinfo, jnx_itch_tree, hf_jnx_itch_quantity, hf_jnx_itch_quantity_64, offset);

  offset = orderbook(tvb, pinfo, jnx_itch_tree, offset);

  proto_tree_add_item(jnx_itch_tree, hf_jnx_itch_group, tvb, offset, 4, ENC_ASCII|ENC_NA);
  offset += 4;

  offset = price(tvb, pinfo, jnx_itch_tree, hf_jnx_itch_price, offset);
  return offset;
}

static int
replace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_itch_tree, int offset)
{
  offset = order_ref_number(tvb, pinfo, jnx_itch_tree, offset, hf_jnx_itch_original_order_reference_number);
  offset = order_ref_number(tvb, pinfo, jnx_itch_tree, offset, hf_jnx_itch_new_order_reference_number);
  offset = quantity(tvb, pinfo, jnx_itch_tree, hf_jnx_itch_quantity, hf_jnx_itch_quantity_64, offset);
  offset = price(tvb, pinfo, jnx_itch_tree, hf_jnx_itch_price, offset);

  return offset;
}

/* -------------------------- */
static int
executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_itch_tree, int offset)
{
  offset = order_ref_number(tvb, pinfo, jnx_itch_tree, offset, hf_jnx_itch_order_reference_number);

  offset = quantity(tvb, pinfo, jnx_itch_tree, hf_jnx_itch_executed, hf_jnx_itch_executed_64, offset);

  offset = match_number(tvb, pinfo, jnx_itch_tree, offset, hf_jnx_itch_match_number);

  return offset;
}

/* -------------------------- */
static int
orderbook_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_itch_tree, int offset)
{
  offset = orderbook(tvb, pinfo, jnx_itch_tree, offset);
  proto_tree_add_item(jnx_itch_tree, hf_jnx_itch_isin, tvb, offset, 12, ENC_ASCII|ENC_NA);
  offset += 12;
  proto_tree_add_item(jnx_itch_tree, hf_jnx_itch_group, tvb, offset, 4, ENC_ASCII|ENC_NA);
  offset += 4;
  if (detect_64bit_message(tvb)) {
    proto_tree_add_uint64(jnx_itch_tree, hf_jnx_itch_round_lot_size_64, tvb, offset, 8, tvb_get_ntoh64(tvb, offset));
    offset += 8;
  }
  else {
    proto_tree_add_uint(jnx_itch_tree, hf_jnx_itch_round_lot_size, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
    offset += 4;
  }
  proto_tree_add_uint(jnx_itch_tree, hf_jnx_itch_tick_size_table, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
  offset += 4;
  proto_tree_add_uint(jnx_itch_tree, hf_jnx_itch_price_decimals, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
  offset += 4;
  proto_tree_add_uint(jnx_itch_tree, hf_jnx_itch_upper_price_limit, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
  offset += 4;
  proto_tree_add_uint(jnx_itch_tree, hf_jnx_itch_lower_price_limit, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
  offset += 4;
  if (detect_64bit_message(tvb)) {
    proto_tree_add_uint(jnx_itch_tree, hf_jnx_itch_quantity_decimals, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
    offset += 4;
  }

  return offset;
}

/* ---------------------------- */
static int
dissect_jnx_itch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item *ti;
    proto_tree *jnx_itch_tree = NULL;
    guint8 jnx_itch_type;
    int  offset = 0;

    (void)(data);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Japannext ITCH");

    jnx_itch_type = tvb_get_guint8(tvb, offset);

    if (tree) {
        const gchar *rep = val_to_str(jnx_itch_type, message_types_val, "Unknown packet type (0x%02x) ");
        col_clear(pinfo->cinfo, COL_INFO);
        col_add_str(pinfo->cinfo, COL_INFO, rep);
        if (tree) {
            ti = proto_tree_add_protocol_format(tree, proto_jnx_itch, tvb, offset, -1, "Japannext ITCH %s",
                                                rep);

            jnx_itch_tree = proto_item_add_subtree(ti, ett_jnx_itch);
        }
    }

    offset = proto_tree_add_char(jnx_itch_tree, hf_jnx_itch_message_type, tvb, offset, message_types_val);

    switch (jnx_itch_type) {
    case 'T': /* seconds */
        offset = timestamp (tvb, jnx_itch_tree, hf_jnx_itch_second, offset);
        break;

    case 'S': /* system event */
        offset = timestamp (tvb, jnx_itch_tree, hf_jnx_itch_nanoseconds, offset);
        proto_tree_add_item(jnx_itch_tree, hf_jnx_itch_group, tvb, offset, 4, ENC_ASCII|ENC_NA);
        offset += 4;
        offset = proto_tree_add_char(jnx_itch_tree, hf_jnx_itch_system_event, tvb, offset, system_event_val);
        break;

    case 'L':
        offset = timestamp (tvb, jnx_itch_tree, hf_jnx_itch_nanoseconds, offset);
        proto_tree_add_uint(jnx_itch_tree, hf_jnx_itch_tick_size_table, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
        offset += 4;
        proto_tree_add_uint(jnx_itch_tree, hf_jnx_itch_tick_size, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
        offset += 4;
        proto_tree_add_uint(jnx_itch_tree, hf_jnx_itch_price_start, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
        offset += 4;
        break;

    case 'R': /* Stock Directory */
        offset = timestamp (tvb, jnx_itch_tree, hf_jnx_itch_nanoseconds, offset);
        offset = orderbook_directory(tvb, pinfo, jnx_itch_tree, offset);
        break;

    case 'H': /* Stock trading action */
        offset = timestamp (tvb, jnx_itch_tree, hf_jnx_itch_nanoseconds, offset);
        offset = orderbook(tvb, pinfo, jnx_itch_tree, offset);
        proto_tree_add_item(jnx_itch_tree, hf_jnx_itch_group, tvb, offset, 4, ENC_ASCII|ENC_NA);
        offset += 4;
        offset = proto_tree_add_char(jnx_itch_tree, hf_jnx_itch_trading_state, tvb, offset, trading_state_val);
        break;

    case 'Y': /* Short Selling Price Restriction Indicator */
        offset = timestamp (tvb, jnx_itch_tree, hf_jnx_itch_nanoseconds, offset);
        offset = orderbook(tvb, pinfo, jnx_itch_tree, offset);
        proto_tree_add_item(jnx_itch_tree, hf_jnx_itch_group, tvb, offset, 4, ENC_ASCII|ENC_NA);
        offset += 4;
        offset = proto_tree_add_char(jnx_itch_tree, hf_jnx_itch_price_restriction_state, tvb, offset, price_restriction_state_val);
        break;

    case 'A': /* Add order, no MPID */
        offset = timestamp (tvb, jnx_itch_tree, hf_jnx_itch_nanoseconds, offset);
        offset = order(tvb, pinfo, jnx_itch_tree, offset);
        break;

    case 'F': /* Add order, MPID */
        offset = timestamp (tvb, jnx_itch_tree, hf_jnx_itch_nanoseconds, offset);
        offset = order(tvb, pinfo, jnx_itch_tree, offset);
        proto_tree_add_item(jnx_itch_tree, hf_jnx_itch_attribution, tvb, offset, 4, ENC_ASCII|ENC_NA);
        offset += 4;
        proto_tree_add_item(jnx_itch_tree, hf_jnx_itch_order_type, tvb, offset, 1, ENC_ASCII|ENC_NA);
        offset += 1;
        break;

    case 'U': /* Order replaced */
        offset = timestamp (tvb, jnx_itch_tree, hf_jnx_itch_nanoseconds, offset);
        offset = replace(tvb, pinfo, jnx_itch_tree, offset);
        break;

    case 'E' : /* Order executed */
        offset = timestamp (tvb, jnx_itch_tree, hf_jnx_itch_nanoseconds, offset);
        offset = executed(tvb, pinfo, jnx_itch_tree, offset);
        break;

    case 'D' : /* Order delete */
        offset = timestamp (tvb, jnx_itch_tree, hf_jnx_itch_nanoseconds, offset);
        offset = order_ref_number(tvb, pinfo, jnx_itch_tree, offset, hf_jnx_itch_order_reference_number);
        offset += 8;
        break;

    case 'G' : /* End of Snapshot */
        proto_tree_add_uint64(jnx_itch_tree, hf_jnx_itch_sequence_number, tvb, offset, 8, tvb_get_ntoh64(tvb, offset));
        offset += 8;
        break;

    default:
        /* unknown */
        proto_tree_add_item(jnx_itch_tree, hf_jnx_itch_message, tvb, offset, -1, ENC_ASCII|ENC_NA);
        break;
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */


static void range_delete_soupbintcp_port_callback(guint32 port, gpointer ptr _U_) {
    dissector_delete_uint("tcp.port", port, jnx_itch_handle);
}

static void range_add_soupbintcp_port_callback(guint32 port, gpointer ptr _U_) {
    dissector_add_uint("tcp.port", port, jnx_itch_handle);
}

static void range_delete_moldudp64_tcp_callback(guint32 port, gpointer ptr _U_) {
    dissector_delete_uint("moldudp64.payload", port, jnx_itch_handle);
}

static void range_add_moldudp64_tcp_callback(guint32 port, gpointer ptr _U_) {
    dissector_add_uint("moldudp64.payload", port, jnx_itch_handle);
}

static void jnx_itch_prefs(void)
{
    range_foreach(soupbintcp_port_range, range_delete_soupbintcp_port_callback, NULL);
    wmem_free(wmem_epan_scope(), soupbintcp_port_range);
    soupbintcp_port_range = range_copy(wmem_epan_scope(), global_soupbintcp_port_range);
    range_foreach(soupbintcp_port_range, range_add_soupbintcp_port_callback, NULL);

    range_foreach(moldudp64_udp_range, range_delete_moldudp64_tcp_callback, NULL);
    wmem_free(wmem_epan_scope(), moldudp64_udp_range);
    moldudp64_udp_range = range_copy(wmem_epan_scope(), global_moldudp64_udp_range);
    range_foreach(moldudp64_udp_range, range_add_moldudp64_tcp_callback, NULL);
}

/** Returns a guess if a packet is OUCH or not
 *
 * Since SOUP doesn't have a sub-protocol type flag, we have to use a
 * heuristic decision to determine if the contained protocol is OUCH
 * or ITCH (or something else entirely).  We look at the message type
 * code, and since we know that we're being called from SOUP, we can
 * check the passed-in length too: if the type code and the length
 * match, we guess at ITCH. */
static gboolean
dissect_jnx_itch_heur(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    if (!detect_32bit_message(tvb) && !detect_64bit_message(tvb))
        return FALSE;

    /* Perform dissection of this (initial) packet */
    dissect_jnx_itch(tvb, pinfo, tree, NULL);

    return TRUE;
}

void
proto_register_jnx_itch(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
    { &hf_jnx_itch_message_type,
      { "Message Type",         "jnx_itch.message_type",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_itch_second,
      { "Second",         "jnx_itch.second",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_itch_nanoseconds,
      { "Nanoseconds",         "jnx_itch.nanoseconds",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_itch_system_event,
      { "System Event",         "jnx_itch.system_event",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_itch_orderbook,
      { "Stock",         "jnx_itch.orderbook",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Uniqie orderbook identifier", HFILL }},

    { &hf_jnx_itch_isin,
      { "ISIN",         "jnx_itch.isin",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Denotes the orderbook ISIN for the issue.", HFILL }},

    { &hf_jnx_itch_tick_size_table,
      { "Tick Size Table",         "jnx_itch.tick_size_table",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Price tick size table identifier.", HFILL }},

    { &hf_jnx_itch_tick_size,
      { "Tick Size",         "jnx_itch.tick_size",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Price tick size.", HFILL }},

    { &hf_jnx_itch_price_start,
      { "Price Start",         "jnx_itch.price_start",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Start of price range for this tick size.", HFILL }},

    { &hf_jnx_itch_round_lot_size,
      { "Round Lot Size",         "jnx_itch.round_lot_size",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "The quantity that represents a round lot.", HFILL }},

    { &hf_jnx_itch_round_lot_size_64,
      { "Round Lot Size",         "jnx_itch.round_lot_size",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "The quantity that represents a round lot.", HFILL }},

    { &hf_jnx_itch_price_decimals,
      { "Price Decimals",         "jnx_itch.price_decimals",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of decimal places in the price field.", HFILL }},

    { &hf_jnx_itch_quantity_decimals,
      { "Quantity Decimals",         "jnx_itch.quantity_decimals",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of decimal places in quantity fields.", HFILL }},

    { &hf_jnx_itch_upper_price_limit,
      { "Upper Price Limit",         "jnx_itch.upper_price_limit",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Maximum tradable price", HFILL }},

    { &hf_jnx_itch_lower_price_limit,
      { "Lower Price Limit",         "jnx_itch.upper_lower_limit",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Minimum tradable price", HFILL }},

    { &hf_jnx_itch_group,
      { "Group",         "jnx_itch.group",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Orderbook group identifier", HFILL }},

    { &hf_jnx_itch_trading_state,
      { "Trading State",         "jnx_itch.trading_state",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_itch_price_restriction_state,
      { "Price Restriction State", "jnx_itch.price_restriction_state",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_itch_order_reference_number,
      { "Order Reference",         "jnx_itch.order_reference_number",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "Order reference number", HFILL }},

    { &hf_jnx_itch_original_order_reference_number,
      { "Original Order Reference",         "jnx_itch.original_order_reference_number",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "Original order reference number", HFILL }},

    { &hf_jnx_itch_new_order_reference_number,
      { "New Order Reference",         "jnx_itch.new_order_reference_number",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "New order reference number", HFILL }},

    { &hf_jnx_itch_buy_sell,
      { "Buy/Sell",         "jnx_itch.buy_sell",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Buy/Sell indicator", HFILL }},

    { &hf_jnx_itch_quantity,
      { "Quantity",         "jnx_itch.quantity",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Quantity", HFILL }},

    { &hf_jnx_itch_quantity_64,
      { "Quantity",         "jnx_itch.quantity",
        FT_UINT64, BASE_DEC,  NULL, 0x0,
        "Quantity", HFILL }},

    { &hf_jnx_itch_price,
      { "Price",         "jnx_itch.price",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Price", HFILL }},

    { &hf_jnx_itch_attribution,
      { "Attribution",         "jnx_itch.attribution",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Market participant identifier", HFILL }},

    { &hf_jnx_itch_order_type,
      { "Order Type",         "jnx_itch.order_type",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_itch_executed,
      { "Executed Quantity",         "jnx_itch.executed",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Quantity executed", HFILL }},

    { &hf_jnx_itch_executed_64,
      { "Executed Quantity",         "jnx_itch.executed",
        FT_UINT64, BASE_DEC,  NULL, 0x0,
        "Quantity executed", HFILL }},

    { &hf_jnx_itch_match_number,
      { "Match Number",         "jnx_itch.match_number",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "Match number", HFILL }},

    { &hf_jnx_itch_sequence_number,
      { "Sequence Number",         "jnx_itch.sequence_number",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "Sequence number", HFILL }},

    { &hf_jnx_itch_message,
      { "Message",         "jnx_itch.message",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }}
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_jnx_itch
    };

    module_t *jnx_itch_module;

    /* Register the protocol name and description */
    proto_jnx_itch = proto_register_protocol("Japannext ITCH", "JNX-ITCH", "jnx_itch");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_jnx_itch, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    jnx_itch_module = prefs_register_protocol(proto_jnx_itch, jnx_itch_prefs);

    prefs_register_range_preference(jnx_itch_module, "tcp.port", "SoupBinTCP ports", "SoupBinTCP port range", &global_soupbintcp_port_range, 65535);
    soupbintcp_port_range = range_empty(NULL);

    prefs_register_range_preference(jnx_itch_module, "udp.port", "MoldUDP64 UDP Ports", "MoldUDP64 UDP port to dissect on.", &global_moldudp64_udp_range, 65535);

    moldudp64_udp_range = range_empty(NULL);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_jnx_itch(void)
{
    jnx_itch_handle = create_dissector_handle(dissect_jnx_itch, proto_jnx_itch);
    heur_dissector_add("soupbintcp", dissect_jnx_itch_heur, "ITCH over SoupBinTCP", "jnx_itch_soupbintcp", proto_jnx_itch, HEURISTIC_ENABLE);
    dissector_add_for_decode_as("moldudp64.payload", jnx_itch_handle); /* for "decode-as" */
}

void
plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_jnx_itch;
    plug.register_handoff = proto_reg_handoff_jnx_itch; /* or NULL */
    proto_register_plugin(&plug);
}
