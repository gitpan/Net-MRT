/*
 * mrttypes.h
 * $Id$
 *
 * Copyright (C) 2013 MaxiM Basunov <maxim.basunov@gmail.com>
 * All rights reserved.
 *
 * This program is free software; you may redistribute it and/or
 * modify it under the same terms as Perl itself.
 */

// Definitions of structures and enums for MRT routing information export format
// http://tools.ietf.org/html/draft-ietf-grow-mrt-13

// 16k is large enough for BGP UPDATE message
#define BUFFER_SIZE 16384

enum MRT_TYPES {
    MT_START            = 1,
    MT_I_AM_DEAD        = 3,
    MT_OSPF             = 11,
    MT_TABLE_DUMP       = 12,
    MT_TABLE_DUMP_V2    = 13,
    MT_BGP4MP           = 16,
    MT_BGP4MP_ET        = 17,
    MT_ISIS             = 32,
    MT_ISIS_ET          = 33,
    MT_OSPFv3           = 48,
    MT_OSPFv3_ET        = 49,
};

enum MT_TABLE_DUMP_V2_SUBTYPES {
    MST_TD2_PEER_INDEX_TABLE    = 1,
    MST_TD2_RIB_IPV4_UNICAST    = 2,
    MST_TD2_RIB_IPV4_MULTICAST  = 3,
    MST_TD2_RIB_IPV6_UNICAST    = 4,
    MST_TD2_RIB_IPV6_MULTICAST  = 5,
    MST_TD2_RIB_GENERIC         = 6,
};

struct _MRT_MESSAGE {
    uint32_t timestamp;
    uint16_t type;
    uint16_t subtype;
    uint32_t length;
    char message[BUFFER_SIZE];
} __attribute__((__packed__));
typedef struct _MRT_MESSAGE MRT_MESSAGE;

// Helper function to copy next SZ bytes to destination and move pointer
inline void mrt_copy_next(char ** src, void* const dst, int const sz)
{
    memcpy(dst, *src, sz);
    *src = *src + sz;
    return;
}