/*
 * MRT.xs
 * $Id$
 *
 * Copyright (C) 2013 MaxiM Basunov <maxim.basunov@gmail.com>
 * All rights reserved.
 *
 * This program is free software; you may redistribute it and/or
 * modify it under the same terms as Perl itself.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
// #include "poll.h"
#ifdef I_UNISTD
#  include <unistd.h>
#endif
#if defined(I_FCNTL) || defined(HAS_FCNTL)
#  include <fcntl.h>
#endif

#include "ppport.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "mrttypes.h"

// Windows XP workaround for inet_ntop
// TODO: Windows Vista/7 can use InetNtop
// TODO: http://vinsworldcom.blogspot.com/2012/08/ipv6-in-perl-on-windows_20.html
#ifdef WIN32
    #include "inet_ntop.c"
#endif

// String buffer size
#define SBUFF 200

// Function to decode single MRT message and compose HV contents
void mrt_decode(HV* const rt, Off_t const msgpos, MRT_MESSAGE* const mh)
{
    char sbuff[SBUFF] = {};
    char* pos = (char*)&mh->message;
    int AF = 0;
    uint32_t seq;
    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof(sa6));
    char ip_address[INET6_ADDRSTRLEN];

    switch (mh->type) {
        case MT_TABLE_DUMP_V2:
            switch (mh->subtype) {
                // Try to decode MULTICAST/ANYCAST
                //case MST_TD2_RIB_IPV6_MULTICAST:
                case MST_TD2_RIB_IPV6_UNICAST:
                    AF = AF_INET6;
                //case MST_TD2_RIB_IPV4_MULTICAST:
                case MST_TD2_RIB_IPV4_UNICAST:
                    if (AF == 0) AF = AF_INET; // Address Family also set for IPV6 messages

                    // Decode Sequence
                    mrt_copy_next(&pos, &seq, 4);
                    seq = ntohl(seq);
                    hv_stores(rt, "sequence", newSVuv(seq));

                    // Decode Prefix Bits
                    uint8_t prefix_bits;
                    mrt_copy_next(&pos, &prefix_bits, 1);
                    hv_stores(rt, "bits", newSVuv(prefix_bits));

                    // Decode Prefix
                    memset(&sa6, 0, sizeof(sa6));
                    if (prefix_bits > 0)
                        mrt_copy_next(&pos, &sa6, (int)ceil((double)prefix_bits/8));
                    inet_ntop(AF, &sa6, &ip_address, INET6_ADDRSTRLEN);
                    hv_stores(rt, "prefix", newSVpv(ip_address, 0));

                    // Decode count of entries
                    uint16_t entries;
                    mrt_copy_next(&pos, &entries, 2);
                    entries = ntohs(entries);

                    // Prepare entres
                    AV* av = newAV();
                    hv_stores(rt, "entries", newRV_noinc((SV *)av));
                    // Loop each entry
                    while (entries > 0)
                    {
                        entries--;

                        // Prepare Entry HashRef
                        HV* entry = newHV();
                        av_push(av, newRV_noinc((SV *)entry));

                        // Decode one entry
                        uint16_t peer;
                        mrt_copy_next(&pos, &peer, 2);
                        peer = ntohs(peer);
                        hv_stores(entry, "peer_index", newSVuv(peer));

                        // Decode Originated Time
                        uint32_t orig_time;
                        mrt_copy_next(&pos, &orig_time, 4);
                        orig_time = ntohl(orig_time);
                        hv_stores(entry, "originated_time", newSVuv(orig_time));

                        // Store length of BGP attributes
                        uint16_t attributes_length;
                        mrt_copy_next(&pos, &attributes_length, 2);
                        attributes_length = ntohs(attributes_length);

                        // Store pointer to BGP attributes
                        char* pBgpAttributes = pos;
                        pos = pos + attributes_length; // Skip pos to next entry

                        // Scan each BGP attribute
                        while (pBgpAttributes < pos) // pos points to next entry
                        {
                            // Parse each attribute
                            uint8_t attribute_flags;
                            mrt_copy_next(&pBgpAttributes, &attribute_flags, 1);
                            uint8_t attribute_code;
                            mrt_copy_next(&pBgpAttributes, &attribute_code, 1);
                            // Check for Extended Length and read length
                            uint16_t attribute_len = 0, attribute_remain_len;
                            if (attribute_flags & 0x10) {
                                mrt_copy_next(&pBgpAttributes, &attribute_len, 2);
                                attribute_len = ntohs(attribute_len);
                            } else {
                                uint8_t att_len_8;
                                mrt_copy_next(&pBgpAttributes, &att_len_8, 1);
                                attribute_len = att_len_8;
                            }
                            attribute_remain_len = attribute_len;

                            // Some temporary variables
                            AV* avTmpAv;
                            uint8_t iTmpI8;
                            uint16_t iTmpI16;
                            uint32_t iTmpI32;

                            // Decode attributes
                            switch (attribute_code)
                            {
                                // 1	ORIGIN	[RFC4271]
                                case 1:
                                    mrt_copy_next(&pBgpAttributes, &iTmpI8, 1);
                                    hv_stores(entry, "ORIGIN", newSVuv(iTmpI8));
                                    break;
                                // 2	AS_PATH	[RFC4271]
                                case 2:
                                    avTmpAv = (AV *)sv_2mortal((SV *)newAV());
                                    hv_stores(entry, "AS_PATH", newRV_inc((SV *)avTmpAv));
                                    while (attribute_remain_len > 0)
                                    {
                                        // Read next AS_PATH subtype
                                        attribute_remain_len -= 2;
                                        uint8_t iPathType;
                                        uint8_t iPathCount;
                                        mrt_copy_next(&pBgpAttributes, &iPathType, 1);
                                        mrt_copy_next(&pBgpAttributes, &iPathCount, 1);

                                        uint32_t iAsPathEntry;
                                        // Decode AS_SET & AS_SEQUENCE
                                        AV* avTmpAv2;
                                        if (iPathType == 1) // Compose subarray in case of AS_SET
                                        {
                                            avTmpAv2 = (AV *)sv_2mortal((SV *)newAV());
                                            av_push(avTmpAv, newRV_inc((SV *)avTmpAv2));
                                        }
                                        while (iPathCount > 0) {
                                            iPathCount--;
                                            attribute_remain_len -= 4; // NOTE: RIPE RIS hold 4-byte ASn in AS_PATH
                                            mrt_copy_next(&pBgpAttributes, &iAsPathEntry, 4);
                                            iAsPathEntry = ntohl(iAsPathEntry);
                                            av_push(((iPathType == 1)? avTmpAv2 : avTmpAv), newSVuv(iAsPathEntry));
                                        }
                                    } // end while (attribute_remain_len > 0)
                                    break; // 2	AS_PATH	[RFC4271]
                                // 3	NEXT_HOP	[RFC4271]
                                case 3:
                                    mrt_copy_next(&pBgpAttributes, &iTmpI32, 4);
                                    inet_ntop(AF_INET, &iTmpI32, &ip_address, INET6_ADDRSTRLEN);
                                    hv_stores(entry, "NEXT_HOP", newSVpv(ip_address, 0));
                                    break;// 3	NEXT_HOP	[RFC4271]
                                // 4	MULTI_EXIT_DISC	[RFC4271]
                                case 4:
                                    mrt_copy_next(&pBgpAttributes, &iTmpI32, 4);
                                    iTmpI32 = ntohl(iTmpI32);
                                    hv_stores(entry, "MULTI_EXIT_DISC", newSVuv(iTmpI32));
                                    break;// 4	MULTI_EXIT_DISC	[RFC4271]
                                // 5	LOCAL_PREF	[RFC4271]
                                case 5:
                                    mrt_copy_next(&pBgpAttributes, &iTmpI32, 4);
                                    iTmpI32 = ntohl(iTmpI32);
                                    hv_stores(entry, "LOCAL_PREF", newSVuv(iTmpI32));
                                    break;// 5	LOCAL_PREF	[RFC4271]
                                // 6	ATOMIC_AGGREGATE	[RFC4271]
                                case 6:
                                    hv_stores(entry, "ATOMIC_AGGREGATE", &PL_sv_undef);
                                    break;// 6	ATOMIC_AGGREGATE	[RFC4271]
                                // 7	AGGREGATOR	[RFC4271]
                                case 7:
                                    //break;// 7	AGGREGATOR	[RFC4271]
                                // 8	COMMUNITY	[RFC1997]
                                case 8:
                                    //break;// 8	COMMUNITY	[RFC1997]
                                // 14	MP_REACH_NLRI	[RFC4760]
                                case 14:
                                    //break;// 14	MP_REACH_NLRI	[RFC4760]
                                default:
                                    snprintf(sbuff, SBUFF, "unsupported%d", attribute_code);
                                    hv_store(entry, sbuff, strlen(sbuff), &PL_sv_undef, 0);
                                    pBgpAttributes += attribute_len;
                            } // switch (attribute_code)
                        } // pBgpAttributes < pos
                    } // while (entries > 0)

                    break; // subtype = IPv4/6 UNICAST/MULTICAST
                default:
                    snprintf(sbuff, SBUFF, "Unsupported MRT type %d subtype %d in message at %lli", mh->type, mh->subtype, (intmax_t)msgpos);
                    hv_stores(rt, "error", newSVpv(sbuff, 0));
            } // switch subtype
            break; // MT_TABLE_DUMP_V2
        default:
            snprintf(sbuff, SBUFF, "Unsupported MRT type %d in message at %lli", mh->type, (intmax_t)msgpos);
            hv_stores(rt, "error", newSVpv(sbuff, 0));
    } // switch message type
    return;
}

MODULE = Net::MRT		PACKAGE = Net::MRT

void
mrt_read_next(f)
PerlIO * f;
    PROTOTYPE: *
    PPCODE:
        # Definitions
        Off_t msgpos = PerlIO_tell(f); // Store message position & check for proper handle
        int sz;
        MRT_MESSAGE mh;
        char sbuff[SBUFF] = {};
        HV* rt;

        if (msgpos == -1)
            croak("Invalid filehandle passed to mrt_read_next");
        sz = PerlIO_read(f, &mh, 12);
        if (sz == 0)
        {
            # No data to read
            ST(0) = &PL_sv_undef;
            XSRETURN(1);
        } else {
            # Network to host for MH
            mh.timestamp = ntohl(mh.timestamp);
            mh.type      = ntohs(mh.type);
            mh.subtype   = ntohs(mh.subtype);
            mh.length    = ntohl(mh.length);

            # Create resulting HASHREF
            rt = newHV();
            hv_stores(rt, "timestamp",  newSVuv(mh.timestamp));
            hv_stores(rt, "type",       newSVuv(mh.type));
            hv_stores(rt, "subtype",    newSVuv(mh.subtype));

            # Decode header
            # Check for length to be less than buffer
            if (mh.length > BUFFER_SIZE)
            {
                snprintf(sbuff, SBUFF, "Message length too big at %lli", (intmax_t)msgpos);
                hv_stores(rt, "error", newSVpv(sbuff, 0));
                PerlIO_seek(f, mh.length, SEEK_CUR);
            } else {
                # Try to read message
                if (mh.length > 0)
                    sz = PerlIO_read(f, &mh.message, mh.length);
                if ((mh.length > 0) && (sz != mh.length))
                    croak("Unable to read %d bytes in message at pos %lli", mh.length, (intmax_t)msgpos);

                # Try to decode
                mrt_decode(rt, msgpos, &mh);
            }
            ST(0) = sv_2mortal((SV*)newRV_noinc((SV*)rt));
            XSRETURN(1);
        }

HV*
mrt_decode_single(type, subtype, message)
uint16_t type;
uint16_t subtype;
SV*      message;
    CODE:
        MRT_MESSAGE mh;
        char* msg;

        // Prepare returning variable(s)
        RETVAL = newHV();

        // Prepare intermediate variables
        mh.timestamp    = 0;
        mh.type         = type;
        mh.subtype      = subtype;
        msg = (char*)SvPV(message, mh.length);
        memcpy(&mh.message, msg, mh.length);

        // Perform checks
        if (mh.length == 0)
            croak("I don't know how to decode a message without contents");
        if (mh.length > BUFFER_SIZE)
            croak("Unable to process message larger than %d bytes", BUFFER_SIZE);

        mrt_decode(RETVAL, 0, &mh);
        sv_2mortal((SV*)newRV_noinc((SV*)RETVAL));
    OUTPUT:
        RETVAL

# void mrt_decode(HV* const rt, Off_t const msgpos, MRT_MESSAGE* const mh)
