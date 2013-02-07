#!/usr/bin/perl -w

use strict;
use warnings;

use Test::More;
use Test::Deep;
use lib qw|../blib/lib ../blib/arch|;
use Net::MRT;

my @tests = (
        # Array rows:
        # - Test name
        # - Subtype (which subtype to decode)
        # - Message in HEX
        # - Decoded test (HASHREF)
        ## Sequence tests (formerly network to host order)
        [   "Test SEQUENCE=0", 2,
            "0000000008030000",
            { 'sequence' => 0, bits => 8, prefix => '3.0.0.0', 'entries' => [], }
        ],
        [   "Test SEQUENCE=1", 2,
            "0000000108030000",
            { 'sequence' => 1, bits => 8, prefix => '3.0.0.0', 'entries' => [], }
        ],
        [   "Test SEQUENCE=256", 2,
            "0000010008030000",
            { 'sequence' => 256, bits => 8, prefix => '3.0.0.0', 'entries' => [], }
        ],
        [   "Test SEQUENCE=4294967295", 2,
            "FFFFFFFF08030000",
            { 'sequence' => 4294967295, bits => 8, prefix => '3.0.0.0', 'entries' => [], }
        ],
        ## Prefix bits tests
        [   "Test IPv4 bits 0", 2,
            "00000000000000",
            { 'sequence' => 0, bits => 0, prefix => '0.0.0.0', 'entries' => [], }
        ],
        [   "Test IPv4 bits 1", 2,
            "0000000001800000",
            { 'sequence' => 0, bits => 1, prefix => '128.0.0.0', 'entries' => [], }
        ],
        [   "Test IPv4 bits 7", 2,
            "0000000007C00000",
            { 'sequence' => 0, bits => 7, prefix => '192.0.0.0', 'entries' => [], }
        ],
        [   "Test IPv4 bits 8", 2,
            "00000000087F0000",
            { 'sequence' => 0, bits => 8, prefix => '127.0.0.0', 'entries' => [], }
        ],
        [   "Test IPv4 bits 9", 2,
            "00000000097F800000",
            { 'sequence' => 0, bits => 9, prefix => '127.128.0.0', 'entries' => [], }
        ],
        [   "Test IPv4 bits 23", 2,
            "00000000170102040000",
            { 'sequence' => 0, bits => 23, prefix => '1.2.4.0', 'entries' => [], }
        ],
        [   "Test IPv4 bits 24", 2,
            "00000000180102030000",
            { 'sequence' => 0, bits => 24, prefix => '1.2.3.0', 'entries' => [], }
        ],
        [   "Test IPv4 bits 25", 2,
            "0000000019010203800000",
            { 'sequence' => 0, bits => 25, prefix => '1.2.3.128', 'entries' => [], }
        ],
        [   "Test IPv4 bits 32", 2,
            "0000000020101214FF0000",
            { 'sequence' => 0, bits => 32, prefix => '16.18.20.255', 'entries' => [], }
        ],
        [   "Test IPv4 bits 0", 4,
            "00000000000000",
            { 'sequence' => 0, bits => 0, prefix => '::', 'entries' => [], }
        ],
        [   "Test IPv4 bits 1", 4,
            "0000000001800000",
            { 'sequence' => 0, bits => 1, prefix => '8000::', 'entries' => [], }
        ],
        [   "Test IPv4 bits 7", 4,
            "0000000007E00000",
            { 'sequence' => 0, bits => 7, prefix => 'e000::', 'entries' => [], }
        ],
        [   "Test IPv4 bits 8", 4,
            "0000000008200000",
            { 'sequence' => 0, bits => 8, prefix => '2000::', 'entries' => [], }
        ],
        [   "Test IPv4 bits 9", 4,
            "000000000920800000",
            { 'sequence' => 0, bits => 9, prefix => '2080::', 'entries' => [], }
        ],
        [   "Test IPv4 bits 23", 4,
            "00000000172001DE0000",
            { 'sequence' => 0, bits => 23, prefix => '2001:de00::', 'entries' => [], }
        ],
        [   "Test IPv4 bits 128", 4,
            "000000008020010DB8DEADBEEF0123456789ABCDEF0000",
            { 'sequence' => 0, bits => 128, prefix => '2001:db8:dead:beef:123:4567:89ab:cdef', 'entries' => [], }
        ],
        ## Entries testing ##
        [   "Test one entry (w/o BGP attributes)", 2,
            "00000000087F00018FFF823456780000",
            { 'sequence' => 0, bits => 8, prefix => '127.0.0.0', 'entries' => [
                    { 'peer_index' => 0x8FFF, 'originated_time' => 0x82345678, },
                ], }
        ],
        [   "Test two entries (w/o BGP attributes)", 2,
            "00000000087F00028FFF823456780000FF00FF1234780000",
            { 'sequence' => 0, bits => 8, prefix => '127.0.0.0', 'entries' => [
                    { 'peer_index' => 0x8FFF, 'originated_time' => 0x82345678, },
                    { 'peer_index' => 0xFF00, 'originated_time' => 0xFF123478, },
                ], }
        ],
        ## Test BGP attributes ##
        # Test attribute short len & ORIGIN
        [   "Test BGP short len & attribute ORIGIN", 2,
            "00000000087F00018FFF82345678000400010101",
            { 'sequence' => 0, bits => 8, prefix => '127.0.0.0', 'entries' => [
                    { 'peer_index' => 0x8FFF, 'originated_time' => 0x82345678, 'ORIGIN' => 1 },
                ], }
        ],
        # Test attribute extended len & ORIGIN
        [   "Test BGP extended len & attribute ORIGIN", 2,
            "00000000087F00018FFF8234567800051001000101",
            { 'sequence' => 0, bits => 8, prefix => '127.0.0.0', 'entries' => [
                    { 'peer_index' => 0x8FFF, 'originated_time' => 0x82345678, 'ORIGIN' => 1 },
                ], }
        ],
        # Test attribute AS_PATH (AS_SET)
        [   "Test attribute AS_PATH (AS_SET)", 2,
            "00000000087F00018FFF82345678000D00020A01020000123480123456",
            { 'sequence' => 0, bits => 8, prefix => '127.0.0.0', 'entries' => [
                    { 'peer_index' => 0x8FFF, 'originated_time' => 0x82345678, 'AS_PATH' => [[0x1234, 0x80123456]] },
                ], }
        ],
        # Test attribute AS_PATH (AS_SEQUENCE)
        [   "Test attribute AS_PATH (AS_SEQUENCE)", 2,
            "00000000087F00018FFF82345678000D00020A02020000123480123456",
            { 'sequence' => 0, bits => 8, prefix => '127.0.0.0', 'entries' => [
                    { 'peer_index' => 0x8FFF, 'originated_time' => 0x82345678, 'AS_PATH' => [0x1234, 0x80123456] },
                ], }
        ],
        # Test attribute AS_PATH SEQ SET SEQ SET
        [   "Test attribute AS_PATH (SEQ SET SEQ SET)", 2,
            "00000000087F00018FFF82345678003F00023C02040000000B0000000A00000009000000080104000000070000004D0000030900001E61020300000005000000040000000301020000000100000002",
            { 'sequence' => 0, bits => 8, prefix => '127.0.0.0', 'entries' => [
                    { 'peer_index' => 0x8FFF, 'originated_time' => 0x82345678,
                        'AS_PATH' => [11, 10, 9, 8, [7, 77, 777, 7777], 5, 4, 3, [1, 2]] },
                ], }
        ],
        # Test attribute NEXT_HOP
        [   "Test attribute NEXT_HOP", 2,
            "00000000087F00018FFF82345678000700030401020304",
            { 'sequence' => 0, bits => 8, prefix => '127.0.0.0', 'entries' => [
                    { 'peer_index' => 0x8FFF, 'originated_time' => 0x82345678, 'NEXT_HOP' => '1.2.3.4' },
                ], }
        ],
        # Test attribute MULTI_EXIT_DISC
        [   "Test attribute MULTI_EXIT_DISC", 2,
            "00000000087F00018FFF82345678000700040486918275",
            { 'sequence' => 0, bits => 8, prefix => '127.0.0.0', 'entries' => [
                    { 'peer_index' => 0x8FFF, 'originated_time' => 0x82345678, 'MULTI_EXIT_DISC' => 0x86918275 },
                ], }
        ],
        # Test attribute LOCAL_PREF
        [   "Test attribute LOCAL_PREF", 2,
            "00000000087F00018FFF82345678000700050485F7D302",
            { 'sequence' => 0, bits => 8, prefix => '127.0.0.0', 'entries' => [
                    { 'peer_index' => 0x8FFF, 'originated_time' => 0x82345678, 'LOCAL_PREF' => 0x85F7D302 },
                ], }
        ],
    );

plan tests => scalar(@tests);

foreach (@tests)
{
    cmp_deeply(Net::MRT::mrt_decode_single(13, @{$_}[1], pack 'H*', @{$_}[2]), @{$_}[3], @{$_}[0]);
}

done_testing();
