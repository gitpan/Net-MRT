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
    );

plan tests => scalar(@tests);

foreach (@tests)
{
    cmp_deeply(Net::MRT::mrt_decode_single(13, @{$_}[1], pack 'H*', @{$_}[2]), @{$_}[3], @{$_}[0]);
}

done_testing();
