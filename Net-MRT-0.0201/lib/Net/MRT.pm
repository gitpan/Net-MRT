# Copyright (C) 2013 MaxiM Basunov <maxim.basunov@gmail.com>
# All rights reserved.
#
# This program is free software; you may redistribute it and/or
# modify it under the same terms as Perl itself.

# $Id$

package Net::MRT;

use 5.010001;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Net::MRT ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(

) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(

);

our $VERSION = '0.0201';

require XSLoader;
XSLoader::load('Net::MRT', $VERSION);

# Preloaded methods go here.

1;
__END__

=head1 NAME

Net::MRT - Perl extension for fast decode of MRT RAW data

=head1 SYNOPSIS

    Decode uncompressed MRT file:
    use Net::MRT;
    open(C, '<', 'file');
    binmode(C);
    while ($decode = Net::MRT::mrt_read_next(C))
    {
        do_something_useful($decode);
    }

    In-memory download/decode:
    use LWP::Simple;
    use PerlIO::gzip;
    use Net::MRT;
    $LWP::Simple::ua->show_progress(1);
    $archive = get($url);
    open $mrt, "<:gzip", \$archive or die $!;
    while ($dd = Net::MRT::mrt_read_next($mrt)) { do_something_useful($decode); }
    # Note: In case of errors, reported message offset will be relative to Perl internal buffer

    Decode some message of known type/subtype:
    $hash = Net::MRT::mrt_decode_single($type, $subtype, $buffer);

=head1 DESCRIPTION

L<Net::MRT::mrt_read_next> Decodes next message from filehandle

B<NOTE> Always set binary mode before call to mrt_read_next or got unexpected results.

L<Net::MRT::mrt_decode_single> Decodes message of specified type & subtype. See t/* for a lot of examples

TODO TODO

=head2 EXPORT

None by default.

=head1 Methods

=head2 Net::MRT::mrt_read_next

TODO TODO

=head2 Net::MRT::mrt_decode_single

TODO TODO

=head1 SEE ALSO

L<http://tools.ietf.org/html/draft-ietf-grow-mrt-13>

L<http://www.ripe.net/data-tools/stats/ris/ris-raw-data>

L<http://www.quagga.net>

=head1 AUTHOR

MaxiM Basunov,  E<lt>maxim.basunov@gmail.comE<gt>

=head1 MODIFICATION HISTORY

See the Changes file.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 MaxiM Basunov <maxim.basunov@gmail.com>
All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

=cut
