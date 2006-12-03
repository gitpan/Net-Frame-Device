use Test;
BEGIN { plan(tests => 1) }

use Net::Frame::Device;
my $d = Net::Frame::Device->new;
print $d->cgDumper if $d->can('cgDumper');

ok(1);
