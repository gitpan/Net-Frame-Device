#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::Device;

my $d = Net::Frame::Device->new(dev => 'lo');
print $d->cgDumper."\n";
