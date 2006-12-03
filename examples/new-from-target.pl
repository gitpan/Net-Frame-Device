#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::Device;

my $d = Net::Frame::Device->new(target => '2.2.2.2');
print $d->cgDumper."\n";
