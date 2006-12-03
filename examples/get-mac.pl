#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::Device;

my $oDevice = Net::Frame::Device->new(target => $ARGV[0]);
print $oDevice->cgDumper."\n";

my $mac = $oDevice->lookupMac($ARGV[0]);
print "MAC: $mac\n" if $mac;
