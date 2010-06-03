#
# $Id: Device.pm 317 2010-06-03 13:44:14Z gomor $
#
package Net::Frame::Device;
use strict;
use warnings;

our $VERSION = '1.04';

require Class::Gomor::Array;
our @ISA = qw(Class::Gomor::Array);

our @AS = qw(
   dev
   mac
   ip
   ip6
   subnet
   subnet6
   gatewayIp
   gatewayIp6
   gatewayMac
   gatewayMac6
   target
   target6
   _dnet
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

BEGIN {
   my $osname = {
      cygwin  => [ \&_getDevWin32, ],
      MSWin32 => [ \&_getDevWin32, ],
   };

   *_getDev = $osname->{$^O}->[0] || \&_getDevOther;
}

no strict 'vars';

use Carp qw(croak carp);
use Data::Dumper;
use Net::Libdnet6;
require Net::IPv4Addr;
require Net::IPv6Addr;
require Net::Pcap;
require Net::Write::Layer2;
use Net::Frame::Dump qw(:consts);
use Net::Frame::Dump::Online;
use Net::Frame::Layer qw(:subs);
use Net::Frame::Layer::ETH qw(:consts);
use Net::Frame::Layer::ARP qw(:consts);
use Net::Frame::Layer::IPv6 qw(:consts);
use Net::Frame::Layer::ICMPv6 qw(:consts);
use Net::Frame::Simple;

sub new {
   my $self = shift->SUPER::new(@_);

   $self->[$__target]  && return $self->updateFromTarget;
   $self->[$__target6] && return $self->updateFromTarget6;
   $self->[$__dev]     && return $self->updateFromDev;

   $self->updateFromDefault or return;
   $self;
}

sub _update {
   my $self = shift;
   my ($dnet6) = @_;

   $self->[$__dev]        = $self->_getDev;
   $self->[$__mac]        = $self->_getMac;
   $self->[$__ip]         = $self->_getIp;
   $self->[$__subnet]     = $self->_getSubnet;
   $self->[$__gatewayIp]  = $self->_getGatewayIp;
   $self->[$__gatewayMac] = $self->_getGatewayMac;

   if ($dnet6) {
      $self->[$___dnet] = $dnet6;
   }

   $self->[$__ip6]        = $self->_getIp6;
   $self->[$__subnet6]    = $self->_getSubnet6;
   $self->[$__gatewayIp6] = $self->_getGatewayIp6;

   $self->[$___dnet] = undef;
   $self;
}

# By default, we take outgoing device to Internet
sub updateFromDefault {
   my $self = shift;
   $self->[$___dnet] = intf_get_dst('1.1.1.1')
      or die("Net::Frame::Device: updateFromDefault: unable to get dnet\n");

   my $dnet6 = intf_get6($self->[$___dnet]->{name});
   $self->_update($dnet6);
}

sub updateFromDev {
   my $self = shift;
   my ($dev) = @_;
   $self->[$__dev]   = $dev if $dev;
   $self->[$___dnet] = intf_get6($self->[$__dev])
      or die("Net::Frame::Device: updateFromDev: unable to get dnet\n");
   $self->_update;
}

sub updateFromTarget {
   my $self = shift;
   my ($target) = @_;
   $self->[$__target] = $target if $target;
   $self->[$___dnet]  = intf_get_dst($self->[$__target])
      or die("Net::Frame::Device: updateFromTarget: unable to get dnet\n");

   my $dnet6 = intf_get6($self->[$___dnet]->{name});
   $self->_update($dnet6);
}

sub updateFromTarget6 {
   my $self = shift;
   my ($target6) = @_;
   $self->[$__target6] = $target6 if $target6;
   my @dnetList = intf_get_dst6($self->[$__target6]);
   if (@dnetList > 1) {
      if (! $self->[$__dev]) {
         croak("Multiple possible network interface for target6, ".
               "choose `dev' manually\n");
      }
      $self->[$___dnet] = intf_get6($self->[$__dev])
         or die("Net::Frame::Device: updateFromTarget6: unable to get dnet\n");
   }
   elsif (@dnetList == 1) {
      $self->[$___dnet] = $dnetList[0];
   }
   else {
      die("Net::Frame::Device: updateFromTarget6: unable to get dnet\n");
   }
   $self->_update;
}

# Thanx to Maddingue
sub _toDotQuad {
   my ($i) = @_;
   ($i >> 24 & 255).'.'.($i >> 16 & 255).'.'.($i >> 8 & 255).'.'.($i & 255);
}

sub _getDevWin32 {
   my $self = shift;

   croak("@{[(caller(0))[3]]}: unable to find a suitable device\n")
      unless $self->[$___dnet]->{name};

   # Get dnet interface name and its subnet
   my $dnet   = $self->[$___dnet]->{name};
   my $subnet = addr_net($self->[$___dnet]->{addr});
   croak("@{[(caller(0))[3]]}: Net::Libdnet::addr_net() error\n")
      unless $subnet;

   my %dev;
   my $err;
   Net::Pcap::findalldevs(\%dev, \$err);
   croak("@{[(caller(0))[3]]}: Net::Pcap::findalldevs() error: $err\n")
      if $err;

   # Search for corresponding WinPcap interface, via subnet value.
   # I can't use IP address or MAC address, they are not available
   # through Net::Pcap (as of version 0.15_01).
   for my $d (keys %dev) {
      my $net;
      my $mask;
      if (Net::Pcap::lookupnet($d, \$net, \$mask, \$err) < 0) {
         croak("@{[(caller(0))[3]]}: Net::Pcap::lookupnet(): $d: $err\n")
      }
      $net = _toDotQuad($net);
      if ($net eq $subnet) {
         return $d;
      }
   }
   undef;
}

sub _getDevOther { shift->[$___dnet]->{name} || undef }

sub _getGatewayIp  { route_get (shift()->[$__target]  || '1.1.1.1') || undef }
sub _getGatewayIp6 { route_get6(shift()->[$__target6] || '2001::1') || undef }

sub _getMacFromCache { shift; arp_get(shift()) }

sub _getGatewayMac {
    my $self = shift;
    $self->[$__gatewayIp] && $self->_getMacFromCache($self->[$__gatewayIp])
       || undef;
}

sub _getSubnet {
   my $addr = shift->[$___dnet]->{addr};
   return unless $addr;
   my $subnet = addr_net($addr) or return;
   (my $mask = $addr) =~ s/^.*(\/\d+)$/$1/;
   $subnet.$mask;
}

sub _getSubnet6 {
   my $addr = shift->[$___dnet]->{addr6};
   return unless $addr;
   my $subnet = addr_net6($addr) or return;
   (my $mask = $addr) =~ s/^.*(\/\d+)$/$1/;
   $subnet.$mask;
}

sub _getMac { shift->[$___dnet]->{link_addr} || undef }

sub _getIp {
   my $ip = shift->[$___dnet]->{addr} || return undef;
   $ip =~ s/\/\d+$//;
   $ip;
}

sub _getIp6 {
   my $ip = shift->[$___dnet]->{addr6} || return undef;
   $ip =~ s/\/\d+$//;
   $ip;
}

sub _lookupMac {
   my $self = shift;
   my ($ip) = @_;

   my $oWrite = Net::Write::Layer2->new(dev => $self->[$__dev]);
   my $oDump  = Net::Frame::Dump::Online->new(
      dev    => $self->[$__dev],
      filter => 'arp',
   );

   $oDump->start;
   if ($oDump->firstLayer ne 'ETH') {
      $oDump->stop;
      croak("lookupMac: can't do that on non-ethernet link layers\n");
   }

   $oWrite->open;

   my $eth = Net::Frame::Layer::ETH->new(
      src  => $self->[$__mac],
      dst  => NF_ETH_ADDR_BROADCAST,
      type => NF_ETH_TYPE_ARP,
   );
   my $arp = Net::Frame::Layer::ARP->new(
      src   => $self->[$__mac],
      srcIp => $self->[$__ip],
      dstIp => $ip,
   );
   $eth->pack;
   $arp->pack;

   # We retry three times
   my $mac;
   for (1..3) {
      $oWrite->send($eth->raw.$arp->raw);
      until ($oDump->timeout) {
         if (my $h = $oDump->next) {
            if ($h->{firstLayer} eq 'ETH') {
               my $raw  = substr($h->{raw}, $eth->getLength);
               my $rArp = Net::Frame::Layer::ARP->new(raw => $raw);
               $rArp->unpack;
               next unless $rArp->srcIp eq $ip;
               $mac = $rArp->src;
               last;
            }
         }
      }
      last if $mac;
      $oDump->timeoutReset;
   }

   $oWrite->close;
   $oDump->stop;

   $mac;
}

sub lookupMac {
   my $self = shift;
   my ($ip) = @_;

   # First, lookup the ARP cache table
   my $mac = $self->_getMacFromCache($ip);
   return $mac if $mac;

   # Then, is the target on same subnet, or not ?
   if (Net::IPv4Addr::ipv4_in_network($self->[$__subnet], $ip)) {
      return $self->_lookupMac($ip);
   }
   # Get gateway MAC
   else {
      # If already retrieved
      return $self->[$__gatewayMac] if $self->[$__gatewayMac];

      # Else, lookup it, and store it
      my $gatewayMac = $self->_lookupMac($self->[$__gatewayIp]);
      $self->[$__gatewayMac] = $gatewayMac;
      return $gatewayMac;
   }
   undef;
}

sub _lookupMac6 {
   my $self = shift;
   my ($ip6, $srcIp6) = @_;

   my $oWrite = Net::Write::Layer2->new(dev => $self->[$__dev]);
   my $oDump  = Net::Frame::Dump::Online->new(
      dev    => $self->[$__dev],
      filter => 'icmp6',
   );

   $oDump->start;
   if ($oDump->firstLayer ne 'ETH') {
      $oDump->stop;
      croak("lookupMac: can't do that on non-ethernet link layers\n");
   }

   $oWrite->open;

   my $srcMac = $self->[$__mac];

   # XXX: risky
   my $target6 = Net::IPv6Addr->new($ip6)->to_string_preferred;
   my @dst = split(':', $target6);
   my $str = $dst[-2];
   $str =~ s/^.*(..)$/$1/;
   $target6 = 'ff02::1:ff'.$str.':'.$dst[-1];

   my $eth = Net::Frame::Layer::ETH->new(
      src  => $srcMac,
      dst  => NF_ETH_ADDR_BROADCAST,
      type => NF_ETH_TYPE_IPv6,
   );
   my $ip = Net::Frame::Layer::IPv6->new(
      src        => $srcIp6,
      dst        => $target6,
      nextHeader => NF_IPv6_PROTOCOL_ICMPv6,
   );
   my $icmp = Net::Frame::Layer::ICMPv6->new(
      type     => NF_ICMPv6_TYPE_NEIGHBORSOLICITATION,
      icmpType => Net::Frame::Layer::ICMPv6::NeighborSolicitation->new(
         targetAddress => $ip6,
      ),
      options => [
         Net::Frame::Layer::ICMPv6::Option->new(
            type   => NF_ICMPv6_OPTION_SOURCELINKLAYERADDRESS,
            length => 1,
            value  => pack('H2H2H2H2H2H2', split(':', $srcMac)),
         ),
      ],
   );

   my $oSimple = Net::Frame::Simple->new(
      layers => [ $eth, $ip, $icmp, ],
   );

   # We retry three times
   my $mac;
FIRST:
   for (1..3) {
      $oWrite->send($oSimple->raw);
      until ($oDump->timeout) {
         if (my $oReply = $oSimple->recv($oDump)) {
            for ($oReply->ref->{ICMPv6}->options) {
               if ($_->type eq NF_ICMPv6_OPTION_TARGETLINKLAYERADDRESS) {
                  $mac = convertMac(unpack('H*', $_->value));
                  last FIRST;
               }
            }
         }
      }
      $oDump->timeoutReset;
   }

   $oWrite->close;
   $oDump->stop;

   $mac;
}

sub _searchSrcIp6 {
   my $self = shift;
   my ($ip6) = @_;
   my @dnet6 = intf_get_dst6($ip6) or return undef;
   my $dev = $self->[$__dev];
   my $dnet6;
   for (@dnet6) {
      if ($_->{name} eq $dev) {
         $dnet6 = $_;
         last;
      }
   }
   my ($srcIp6) = split('/', $dnet6->{addr6});
   $srcIp6;
}

sub lookupMac6 {
   my $self = shift;
   my ($ip6) = @_;

   # XXX: No ARP6 cache support for now

   # If gatewayIp6 is not set, the target is on the same subnet, 
   # we lookup its MAC address
   if (! $self->[$__gatewayIp6]) {
      # We must change source IPv6 address to the one of same subnet
      my $srcIp6 = $self->_searchSrcIp6($ip6);
      return $self->_lookupMac6($ip6, $srcIp6);
   }
   # Otherwise, we lookup the gateway MAC address, and store it
   else {
      # If already retrieved
      return $self->[$__gatewayMac6] if $self->[$__gatewayMac6];

      # Else, lookup it, and store it
      # We must change source IPv6 address to the one of same subnet
      my $srcIp6 = $self->_searchSrcIp6($self->[$__gatewayIp6]);
      my $gatewayMac6 = $self->_lookupMac6($self->[$__gatewayIp6], $srcIp6);
      $self->[$__gatewayMac6] = $gatewayMac6;
      return $gatewayMac6;
   }
   undef;
}

sub debugDeviceList {
   my %dev;
   my $err;
   Net::Pcap::findalldevs(\%dev, \$err);
   print STDERR "findalldevs: error: $err\n" if $err;

   # Net::Pcap stuff
   for my $d (keys %dev) {
      my ($net, $mask);
      if (Net::Pcap::lookupnet($d, \$net, \$mask, \$err) < 0) {
         print STDERR "lookupnet: error: $d: $err\n";
         $err = undef; next;
      }
      print STDERR "[$d] => subnet: "._toDotQuad($net)."\n";
   }

   # Net::Libdnet stuff
   for my $i (0..5) {
      my $eth = 'eth'.$i;
      my $dnet = intf_get($eth);
      last unless keys %$dnet > 0;
      $dnet->{subnet} = addr_net($dnet->{addr})
         if $dnet->{addr};
      print STDERR Dumper($dnet)."\n";
   }
}

1;

__END__

=head1 NAME

Net::Frame::Device - get network device information and gateway

=head1 SYNOPSIS

   use Net::Frame::Device;

   # Get default values from system
   my $device = Net::Frame::Device->new;

   # Get values from a specific device
   my $device2 = Net::Frame::Device->new(dev => 'vmnet1');

   # Get values from a specific target
   my $device3 = Net::Frame::Device->new(target => '192.168.10.2');

   print "dev: ", $device->dev, "\n";
   print "mac: ", $device->mac, "\n";
   print "ip : ", $device->ip,  "\n";
   print "ip6: ", $device->ip6, "\n";
   print "gatewayIp:  ", $device->gatewayIp,  "\n" if $device->gatewayIp;
   print "gatewayMac: ", $device->gatewayMac, "\n" if $device->gatewayMac;

   # Get values from a specific target
   my $device5 = Net::Frame::Device->new(target6 => '2001::1');

   print "dev: ", $device5->dev, "\n";
   print "mac: ", $device5->mac, "\n";
   print "ip6: ", $device5->ip6, "\n";
   print "gatewayIp6:  ", $device5->gatewayIp6, "\n" if $device5->gatewayIp6;

=head1 DESCRIPTION

This module is used to get network information, and is especially useful when you want to do low-level network programming.

It also provides useful functions to lookup network MAC addresses.

=head1 ATTRIBUTES

=over 4

=item B<dev>

The network device. undef if none found.

=item B<ip>

The IPv4 address of B<dev>. undef if none found.

=item B<ip6>

The IPv6 address of B<dev>. undef if none found.

=item B<mac>

The MAC address of B<dev>. undef if none found.

=item B<subnet>

The subnet of IPv4 address B<ip>. undef if none found.

=item B<subnet6>

The subnet of IPv6 address B<ip6>. undef if none found.

=item B<gatewayIp>

The gateway IPv4 address. It defaults to default gateway that let you access Internet. If none found, or not required in the usage context, it defaults to undef.

=item B<gatewayIp6>

The gateway IPv6 address. It defaults to default gateway that let you access Internet. If none found, or not required in the usage context, it defaults to undef.

=item B<gatewayMac>

The MAC address B<gatewayIp>. See B<lookupMac> method.

=item B<gatewayMac6>

The MAC address B<gatewayIp6>. See B<lookupMac6> method.

=item B<target>

This attribute is used when you want to detect which B<dev>, B<ip>, B<mac> attributes to use for a specific target. See B<SYNOPSIS>.

=item B<target6>

This attribute is used when you want to detect which B<dev>, B<ip6>, B<mac> attributes to use for a specific target. See B<SYNOPSIS>.

=back

=head1 METHODS

=over 4

=item B<new>

=item B<new> (hash)

Object constructor. See B<SYNOPSIS> for default values.

=item B<updateFromDefault>

Will update attributes according to the default interface that has access to Internet.

=item B<updateFromDev>

=item B<updateFromDev> (dev)

Will update attributes according to B<dev> attribute, or if you specify 'dev' as a parameter, it will use it for updating (and will also set B<dev> to this new value).

=item B<updateFromTarget>

=item B<updateFromTarget> (target)

Will update attributes according to B<target> attribute, or if you specify 'target' as a parameter, it will use it for updating (and will also set B<target> to this new value).

=item B<updateFromTarget6>

=item B<updateFromTarget6> (target6)

Will update attributes according to B<target6> attribute, or if you specify 'target6' as a parameter, it will use it for updating (and will also set B<target6> to this new value).

=item B<lookupMac> (IPv4 address)

Will try to get the MAC address of the specified IPv4 address. First, it checks against ARP cache table. Then, verify the target is on the same subnet as we are, and if yes, it does the ARP request. If not on the same subnet, it tries to resolve the gateway MAC address (by using B<gatewayIp> attribute). Returns undef on failure.

=item B<lookupMac6> (IPv6 address)

Will try to get the MAC address of the specified IPv6 address (using ICMPv6). First, verify the target is on the same subnet as we are, and if yes, it does the ICMPv6 lookup request. If not on the same subnet, it tries to resolve the gateway MAC address (by using B<gatewayIp6> attribute). Returns undef on failure.

=item B<debugDeviceList>

Just for debugging purposes, especially on Windows systems.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE
   
Copyright (c) 2006-2010, Patrice E<lt>GomoRE<gt> Auffret
   
You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
