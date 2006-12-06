#
# $Id: Device.pm,v 1.5 2006/12/06 21:12:41 gomor Exp $
#
package Net::Frame::Device;
use strict;
use warnings;

our $VERSION = '1.00_02';

require Class::Gomor::Array;
our @ISA = qw(Class::Gomor::Array);

our @AS = qw(
   dev
   ip
   ip6
   mac
   subnet
   gatewayIp
   gatewayMac
   target
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

use Carp qw(croak);
require Net::Libdnet;
require Net::IPv4Addr;
require Net::IPv6Addr;
require Net::Pcap;
require Net::Write::Layer2;
require Net::Frame::Dump;
use Net::Frame::ETH qw(:consts);
require Net::Frame::ARP;

sub new {
   my $self = shift->SUPER::new(@_);

   $self->[$__dev]    && return $self->updateFromDev;
   $self->[$__target] && return $self->updateFromTarget;

   $self->updateFromDefault;
}

sub _update {
   my $self = shift;
   $self->[$__dev]    = $self->_getDev;
   $self->[$__mac]    = $self->_getMac;
   $self->[$__ip]     = $self->_getIp;
   $self->[$__ip6]    = $self->_getIp6;
   $self->[$__subnet] = $self->_getSubnet;
   $self->[$__gatewayIp]  = $self->_getGatewayIp;
   $self->[$__gatewayMac] = $self->_getGatewayMac;
   $self;
}

# By default, we take outgoing device to Internet
sub updateFromDefault {
   my $self = shift;
   $self->[$___dnet] = Net::Libdnet::intf_get_dst('1.1.1.1');
   $self->_update;
}

sub updateFromDev {
   my $self = shift;
   my ($dev) = @_;
   $self->[$__dev]   = $dev if $dev;
   $self->[$___dnet] = Net::Libdnet::intf_get($self->[$__dev]);
   $self->_update;
}

sub updateFromTarget {
   my $self = shift;
   my ($target) = @_;
   $self->[$__target] = $target if $target;
   $self->[$___dnet]  = Net::Libdnet::intf_get_dst($self->[$__target]);
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
   my $subnet = Net::Libdnet::addr_net($self->[$___dnet]->{addr});
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

sub _getDevOther {
   shift->[$___dnet]->{name} || (($^O eq 'linux') ? 'lo' : 'lo0');
}

sub _getGatewayIp {
   my $self = shift;
   Net::Libdnet::route_get($self->[$__target] || '1.1.1.1') || undef;
}

sub _getMacFromCache { shift; Net::Libdnet::arp_get(shift()) }

sub _getGatewayMac {
    my $self = shift;
    $self->[$__gatewayIp] && $self->_getMacFromCache($self->[$__gatewayIp])
       || undef;
}

sub _getSubnet {
   my $addr = shift->[$___dnet]->{addr};
   return '127.0.0.0/8' unless $addr;

   my $subnet = Net::Libdnet::addr_net($addr);
   (my $mask = $addr) =~ s/^.*(\/\d+)$/$1/;
   $subnet.$mask;
}

sub _getMac { shift->[$___dnet]->{link_addr} || 'ff:ff:ff:ff:ff:ff' }

sub _getIp {
   my $ip = shift->[$___dnet]->{addr} || '127.0.0.1';
   $ip =~ s/\/\d+$//;
   $ip;
}

sub _getIp6 {
   my $self = shift;

   # XXX: No IP6 under Windows for now
   return '::1' if $^O =~ m/MSWin32|cygwin/i;

   my $dev = $self->[$__dev];
   my $mac = $self->[$__mac];
   my $buf = `/sbin/ifconfig $dev 2> /dev/null`;
   $buf =~ s/$dev//;
   $buf =~ s/$mac//i;
   my ($ip6) = ($buf =~ /((?:[a-f0-9]{1,4}(?::|%|\/){1,2})+)/i); # XXX: better
   if ($ip6) {
      $ip6 =~ s/%|\///g;
      $ip6 = lc($ip6);
   }
   ($ip6 && Net::IPv6Addr::ipv6_chkip($ip6) && $ip6) || '::1';
}

sub _lookupMac {
   my $self = shift;
   my ($ip) = @_;

   my $eth = Net::Frame::ETH->new(
      src  => $self->[$__mac],
      dst  => NP_ETH_ADDR_BROADCAST,
      type => NP_ETH_TYPE_ARP,
   );
   my $arp = Net::Frame::ARP->new(
      src   => $self->[$__mac],
      srcIp => $self->[$__ip],
      dstIp => $ip,
   );
   $eth->pack;
   $arp->pack;

   my $oWrite = Net::Write::Layer2->new(dev => $self->[$__dev]);
   my $oDump  = Net::Frame::Dump->new(dev => $self->[$__dev], filter => 'arp');

   $oDump->start;
   $oWrite->open;

   # We retry three times
   my $mac;
   for (1..3) {
      $oWrite->send($eth->raw.$arp->raw);
      until ($oDump->timeout) {
         if (my $h = $oDump->next) {
            if ($h->{firstLayer} eq 'ETH') {
               my $raw  = substr($h->{raw}, $eth->getLength);
               my $rArp = Net::Frame::ARP->new(raw => $raw);
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
   $oDump->clean;

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
}

sub debugDeviceList {
   use Data::Dumper;

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
      my $dnet = Net::Libdnet::intf_get($eth);
      last unless keys %$dnet > 0;
      $dnet->{subnet} = Net::Libdnet::addr_net($dnet->{addr})
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
   print "gatewayIp:  ", $device->gatewayIp,  "\n";
   print "gatewayMac: ", $device->gatewayMac, "\n" if $device->gatewayMac;

=head1 DESCRIPTION

Basically, this module is used to tell where to inject a frame. XXX: todo

=head1 ATTRIBUTES

=over 4

=item B<dev>

The network device.

=item B<ip>

The IPv4 address of B<dev>.

=item B<ip6>

The IPv6 address of B<dev>. If none found, it defaults to '::1'.

=item B<mac>

The MAC address of B<dev>. If none found, it defaults to 'ff:ff:ff:ff:ff:ff'.

=item B<subnet>

The subnet of IPv4 address B<ip>.

=item B<gatewayIp>

The gateway IPv4 address. It defaults to default gateway that let you access Internet.

=item B<gatewayMac>

The MAC address B<gatewayIp>. The MAC is looked up from cache. If no entry is found, attribute will be undef.

=item B<target>

This attribute is used when you want to detect which B<dev>, B<ip>, B<mac> attributes to use for a specific target. See B<SYNOPSIS>.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. Default values:

dev:             if not user provided, default interface is used, by calling B<getDevInfo> method. If user provided, all B<ip>, B<ip6> and B<mac> attributes will be used for that B<dev>.

ip:              if not user provided, default interface IP is used, by calling B<getIp> method. If user provided, it is overwritten by the user.

ip6:             if not user provided, default interface IPv6 is used, by calling B<getIp6> method. If user provided, it is overwritten by the user.

mac:             if not user provided, default interface MAC is used, by calling B<getMac> method. If user provided, it is overwritten by the user.

=item B<updateFromDefault>

=item B<updateFromDev>

=item B<updateFromTarget>

=item B<lookupMac>

=item B<debugDeviceList>

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE
   
Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret
   
You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
