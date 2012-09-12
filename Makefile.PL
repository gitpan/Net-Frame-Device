#
# $Id: Makefile.PL 351 2012-09-12 11:37:58Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Device',
   VERSION_FROM  => 'lib/Net/Frame/Device.pm',
   LICENSE       => 'artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Device.pm',
   AUTHOR        => 'GomoR <gomor-cpan_at_gomor.org>',
   PREREQ_PM     => {
      Class::Gomor              => '1.00',
      Net::Libdnet              => 0,
      Net::Libdnet6             => 0,
      Net::IPv4Addr             => 0,
      Net::IPv6Addr             => 0,
      Net::Pcap                 => '0.12',
      Net::Write                => '1.00',
      Net::Frame                => 0,
      Net::Frame::Dump          => '1.08',  # For Dump::Online2
      Net::Frame::Layer::IPv6   => 0,
      Net::Frame::Layer::ICMPv6 => 0,
      Net::Frame::Simple        => '1.05',  # Cause of a bug in ICMPv6 unpacking
   },
);
