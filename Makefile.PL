#
# $Id: Makefile.PL 317 2010-06-03 13:44:14Z gomor $
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
      Class::Gomor     => '1.00',
      Net::Libdnet6    => 0,
      Net::IPv4Addr    => 0,
      Net::IPv6Addr    => 0,
      Net::Pcap        => '0.12',
      Net::Write       => '1.00',
      Net::Frame       => 0,
      Net::Frame::Dump => 0,
      Net::Frame::Layer::IPv6   => 0,
      Net::Frame::Layer::ICMPv6 => 0,
      Net::Frame::Simple        => 0,
   },
);
