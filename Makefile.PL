#
# $Id: Makefile.PL,v 1.2 2006/12/03 12:11:24 gomor Exp $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::Frame::Device',
   VERSION_FROM  => 'lib/Net/Frame/Device.pm',
   LICENSE       => 'Artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Device.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   PREREQ_PM     => {
      Class::Gomor     => '1.00',
      Net::Libdnet     => 0,
      Net::IPv4Addr    => 0,
      Net::IPv6Addr    => 0,
      Net::Pcap        => '0.12',
      Net::Write       => '1.00',
      Net::Frame       => 0,
      Net::Frame::Dump => 0,
   },
);
