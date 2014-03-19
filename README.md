Ipsumdump
=========

   `ipsumdump` reads IP packets from the network (using libpcap, or
packet sockets on Linux), or from a tcpdump(1) save file, and writes
an ASCII summary of the packet data to the standard output. Comments
on the first couple lines describe the summary’s contents; for
example:

    !IPSummaryDump 1.3
    !creator "ipsumdump -i wvlan0"
    !host no.lcdf.org
    !runtime 996022410.322317 (Tue Jul 24 17:53:30 2001)
    !data ip_src ip_dst
    63.250.213.167 192.150.187.106
    63.250.213.167 192.150.187.106
    // ...

   Two other programs are included. `ipaggcreate` processes traces and
counts various properties of packet aggregates, making it easy to
answer questions such as “What is the distribution of packets per
TCP/UDP flow in this trace?” or “How long does it take to encounter
10000 different IP addresses in this trace?” `ipaggmanip` takes
aggregate files produced by `ipaggcreate` and manipulates them in
various ways.

   If you are building from a source repository (git), you will need
to generate configure scripts. (This is not necessary if you
downloaded a tarball.) Run `./bootstrap.sh` from the top directory.

   Thereafter installation is standard. Run `./configure`, supplying
any options, then `make install`. Documentation is supplied in manual
page format; after `make install`, try `man ipsumdump`. (Before
installation, try `pod2man ipsumdump.pod | nroff -man | less`.) Run
`ipsumdump --help` to see what options are available.


About Click
-----------

   `ipsumdump` is built from the Click modular router, an extensible
system for processing packets. Click routers consist of C++ components
called elements. While some elements run only in a Linux kernel, most can
run either in the kernel or in user space, and there are user-level
elements for reading packets from libpcap or from tcpdump files.

   The `ipsumdump` program just builds up a simple Click configuration and
runs it, as if by the `click` user-level driver. However, you don't need to
install Click to run ipsumdump; the `libclick` directory contains all the
relevant parts of Click, bundled into a library.

   If you’re curious, try running `ipsumdump --config` with some other
options to see the Click configuration ipsumdump would run. Only three
source files had to be written from scratch: src/ipsumdump.cc,
src/toipsumdump.cc, and src/toipsumdump.hh. The rest came from Click
itself.

   This is, I think, a pleasant way to write a packet processor!

   The Click source distribution: https://github.com/kohler/click/


Authors
-------

Eddie Kohler
Harvard University
(UCLA and ICIR/International Computer Science Institute)
kohler@seas.harvard.edu

Copyright (c) 2001-2003 International Computer Science Institute
Copyright (c) 2004-2011 Regents of the University of California
Copyright (c) 2008 Meraki, Inc.
Copyright (c) 2001-2014 Eddie Kohler

   The anonymization algorithm was borrowed from tcpdpriv by Greg Minshall.

   Thanks to Vern Paxson and Lee Breslau for comments and suggestions.


License
-------

   `ipsumdump` is available under the Click license, a BSD-like license. See
the file `libclick*/LICENSE` for full license terms.
