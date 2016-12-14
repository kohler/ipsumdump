Ipsumdump NEWS
==============

## Version 1.86 - 14.Dec.2016

* Don't mis-report UDP packets as being too short (Mark Allman).

* Click updates.

## Version 1.85 - 22.Feb.2015

* Support nanosecond-precision tcpdump files and pcap captures.

* Bug fixes with TCP option output.

* Click updates.

## Version 1.84 - 2.May.2014

* Compile fix.

## Version 1.83 - 19.Mar.2014

* Correct binary output of Ethernet addresses (Romain Fontugne report).

## Version 1.82 - 29.Jun.2011

* Fix compilation problems with later GCCs (José Pedro Oliveira report).
  Also update Click.

## Version 1.81 - 29.Mar.2011

* Fix compilation problems with later GCCs (José Pedro Oliveira report).

## Version 1.80 - 14.Feb.2011

* Fix --wire-length in presence of IP-related arguments (Dan Levin report).

## Version 1.79 - 1.Oct.2010

* Add --wire-length data type (Mark Allman request).

## Version 1.78 - 24.Sep.2009

* Fix length calculations for short frames with short capture lengths.
  Specifically, Ethernet padding could sometimes be added to the IP length,
  if the Ethernet padding wasn't part of the capture length.  This was due
  to the way we handle "extra length" annotations, a source of many issues.
  The current logic passes our current tests.  Problem reported by Mark
  Allman.

## Version 1.77 - 12.Jun.2009

* Add --skip-packets option (Kevin Fall request).

## Version 1.76 - 4.Dec.2008

* Fix handling of lengths between 2^16 and 2^16+7.  Problem reported by
  Damien Ancelin.  Thanks, Damien Ancelin!

## Version 1.75 - 3.Dec.2008

* Some bug fixes for problems caught by Click tests.

## Version 1.74 - 3.Dec.2008

* ipaggcreate: Control-C will lead to output.  Reported by Martin Duke.

## Version 1.73 - 3.Dec.2008

* Fix reading timestamps from binary ipsumdump files.  Problem reported by
  Damien Ancelin.

* Changes to the way lengths of 2^16 or more are represented.  Issue
  reported by Damien Ancelin.

* Summary dump sources correctly represent packets with different IP and
  payload lengths.  In particular, a TCP packet with IP length 1500 and
  payload length 1448 implies 12 bytes of option.  Now we add 12 bytes of
  empty option to represent that.  Issue reported by Damien Ancelin.

## Version 1.72 - 13.Nov.2008

* ipaggcreate: `--split-time` works correctly, and does not drop packets
  when switching from time bucket to time bucket.  Problem reported by
  Damien Ancelin.

## Version 1.71 - 8.Oct.2008

* Generate correct MD5 checksums for packets with link-level headers and
  short payloads, such as pure TCP acknowledgments from Ethernet traces.
  This makes payload MD5 sums incompatible with prior versions, an
  unfortunate, but unavoidable, incompatibility.  Problem reported by
  Nicholas Weaver and Christian Kreibich.

* Add `--payload-md5-hex`.

## Version 1.70 - 5.May.2008

* Add support for IEEE802_11_RADIO encapsulation.  Requested by Mustafa
  Mohammad.

## Version 1.69 - 28.Apr.2008

* Reading from IP summary dumps preserves all extra length, including
  extra length above 0xFFFF (Damien Ancelin).

## Version 1.68 - 9.Apr.2008

* Add `--no-payload` (Nicholas Weaver).

## Version 1.67 - 3.Apr.2008

* Add `--ip-ttl`, `--ip-tos`, `--ip-hl`, `--icmp-type`, `--icmp-code`,
  `--icmp-type-name`, `--icmp-code-name` options (Nicholas Weaver and
  Kamran Shafi).

## Version 1.66 - 4.Mar.2008

* Another bug fix, reported this time by Nick Weaver.

## Version 1.65 - 28.Feb.2008

* Fix sampling.  Problem reported by Vern Paxson.

## Version 1.64 - 27.Feb.2008

* Add `--no-header`, `--eth-src`, and `--eth-dst` options.  Requested by
  Vern Paxson.

## Version 1.63 - 19.Jan.2007

* Add `--payload-md5` option.  Requested by Vern Paxson.

## Version 1.62 - 17.Sep.2006

* Update Click to 1.5.0.  This also solves Solaris compiling problems
  reported by Vern Paxson.

## Version 1.61 - 17.Jan.2006

* The `--payload-len` option will correctly report a 0 payload length when
  the TCP header is broken.  Reported by Vern Paxson.

* Include initial, undocumented version of ipaggmanip.

## Version 1.60 - 9.Jan.2006

* Ipaggcreate works and is documented!

* Extensive update of ipsumdump's internals to use new Click features,
  including the Script element.  Please report any bugs you find.

## Version 1.59 - 26.Nov.2005

* Add `--tcp-window` option.  Requested by Vern Paxson.

## Version 1.58 - 21.Nov.2005

* Do not FORCE_IP unless you have to.  Requested by Vern Paxson.

## Version 1.57 - 3.Oct.2005

* More verbose error messages on USE_ENCAP_FROM conflict (combining
  multiple traces with different encapsulations).  Reported by Vern Paxson.

## Version 1.56 - 31.Aug.2005

* Drop any set-uid-root privileges after initializing device reading
  elements.  Requested by Mark Allman.

## Version 1.55 - 3.Jun.2005

* Better support for old-style DAG dumps via the --dag=ENCAP option
  variant.  Bug reported by Harshit Nayyar.

* Include initial version of ipaggcreate (but it doesn't fully work yet).

## Version 1.54 - 10.Apr.2005

* Bug fix: Mac OS X defines pcap_setnonblock, but does not declare it.

## Version 1.53 - 9.Apr.2005

* Bug fix: include IPNameInfo.  Reported by Vern Paxson.

## Version 1.52 - 15.Mar.2005

* Compile fix for Solaris: check for madvise under C++.

## Version 1.51 - 3.Feb.2005

* Add `--ip-sum` option; patch from José Maria González.

* Fix `--ip-opt` crash; patch from Mark Allman.

## Version 1.50 - 25.Jan.2005

* Add `--ip-opt` option, requested by Mark Allman.

## Version 1.49 - 14.Jan.2005

* Add `--udp-length` option requested by Ruoming Pang.

## Version 1.48 - 12.Jan.2005

* Fix handling of extra length annotations.  If the IP length is available,
  use that (not extra length), except for packets that represent flows.
  Problem reported by Ruoming Pang.

## Version 1.47 - 12.Jan.2005

* More AMD64 stuff, this time reported by Kirill Ponomarew.

## Version 1.46 - 10.Jan.2005

* Update config.guess and config.sub within Click, hopefully addressing
  configure errors on AMD64 reported by Sivakumar Ramagopal.

## Version 1.45 - 4.Jan.2005

* Update with Click bug fixes.

## Version 1.44 - 3.Jan.2005

* Timestamps now use nanosecond precision when available (such as for DAG
  inputs).  Requested by Alefiya Hussain.  Supply the
  `--disable-nanotimestamp` option to turn this feature off.

* Add support for NULL encapsulated dumps.  Requested by Vern Paxson.

## Version 1.43 - 16.Sep.2004

* Add the `--link` content option, relevant to NLANR TSH logs and NetFlow
  logs.  Requested by Kaushal Patel.

* Rewrite ToIPSummaryDump element, separating its functionality into
  separate "unparser" files.

## Version 1.42 - 3.Sep.2004

* Add support for PPP-encapsulated DAG dumps, via the `--dag-ppp` option,
  and for PPP-encapsulated tcpdump files.  Requested by Pedro Torres.

## Version 1.41 - 18.Aug.2004

* Add support for IEEE 802.11/Prism2 encapsulated dumps.  Requested by
  David Wetherall.

* Use `C` for CWR in tcp_flags dumps, since that's what tcpdump does.  Bump
  IPSummaryDump file format version number to 1.2 as a result.

## Version 1.40 - 16.Aug.2004

* Fix ERF/DAG timestamps.  Again, reported by Holger Dreger.

## Version 1.39 - 10.Aug.2004

* Support new-style ERF/DAG dumps.  Reported by Holger Dreger.

## Version 1.38 - 10.Jul.2004

* Print information from partially-captured headers.  For example,
  ipsumdump will print the TCP source ports of packets whose TCP options
  were not captured (as long as the source ports were captured).
  Previously the source ports would be printed as '-', since the whole TCP
  header was not captured.  Requested by Vern Paxson.

* `--bad-packets` now prints `!bad` lines IN ADDITION TO normal output, not
  instead of normal output.

## Version 1.37 - 9.Jul.2004

* Support HDLC link layers.  Requested by Vern Paxson.

## Version 1.36 - 7.Jul.2004

* Support 64-bit-long systems (patch directly from Click).  Reported by
  Kirill Ponomarew.

## Version 1.35 - 17.Jun.2004

* Add `--capture-length` option, requested by Vern Paxson.

* Add `--dag` and `--nlanr` options, for DAG and NLANR dumps.

## Version 1.34 - 26.Jan.2004

* Fix configure check for machines where int64_t and long are the same
  type.  Reported by Kirill Ponomarew.

* Add `--tcpdump-text` option.

## Version 1.33 - 3.Dec.2003

* Document segmentation-fault behavior when mmaping corrupt files, and add
  `--no-mmap` option (requested by Vern Paxson).

* Allow progress bars when there's no IP summary dump output.

## Version 1.32 - 10.Nov.2003

* Support large files (bug reported by David Loose).

## Version 1.31 - 6.Nov.2003

* Include Unqueue element (bug reported by David Loose).

## Version 1.30 - 5.Sep.2003

* Set UDP and IP lengths correctly, hopefully addressing problems reported
  by Andrew White.

* In `--multipacket`, the sum of the individual packet lengths should equal
  the total packet length.

## Version 1.29 - 4.Sep.2003

* Fix build problems reported by Andrew White.

## Version 1.28 - 3.Sep.2003

* Fix `--netflow-summary` problems reported by Andrew White:
  FromNetFlowSummaryDump didn't set IP length correctly, causing packets to
  be treated as corrupt.

* `--netflow-summary` pays attention to flow end timestamp as well as flow
  timestamp, and to TCP flags.

* `--multipacket` spreads out packets between flow-begin and flow-end
  timestamps.

## Version 1.27 - 25.Apr.2003

* Change build process to put dependency flags in their own variable (avoid
  ./configure problems reported by Anestis Karasaridis).

## Version 1.26 - 22.Apr.2003

* Update to newer version of Click (reduces ./configure problems).

## Version 1.25 - 21.Sep.2002

* Add `--binary' option and support for binary IPSummaryDump files.

## Version 1.24 - 31.Jul.2002

* Speed up interaction of `-r' (read from tcpdump(1) files) and `-A'
  (anonymize). Previously this would uselessly copy 4MB of data per packet!
  Reported by Vern.

* Add `--limit-packets' option.

## Version 1.23 - 2.Jun.2002

* Documentation updates.

* TCP flag bits 6 and 7 are printed as E and W, for ECE and CWR, based on
  the ECN Proposed Standard.

* Fixed bug with interaction between `--interval' and `--interface'.

* Under `--tcpdump', truncated IP packets are now printed as normal
  packets. Some tcpdump files don't correctly record the caplen.

## Version 1.22 - 2.Jun.2002

* Fragment offset fields, produced by -G, formerly were expressed in 8-byte
  units. Starting with this version, fragment offset fields are expressed
  in bytes. Updated the `!IPSummaryDump' file version number to `1.1' to
  represent this change.

* Fixed bug with reading ipsumdump files: incorrect IP lengths caused many
  packets to be ignored.

* Update to Click-1.2.4.

## Version 1.21 - 26.Mar.2002

* Update endianness test (Click failed to compile on Solaris). Reported by
  Ahmed Aslam <aaslam@csee.usf.edu>.

## Version 1.20 - 8.Jan.2002

* Add `--interval' option.

## Version 1.19 - 31.Dec.2001

* Add some sanity checks on ip_len to the TCP and UDP header checks, and
  improve payload length calculation. Reported by Vern.

## Version 1.18 - 30.Dec.2001

* Fix bug with --payload: ipsumdump could output a payload string
  containing too much or too little data. Reported by Vern.

## Version 1.17 - 17.Dec.2001

* Reading from network interfaces was broken by version 1.14: unless -w was
  given, ToIPSummaryDump treated partially-read packets (low SNAPLEN) as
  erroneous. Reported by Brecht Vermeulen <brecht.vermeulen@rug.ac.be>.

## Version 1.16 - 30.Nov.2001

* Progress bar improvements: The progress bar will not appear if normal
  output is to the terminal, or if the invocation doesn't take very long.

## Version 1.15 - 28.Nov.2001

* --length, --payload-length, and --payload deal with IP length, ignoring
  any link-level padding at the end. Problem reported by Vern.

## Version 1.14 - 28.Nov.2001

* Don't generate mistaken output for bad IP, TCP, or UDP headers (print
  dashes instead). Bad headers include IP versions other than 4, bad IP
  header lengths, bad TCP header lengths, and TCP/UDP headers not included
  in a single fragment. Suggested by Vern.

* Add --bad-packets option. When supplied, the IP summary dump contains
  messages like `!bad IP header length 2' on packets with bad IP, TCP, or
  UDP headers, instead of normal output (with dashes).

* Add --payload option.

## Version 1.13 - 4.Nov.2001

* Speed improvements in --tu-summary/--ipsumdump.

## Version 1.12 - 31.Oct.2001

* Remove default dump content options. If you don't supply any dump
  contents, ipsumdump won't create a summary dump. It still will create any
  --write-tcpdump file, though. For Vern.

* Catch fewer signals.

## Version 1.11 - 29.Oct.2001

* Add progress bar.

## Version 1.10 - 10.Oct.2001

* Add --fragment and --fragoff options. Fix behavior with fragments.
  Reported by Vern Paxson <vern@icir.org>.

## Version 1.9 - 10.Oct.2001

* Add --record-counts option.

## Version 1.8 - 9.Oct.2001

* Fix --filter option, and add --no-promisc.

## Version 1.7 - 9.Oct.2001

* Bug fixes. Signal handling. Sampling works correctly with MULTIPACKET.

## Version 1.6 - 9.Oct.2001

* The --write-tcpdump output file includes link-level headers.

## Version 1.5 - 8.Oct.2001

* Add --random-seed option.

## Version 1.4 - 7.Oct.2001

* Add --sample and --collate options.

## Version 1.3

* Add FromDevice.kernel_drops handler, and use that handler to report any
  kernel packet drops.
