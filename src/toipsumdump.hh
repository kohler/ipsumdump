#ifndef CLICK_TOIPSUMDUMP_HH
#define CLICK_TOIPSUMDUMP_HH
#include <click/element.hh>
#include <click/task.hh>
#include <click/straccum.hh>

/*
=c

ToIPSummaryDump(FILENAME [, I<KEYWORDS>])

=s sinks

writes packet summary information

=d

Writes summary information about incoming packets to FILENAME in a simple
ASCII format---each line corresponds to a packet. The CONTENTS keyword
argument determines what information is written. Writes to standard output if
FILENAME is a single dash `C<->'.

Keyword arguments are:

=over 8

=item CONTENTS

Space-separated list of field names. Each line of the summary dump will
contain those fields. Valid field names, with examples, are:

   timestamp   Packet timestamp: `996033261.451094'
   ts sec      Seconds portion of timestamp: `996033261'
   ts usec     Microseconds portion of timestamp: `451094'
   src         IP source address: `192.150.187.37'
   dst         IP destination address: `192.168.1.100'
   len         IP length field: `132'
   proto       IP protocol: `6'
   ip id       IP ID: `48759'
   sport       TCP/UDP source port: `22'
   dport       TCP/UDP destination port: `2943'

(You must quote field names that contain a space.) Default CONTENTS is `src
dst'.

=item VERBOSE

Boolean. If true, then print out a couple comments at the beginning of the
dump describing the hostname and starting time, in addition to the `C<!data>' line describing the log contents.

=item BANNER

String. If supplied, prints a `C<!creator "BANNER">' comment at the beginning
of the dump.

=back

=e

Here are a couple lines from the start of a sample verbose dump.

  !creator "aciri-ipsumdump -i wvlan0"
  !host no.lcdf.org
  !starttime 996022410.322317 (Tue Jul 24 17:53:30 2001)
  !data 'ip src' 'ip dst'
  63.250.213.167 192.150.187.106
  63.250.213.167 192.150.187.106

=a

FromDump, ToDump */

class ToIPSummaryDump : public Element { public:
  
    ToIPSummaryDump();
    ~ToIPSummaryDump();
  
    const char *class_name() const	{ return "ToIPSummaryDump"; }
    const char *processing() const	{ return AGNOSTIC; }
    const char *flags() const		{ return "S2"; }
    ToIPSummaryDump *clone() const	{ return new ToIPSummaryDump; }
  
    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void uninitialize();
    void add_handlers();

    void push(int, Packet *);
    void run_scheduled();

    enum Content {
	W_NONE, W_TIMESTAMP, W_TIMESTAMP_SEC, W_TIMESTAMP_USEC,
	W_SRC, W_DST, W_LENGTH, W_PROTO, W_IPID, W_SPORT, W_DPORT
    };
    static const char *content_name(int);
    
  private:

    String _filename;
    FILE *_f;
    StringAccum _sa;
    Vector<unsigned> _contents;
    bool _active;
    Task _task;
    bool _verbose : 1;
    String _banner;

    bool ascii_summary(Packet *, StringAccum &) const;
    void write_packet(Packet *);
    
};

#endif
