#ifndef CLICK_TOEJYSUMMARYDUMP_HH
#define CLICK_TOEJYSUMMARYDUMP_HH
#include <click/element.hh>
#include <click/task.hh>
#include <click/straccum.hh>

/*
=c

ToEjySummaryDump(FILENAME [, I<KEYWORDS>])

=s sinks

writes packets to a tcpdump(1) file

=d

Writes incoming packets to FILENAME in `tcpdump -w' format. This file can be
read `tcpdump -r', or by FromDump on a later run. FILENAME can be `-', in
which case ToDump writes to the standard output.

Writes at most SNAPLEN bytes of each packet to the file. The default SNAPLEN
is 2000. ENCAP specifies the first header each packet is expected to have.
This information is stored in the file header, and must be correct or tcpdump
won't be able to read the file correctly. It can be `C<IP>' or `C<ETHER>';
default is `C<ETHER>'.

Keyword arguments are:

=over 8

=item SNAPLEN

Integer. Same as the SNAPLEN argument.

=item ENCAP

Either `C<IP>' or `C<ETHER>'. Same as the ENCAP argument.

=back

This element is only available at user level.

=a

FromDump, ToDump */

class ToEjySummaryDump : public Element { public:
  
    ToEjySummaryDump();
    ~ToEjySummaryDump();
  
    const char *class_name() const	{ return "ToEjySummaryDump"; }
    const char *processing() const	{ return AGNOSTIC; }
    const char *flags() const		{ return "S2"; }
    ToEjySummaryDump *clone() const	{ return new ToEjySummaryDump; }
  
    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void uninitialize();
    void add_handlers();

    void push(int, Packet *);
    void run_scheduled();

  private:

    enum {
	W_NONE, W_TIMESTAMP, W_TIMESTAMP_SEC, W_TIMESTAMP_USEC,
	W_IP_SRC, W_IP_DST, W_TU_SPORT, W_TU_DPORT
    };
    
    String _filename;
    FILE *_f;
    StringAccum _sa;
    Vector<unsigned> _descs;
    bool _active;
    Task _task;
    bool _verbose : 1;

    static const char *desc_name(int);
    bool ascii_summary(Packet *, StringAccum &) const;
    void write_packet(Packet *);
    
};

#endif
