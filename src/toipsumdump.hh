#ifndef CLICK_TOEJYSUMMARYDUMP_HH
#define CLICK_TOEJYSUMMARYDUMP_HH
#include <click/element.hh>
#include <click/task.hh>
#include <click/straccum.hh>

/*
=c

ToEjySummaryDump(FILENAME [, I<KEYWORDS>])

=s sinks

writes packet summary information

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
