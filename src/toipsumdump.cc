/*
 * toejysummarydump.{cc,hh} -- element writes packets to tcpdump-like file
 * Eddie Kohler
 *
 * Copyright (c) 2001 International Computer Science Institute
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "toejysummarydump.hh"
#include <click/standard/scheduleinfo.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/click_ip.h>
#include <click/click_udp.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

ToEjySummaryDump::ToEjySummaryDump()
    : Element(1, 0), _f(0), _task(this)
{
    MOD_INC_USE_COUNT;
}

ToEjySummaryDump::~ToEjySummaryDump()
{
    MOD_DEC_USE_COUNT;
}

int
ToEjySummaryDump::configure(const Vector<String> &conf, ErrorHandler *errh)
{
    int before = errh->nerrors();
    String save = "timestamp 'ip src'";
    bool verbose = false;

    if (cp_va_parse(conf, this, errh,
		    cpFilename, "dump filename", &_filename,
		    cpKeywords,
		    "CONTENTS", cpArgument, "log contents", &save,
		    "VERBOSE", cpBool, "be verbose?", &verbose,
		    "BANNER", cpString, "banner", &_banner,
		    0) < 0)
	return -1;

    Vector<String> v;
    cp_spacevec(save, v);
    for (int i = 0; i < v.size(); i++) {
	String word = cp_unquote(v[i]);
	if (word == "timestamp" || word == "ts")
	    _contents.push_back(W_TIMESTAMP);
	else if (word == "sec" || word == "ts sec")
	    _contents.push_back(W_TIMESTAMP_SEC);
	else if (word == "usec" || word == "ts usec")
	    _contents.push_back(W_TIMESTAMP_USEC);
	else if (word == "src" || word == "ip src")
	    _contents.push_back(W_SRC);
	else if (word == "dst" || word == "ip dst")
	    _contents.push_back(W_DST);
	else if (word == "sport")
	    _contents.push_back(W_SPORT);
	else if (word == "dport")
	    _contents.push_back(W_DPORT);
	else if (word == "len" || word == "length")
	    _contents.push_back(W_LENGTH);
	else if (word == "id" || word == "ip id")
	    _contents.push_back(W_IPID);
	else
	    errh->error("unknown save data `%s'", word.cc());
    }
    if (_contents.size() == 0)
	errh->error("no save data specified");

    _verbose = verbose;

    return (before == errh->nerrors() ? 0 : -1);
}

int
ToEjySummaryDump::initialize(ErrorHandler *errh)
{
    assert(!_f);
    if (_filename != "-") {
	_f = fopen(_filename, "wb");
	if (!_f)
	    return errh->error("%s: %s", _filename.cc(), strerror(errno));
    } else {
	_f = stdout;
	_filename = "<stdout>";
    }

    if (input_is_pull(0))
	ScheduleInfo::join_scheduler(this, &_task, errh);
    _active = true;

    if (_banner)
	fprintf(_f, "!creator %s\n", cp_quote(_banner).cc());
    
    // write open data
    if (_verbose) {
	char buf[BUFSIZ];
	buf[BUFSIZ - 1] = '\0';	// ensure NUL-termination
	if (gethostname(buf, BUFSIZ - 1) >= 0)
	    fprintf(_f, "!host %s\n", buf);

	time_t when = time(0);
	const char *cwhen = ctime(&when);
	struct timeval tv;
	if (gettimeofday(&tv, 0) >= 0)
	    fprintf(_f, "!starttime %ld.%ld (%.*s)\n", (long)tv.tv_sec,
		    (long)tv.tv_usec, (int)(strlen(cwhen) - 1), cwhen);
	
	fprintf(_f, "!data ");
	for (int i = 0; i < _contents.size(); i++)
	    fprintf(_f, (i ? " '%s'" : "'%s'"), content_name(_contents[i]));
	fprintf(_f, "\n");
    }
    
    return 0;
}

void
ToEjySummaryDump::uninitialize()
{
    if (_f && _f != stdout)
	fclose(_f);
    _f = 0;
    _task.unschedule();
}

static const char *content_names[] = {
    "??", "timestamp", "ts sec", "ts usec",
    "ip src", "ip dst", "len", "ip id",
    "sport", "dport",
};

const char *
ToEjySummaryDump::content_name(int what)
{
    if (what < 0 || what >= (int)(sizeof(content_names) / sizeof(content_names[0])))
	return "??";
    else
	return content_names[what];
}

bool
ToEjySummaryDump::ascii_summary(Packet *p, StringAccum &sa) const
{
    for (int i = 0; i < _contents.size(); i++) {
	if (i)
	    sa << ' ';
	
	switch (_contents[i]) {

	  case W_TIMESTAMP:
	    sa << p->timestamp_anno();
	    break;
	  case W_TIMESTAMP_SEC:
	    sa << p->timestamp_anno().tv_sec;
	    break;
	  case W_TIMESTAMP_USEC:
	    sa << p->timestamp_anno().tv_usec;
	    break;
	  case W_SRC: {
	      const click_ip *iph = p->ip_header();
	      if (!iph) return false;
	      sa << IPAddress(iph->ip_src);
	      break;
	  }
	  case W_DST: {
	      const click_ip *iph = p->ip_header();
	      if (!iph) return false;
	      sa << IPAddress(iph->ip_dst);
	      break;
	  }
	  case W_SPORT: {
	      const click_ip *iph = p->ip_header();
	      const click_udp *udph = (const click_udp *)p->transport_header();
	      if (!iph || !udph) return false;
	      sa << ntohs(udph->uh_sport);
	      break;
	  }
	  case W_DPORT: {
	      const click_ip *iph = p->ip_header();
	      const click_udp *udph = (const click_udp *)p->transport_header();
	      if (!iph || !udph) return false;
	      sa << ntohs(udph->uh_dport);
	      break;
	  }
	  case W_LENGTH: {
	      const click_ip *iph = p->ip_header();
	      if (!iph) return false;
	      sa << ntohs(iph->ip_len);
	      break;
	  }
	  case W_IPID: {
	      const click_ip *iph = p->ip_header();
	      if (!iph) return false;
	      sa << ntohs(iph->ip_id);
	      break;
	  }

	}
    }
    sa << '\n';
    return true;
}

void
ToEjySummaryDump::write_packet(Packet *p)
{
    _sa.clear();
    if (ascii_summary(p, _sa))
	fwrite(_sa.data(), 1, _sa.length(), _f);
}

void
ToEjySummaryDump::push(int, Packet *p)
{
    if (_active)
	write_packet(p);
    p->kill();
}

void
ToEjySummaryDump::run_scheduled()
{
    if (!_active)
	return;
    Packet *p = input(0).pull();
    if (p) {
	write_packet(p);
	p->kill();
    }
    _task.fast_reschedule();
}

void
ToEjySummaryDump::add_handlers()
{
    if (input_is_pull(0))
	add_task_handlers(&_task);
}

ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(ToEjySummaryDump)
