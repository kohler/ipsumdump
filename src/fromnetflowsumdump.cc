/*
 * frombreslau1dump.{cc,hh} -- element reads packets from Lee Breslau-style
 * NetFlow dump file
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

#include "frombreslau1dump.hh"
#include <click/confparse.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <click/click_ip.h>
#include <click/click_udp.h>
#include <click/click_tcp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

FromBreslau1Dump::FromBreslau1Dump()
    : Element(0, 1), _fd(-1), _pos(0), _len(0), _task(this), _pipe(0)
{
    MOD_INC_USE_COUNT;
}

FromBreslau1Dump::~FromBreslau1Dump()
{
    MOD_DEC_USE_COUNT;
    uninitialize();
}

int
FromBreslau1Dump::configure(const Vector<String> &conf, ErrorHandler *errh)
{
    bool stop = false, active = true, zero = false;
    
    if (cp_va_parse(conf, this, errh,
		    cpFilename, "dump file name", &_filename,
		    cpKeywords,
		    "STOP", cpBool, "stop driver when done?", &stop,
		    "ACTIVE", cpBool, "start active?", &active,
		    "ZERO", cpBool, "zero packet data?", &zero,
		    0) < 0)
	return -1;

    _stop = stop;
    _active = active;
    _zero = zero;
    return 0;
}

int
FromBreslau1Dump::error_helper(ErrorHandler *errh, const char *x)
{
    if (errh)
	errh->error("%s: %s", _filename.cc(), x);
    else
	click_chatter("%s: %s", id().cc(), x);
    return -1;
}

int
FromBreslau1Dump::read_buffer(ErrorHandler *errh)
{
    if (_pos == 0 && _len == _buffer.length())
	_buffer.append_garbage(BUFFER_SIZE);

    unsigned char *data = (unsigned char *)_buffer.mutable_data();
    int buffer_len = _buffer.length();

    if (_len == buffer_len) {
	memmove(data, data + _pos, _len - _pos);
	_len -= _pos;
	_pos = 0;
    }
    int initial_len = _len;
    
    while (_len < buffer_len) {
	ssize_t got = read(_fd, data + _len, buffer_len - _len);
	if (got > 0)
	    _len += got;
	else if (got == 0)	// premature end of file
	    return _len - initial_len;
	else if (got < 0 && errno != EINTR && errno != EAGAIN)
	    return error_helper(errh, strerror(errno));
    }
    
    return _len - initial_len;
}

int
FromBreslau1Dump::read_line(String &result, ErrorHandler *errh)
{
    int epos = _pos;

    while (1) {
	bool done = false;
	
	if (epos >= _len) {
	    int delta = epos - _pos;
	    int errcode = read_buffer(errh);
	    if (errcode < 0 || (errcode == 0 && delta == 0))	// error
		return errcode;
	    else if (errcode == 0)
		done = true;
	    epos = _pos + delta;
	}

	const char *d = _buffer.data();
	while (epos < _len && d[epos] != '\n' && d[epos] != '\r')
	    epos++;

	if (epos < _len || done) {
	    result = _buffer.substring(_pos, epos - _pos);
	    if (epos < _len && d[epos] == '\r')
		epos++;
	    if (epos < _len && d[epos] == '\n')
		epos++;
	    _pos = epos;
	    return 1;
	}
    }
}

int
FromBreslau1Dump::initialize(ErrorHandler *errh)
{
    _pipe = 0;
    if (_filename == "-") {
	_fd = STDIN_FILENO;
	_filename = "<stdin>";
    } else
	_fd = open(_filename.cc(), O_RDONLY);

  retry_file:
    if (_fd < 0)
	return errh->error("%s: %s", _filename.cc(), strerror(errno));

    _pos = _len = 0;
    _buffer = String();
    int result = read_buffer(errh);
    if (result < 0) {
	uninitialize();
	return -1;
    } else if (result == 0) {
	uninitialize();
	return errh->error("%s: empty file", _filename.cc());
    }

    // check for a gziped or bzip2d dump
    if (_fd == STDIN_FILENO || _pipe)
	/* cannot handle gzip or bzip2 */;
    else if (_len >= 3
	     && ((_buffer[0] == '\037' && _buffer[1] == '\213')
		 || (_buffer[0] == 'B' && _buffer[1] == 'Z' && _buffer[2] == 'h'))) {
	close(_fd);
	_fd = -1;
	String command = (_buffer[0] == '\037' ? "zcat " : "bzcat ") + _filename;
	_pipe = popen(command.cc(), "r");
	if (!_pipe)
	    return errh->error("%s while executing `%s'", strerror(errno), command.cc());
	_fd = fileno(_pipe);
	goto retry_file;
    }

    String line;
    if (read_line(line, errh) < 0) {
	uninitialize();
	return -1;
    } else
	_pos = 0;
    
    _format_complaint = false;
    if (output_is_push(0))
	ScheduleInfo::initialize_task(this, &_task, _active, errh);
    return 0;
}

void
FromBreslau1Dump::uninitialize()
{
    if (_pipe)
	pclose(_pipe);
    else if (_fd >= 0 && _fd != STDIN_FILENO)
	close(_fd);
    _fd = -1;
    _pipe = 0;
    _buffer = String();
    _task.unschedule();
}

Packet *
FromBreslau1Dump::read_packet(ErrorHandler *errh)
{
    WritablePacket *q = Packet::make((const char *)0, sizeof(click_ip) + sizeof(click_tcp));
    if (!q) {
	error_helper(errh, "out of memory!");
	return 0;
    }
    if (_zero)
	memset(q->data(), 0, q->length());
    q->set_ip_header((click_ip *)q->data(), sizeof(click_ip));
    click_ip *iph = q->ip_header();
    iph->ip_v = 4;
    iph->ip_hl = sizeof(click_ip) >> 2;
    
    String line;
    String words[15];
    uint32_t j;
    
    while (1) {

	if (read_line(line, errh) <= 0) {
	    q->kill();
	    return 0;
	}

	const char *data = line.data();
	int len = line.length();

	if (len == 0 || data[0] == '!' || data[0] == '#')
	    continue;

	int pos = 0, dpos = 0;
	while (dpos < len && pos < 15) {
	    int start = dpos;
	    while (dpos < len && data[dpos] != '|')
		dpos++;
	    words[pos++] = line.substring(start, dpos - start);
	    dpos++;
	}
	if (pos < 15)
	    break;

	// relevant indices:
	// 0 - source IP
	// 1 - dest IP
	// 5 - # packets
	// 6 - # bytes
	// 7 - start timestamp sec
	// 9 - source port
	// 10 - dest port
	// 13 - protocol
	// 14 - TOS bits

	int ok = 0;
	ok += cp_ip_address(words[0], (unsigned char *)&iph->ip_src);
	ok += cp_ip_address(words[1], (unsigned char *)&iph->ip_dst);
	if (cp_unsigned(words[5], &j))
	    SET_PACKET_COUNT_ANNO(q, j), ok++;
	if (cp_unsigned(words[6], &j))
	    SET_EXTRA_LENGTH_ANNO(q, j - q->length()), ok++;
	if (cp_unsigned(words[7], &j))
	    q->set_timestamp_anno(j, 0), ok++;
	if (cp_unsigned(words[13], &j) && j <= 0xFF)
	    iph->ip_p = j, ok++;
	if (cp_unsigned(words[14], &j) && j <= 0xFF)
	    iph->ip_tos = j, ok++;
	if (cp_unsigned(words[9], &j) && j <= 0xFFFF)
	    q->udp_header()->uh_sport = htons(j), ok++;
	if (cp_unsigned(words[10], &j) && j <= 0xFFFF)
	    q->udp_header()->uh_dport = htons(j), ok++;

	if (ok < 9)
	    break;
	return q;
    }

    // bad format if we get here
    if (!_format_complaint) {
	error_helper(errh, "bad format");
	_format_complaint = true;
    }
    if (q)
	q->kill();
    return 0;
}

void
FromBreslau1Dump::run_scheduled()
{
    if (!_active)
	return;

    Packet *p = read_packet(0);
    if (!p) {
	if (_stop)
	    router()->please_stop_driver();
	return;
    }
    
    output(0).push(p);
    _task.fast_reschedule();
}

Packet *
FromBreslau1Dump::pull(int)
{
    if (!_active)
	return 0;

    Packet *p = read_packet(0);
    if (!p && _stop)
	router()->please_stop_driver();
    return p;
}

String
FromBreslau1Dump::read_handler(Element *e, void *thunk)
{
    FromBreslau1Dump *fd = static_cast<FromBreslau1Dump *>(e);
    switch ((int)thunk) {
      case 1:
	return cp_unparse_bool(fd->_active) + "\n";
      default:
	return "<error>\n";
    }
}

int
FromBreslau1Dump::write_handler(const String &s_in, Element *e, void *thunk, ErrorHandler *errh)
{
    FromBreslau1Dump *fd = static_cast<FromBreslau1Dump *>(e);
    String s = cp_uncomment(s_in);
    switch ((int)thunk) {
      case 1: {
	  bool active;
	  if (cp_bool(s, &active)) {
	      fd->_active = active;
	      if (active && fd->output_is_push(0) && !fd->_task.scheduled())
		  fd->_task.reschedule();
	      return 0;
	  } else
	      return errh->error("`active' should be Boolean");
      }
      default:
	return -EINVAL;
    }
}

void
FromBreslau1Dump::add_handlers()
{
    add_read_handler("active", read_handler, (void *)1);
    add_write_handler("active", write_handler, (void *)1);
    if (output_is_push(0))
	add_task_handlers(&_task);
}

ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(FromBreslau1Dump)
