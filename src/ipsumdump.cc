// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * ipsumdump.cc -- driver for the ipsumdump program
 * Eddie Kohler
 *
 * Copyright (c) 2001-4 International Computer Science Institute
 * Copyright (c) 2004-8 Regents of the University of California
 * Copyright (c) 2008 Meraki, Inc.
 * Copyright (c) 2001-2015 Eddie Kohler
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <click/config.h>
#include <click/clp.h>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/router.hh>
#include <click/driver.hh>
#include <click/llrpc.h>
#include <click/handlercall.hh>
#include <click/master.hh>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>

#include "fromipsumdump.hh"
#include "toipsumdump.hh"
#include "fromdevice.hh"

#define HELP_OPT		300
#define VERSION_OPT		301
#define OUTPUT_OPT		302
#define CONFIG_OPT		303
#define WRITE_DUMP_OPT		304
#define FILTER_OPT		305
#define VERBOSE_OPT		306
#define ANONYMIZE_OPT		307
#define MAP_PREFIX_OPT		308
#define MULTIPACKET_OPT		309
#define SAMPLE_OPT		310
#define COLLATE_OPT		311
#define RANDOM_SEED_OPT		312
#define PROMISCUOUS_OPT		313
#define WRITE_DROPS_OPT		314
#define QUIET_OPT		315
#define BAD_PACKETS_OPT		316
#define INTERVAL_OPT		317
#define LIMIT_PACKETS_OPT	318
#define BINARY_OPT		319
#define MMAP_OPT		320
#define HEADER_OPT		321
#define HELP_DATA_OPT		322
#define NO_PAYLOAD_OPT		323
#define SKIP_PACKETS_OPT	324
#define WRITE_TCPDUMP_NANO_OPT  325

// sources
#define INTERFACE_OPT		400
#define READ_DUMP_OPT		401
#define READ_NETFLOW_SUMMARY_OPT 402
#define READ_IPSUMDUMP_OPT	403
#define READ_ASCII_TCPDUMP_OPT	404
#define READ_NLANR_DUMP_OPT	405
#define READ_DAG_DUMP_OPT	406
#define READ_DAG_PPP_DUMP_OPT	407
#define IPSUMDUMP_FORMAT_OPT	450

static const char* const field_names[] = {
    "timestamp", "first_timestamp", "ip_src", "ip_dst", // 0-4
    "sport", "dport", "ip_len", "ip_id",		// 5-7
    "ip_proto", "tcp_seq", "tcp_ack", "tcp_flags",	// 8-11
    "tcp_opt", "tcp_sack", "payload_len", "count",	// 12-15
    "ip_frag", "ip_fragoff", "payload", "ip_capture_len", // 16-19
    "link", "udp_len", "ip_opt", "ip_sum", "tcp_window", // 20-24
    "payload_md5", "eth_src", "eth_dst", "icmp_type", "icmp_code", // 25-29
    "ip_ttl", "icmp_type_name", "icmp_code_name", "ip_tos", "ip_hl", // 30-34
    "payload_md5_hex", "wire_len"			// 35-36
};

// data
#define FIRST_LOG_OPT		1000
#define TIMESTAMP_OPT		1000
#define FIRST_TIMESTAMP_OPT	1001
#define SRC_OPT			1002
#define DST_OPT			1003
#define SPORT_OPT		1004
#define DPORT_OPT		1005
#define LENGTH_OPT		1006
#define IPID_OPT		1007
#define PROTO_OPT		1008
#define TCP_SEQ_OPT		1009
#define TCP_ACK_OPT		1010
#define TCP_FLAGS_OPT		1011
#define TCP_OPT_OPT		1012
#define TCP_SACK_OPT		1013
#define PAYLOAD_LEN_OPT		1014
#define COUNT_OPT		1015
#define FRAG_OPT		1016
#define FRAGOFF_OPT		1017
#define PAYLOAD_OPT		1018
#define IPCAPLEN_OPT		1019
#define LINK_OPT		1020
#define UDP_LEN_OPT		1021
#define IP_OPT_OPT		1022
#define IP_SUM_OPT		1023
#define TCP_WINDOW_OPT		1024
#define PAYLOAD_MD5_OPT		1025
#define ETH_SRC_OPT		1026
#define ETH_DST_OPT		1027
#define ICMP_TYPE_OPT		1028
#define ICMP_CODE_OPT		1029
#define IP_TTL_OPT		1030
#define ICMP_TYPE_NAME_OPT	1031
#define ICMP_CODE_NAME_OPT	1032
#define IP_TOS_OPT		1033
#define IP_HL_OPT		1034
#define PAYLOAD_MD5_HEX_OPT	1035
#define WIRE_LEN_OPT		1036

#define CLP_TIMESTAMP_TYPE	(Clp_ValFirstUser)

static const Clp_Option options[] = {

    { "help", 'h', HELP_OPT, 0, Clp_PreferredMatch },
    { "help-data", 0, HELP_DATA_OPT, 0, 0 },
    { "version", 'v', VERSION_OPT, 0, 0 },
    { "verbose", 'V', VERBOSE_OPT, 0, Clp_Negate },

    { "interface", 'i', INTERFACE_OPT, 0, 0 },
    { "tcpdump", 'r', READ_DUMP_OPT, 0, 0 },
    { "ipsumdump", 0, READ_IPSUMDUMP_OPT, 0, 0 },
    { "format", 0, IPSUMDUMP_FORMAT_OPT, Clp_ValString, 0 },
    { "nlanr", 0, READ_NLANR_DUMP_OPT, 0, 0 },
    { "dag", 0, READ_DAG_DUMP_OPT, Clp_ValString, Clp_Optional },
    { "dag-ppp", 0, READ_DAG_PPP_DUMP_OPT, 0, 0 },
    { "netflow-summary", 0, READ_NETFLOW_SUMMARY_OPT, 0, 0 },
    { "tcpdump-text", 0, READ_ASCII_TCPDUMP_OPT, 0, 0 },

    { "write-tcpdump", 'w', WRITE_DUMP_OPT, Clp_ValString, 0 },
    { "tcpdump-nano", 0, WRITE_TCPDUMP_NANO_OPT, 0, Clp_Negate },
    { "filter", 'f', FILTER_OPT, Clp_ValString, 0 },
    { "anonymize", 'A', ANONYMIZE_OPT, 0, Clp_Negate },
    { "binary", 'b', BINARY_OPT, 0, Clp_Negate },
    { "map-prefix", 0, MAP_PREFIX_OPT, Clp_ValString, 0 },
    { "map-address", 0, MAP_PREFIX_OPT, Clp_ValString, 0 },
    { "mmap", 0, MMAP_OPT, 0, Clp_Negate },
    { "headers", 0, HEADER_OPT, 0, Clp_Negate },
    { "multipacket", 0, MULTIPACKET_OPT, 0, Clp_Negate },
    { "sample", 0, SAMPLE_OPT, Clp_ValDouble, Clp_Negate },
    { "collate", 0, COLLATE_OPT, 0, Clp_Negate },
    { "random-seed", 0, RANDOM_SEED_OPT, Clp_ValUnsigned, 0 },
    { "promiscuous", 0, PROMISCUOUS_OPT, 0, Clp_Negate },
    { "record-counts", 0, WRITE_DROPS_OPT, Clp_ValString, 0 },
    { "quiet", 'q', QUIET_OPT, 0, Clp_Negate },
    { "bad-packets", 0, BAD_PACKETS_OPT, 0, Clp_Negate },
    { "interval", 0, INTERVAL_OPT, CLP_TIMESTAMP_TYPE, 0 },
    { "skip-packets", 0, SKIP_PACKETS_OPT, Clp_ValUnsigned, Clp_Negate },
    { "limit-packets", 0, LIMIT_PACKETS_OPT, Clp_ValUnsigned, Clp_Negate },
    { "no-payload", 0, NO_PAYLOAD_OPT, 0, 0 },

    { "output", 'o', OUTPUT_OPT, Clp_ValString, 0 },
    { "config", 0, CONFIG_OPT, 0, 0 },

    { "capture-length", 0, IPCAPLEN_OPT, 0, 0 },
    { "dport", 'D', DPORT_OPT, 0, 0 },
    { "dst", 'd', DST_OPT, 0, 0 },
    { "first-timestamp", 'T', FIRST_TIMESTAMP_OPT, 0, 0 },
    { "fragment", 'g', FRAG_OPT, 0, 0 },
    { "fragment-offset", 0, FRAGOFF_OPT, 0, 0 },
    { "fragoff", 'G', FRAGOFF_OPT, 0, 0 },
    { "id", 0, IPID_OPT, 0, 0 },
    { "ip-dst", 'd', DST_OPT, 0, 0 },
    { "ip-hl", 0, IP_HL_OPT, 0, 0 },
    { "ip-id", 0, IPID_OPT, 0, 0 },
    { "ip-opt", 0, IP_OPT_OPT, 0, 0 },
    { "ip-protocol", 0, PROTO_OPT, 0, 0 },
    { "ip-src", 's', SRC_OPT, 0, 0 },
    { "ip-sum", 0, IP_SUM_OPT, 0, 0 },
    { "ip-tos", 0, IP_TOS_OPT, 0, 0 },
    { "length", 'l', LENGTH_OPT, 0, 0 },
    { "link", 0, LINK_OPT, 0, 0 },
    { "packet-count", 'c', COUNT_OPT, 0, 0 },
    { "payload", 0, PAYLOAD_OPT, 0, 0 },
    { "payload-length", 'L', PAYLOAD_LEN_OPT, 0, 0 },
    { "payload-md5", 0, PAYLOAD_MD5_OPT, 0, 0 },
    { "payload-md5-hex", 0, PAYLOAD_MD5_HEX_OPT, 0, 0 },
    { "protocol", 'p', PROTO_OPT, 0, 0 },
    { "src", 's', SRC_OPT, 0, 0 },
    { "sport", 'S', SPORT_OPT, 0, 0 },
    { "tcp-ack", 'K', TCP_ACK_OPT, 0, 0 },
    { "tcp-flags", 'F', TCP_FLAGS_OPT, 0, 0 },
    { "tcp-opt", 'O', TCP_OPT_OPT, 0, 0 },
    { "tcp-sack", 0, TCP_SACK_OPT, 0, 0 },
    { "tcp-seq", 'Q', TCP_SEQ_OPT, 0, 0 },
    { "tcp-window", 'W', TCP_WINDOW_OPT, 0, 0 },
    { "timestamp", 't', TIMESTAMP_OPT, 0, 0 },
    { "udp-length", 0, UDP_LEN_OPT, 0, 0 },
    { "wire-length", 0, WIRE_LEN_OPT, 0, 0 },
    { "eth-src", 0, ETH_SRC_OPT, 0, 0 },
    { "eth-dst", 0, ETH_DST_OPT, 0, 0 },
    { "icmp-type", 0, ICMP_TYPE_OPT, 0, Clp_PreferredMatch },
    { "icmp-code", 0, ICMP_CODE_OPT, 0, Clp_PreferredMatch },
    { "ip-ttl", 0, IP_TTL_OPT, 0, 0 },
    { "icmp-type-name", 0, ICMP_TYPE_NAME_OPT, 0, 0 },
    { "icmp-code-name", 0, ICMP_CODE_NAME_OPT, 0, 0 },

};

static const char *program_name;
static Router *router = 0;
static bool started = false;

void
die_usage(const char* format, ...)
{
    ErrorHandler *errh = ErrorHandler::default_handler();
    if (format) {
        va_list val;
        va_start(val, format);
        errh->xmessage(ErrorHandler::e_error, String(program_name) + ": " + errh->vformat(format, val));
        va_end(val);
    }
    errh->fatal("Usage: %s [-i | -r] [CONTENT OPTIONS] [DEVNAMES or FILES]...\n\
Try %<%s --help%> or %<%s --help-data%> for more information.",
		program_name, program_name);
    // should not get here, but just in case...
    exit(1);
}

void
usage(bool data_only)
{
    FileErrorHandler merrh(stdout);
    if (!data_only)
	merrh.message("\
%<Ipsumdump%> reads IP packets from tcpdump(1) files, or network interfaces,\n\
and summarizes their contents in an ASCII file.\n\
\n\
Usage: %s [DATA OPTIONS] [-i DEVNAMES | FILES] > SUMMARYFILE\n\n",
		      program_name);
    merrh.message("\
General data options:\n\
  -t, --timestamp            Include packet timestamp.\n\
  -T, --first-timestamp      Include flow-begin timestamp.\n\
  -c, --packet-count         Include packet count (usually 1).\n\
      --wire-length          Include wire length (with link header/trailer).\n\
      --link                 Include link number (NLANR/NetFlow).\n\
\n\
Ethernet data options:\n\
      --eth-src              Include Ethernet source address.\n\
      --eth-dst              Include Ethernet destination address.\n\
\n\
IP data options:\n\
  -s, --src                  Include IP source address.\n\
  -d, --dst                  Include IP destination address.\n\
  -l, --length               Include IP length.\n\
  -p, --protocol             Include IP protocol.\n\
  -g, --fragment             Include IP fragment flags (%<F%> or %<.%>).\n\
  -G, --fragment-offset      Include IP fragment offset.\n\
      --ip-id                Include IP ID.\n\
      --ip-sum               Include IP checksum.\n\
      --ip-opt               Include IP options.\n\
      --ip-ttl               Include IP time to live.\n\
      --ip-tos               Include IP type of service.\n\
      --ip-hl                Include IP header length.\n\
      --capture-length       Include length of captured IP data.\n\n");
    merrh.message("\
Transport data options:\n\
  -S, --sport                Include TCP/UDP source port.\n\
  -D, --dport                Include TCP/UDP destination port.\n\
  -L, --payload-length       Include payload length (no IP/UDP/TCP headers).\n\
      --payload              Include packet payload as quoted string.\n\
      --payload-md5          Include MD5 checksum of packet payload.\n\
      --payload-md5-hex      Include MD5 payload checksum in md5sum hex format.\n\
\n\
TCP data options:\n\
  -F, --tcp-flags            Include TCP flags word.\n\
  -Q, --tcp-seq              Include TCP sequence number.\n\
  -K, --tcp-ack              Include TCP acknowledgement number.\n\
  -W, --tcp-window           Include TCP receive window (unscaled).\n\
  -O, --tcp-opt              Include TCP options.\n\
      --tcp-sack             Include TCP selective acknowledgement options.\n\
\n\
UDP data options:\n\
      --udp-length           Include UDP length.\n\n");
    merrh.message("\
ICMP data options:\n\
      --icmp-type            Include ICMP type.\n\
      --icmp-code            Include ICMP code.\n\
      --icmp-type-name       Include human-readable ICMP type.\n\
      --icmp-code-name       Include human-readable ICMP code.\n\n");
    if (data_only) {
	merrh.message("\
      --help                 Print general help message.\n");
	return;
    }
    merrh.message("\
Source options (give exactly one):\n\
  -r, --tcpdump              Read tcpdump(1) FILES (default).\n\
  -i, --interface            Read network devices DEVNAMES until interrupted.\n\
      --ipsumdump            Read existing ipsumdump FILES.\n\
      --format FORMAT        Read ipsumdump FILES with format FORMAT.\n\
      --dag[=ENCAP]          Read DAG-format FILES.\n\
      --nlanr                Read NLANR-format FILES (fr/fr+/tsh).\n\
      --netflow-summary      Read summarized NetFlow FILES.\n\
      --tcpdump-text         Read tcpdump(1) text output FILES.\n\
\n");
    merrh.message("\
Other options:\n\
  -o, --output FILE          Write summary dump to FILE (default stdout).\n\
  -b, --binary               Create binary output file.\n\
  -w, --write-tcpdump FILE   Also dump packets to FILE in tcpdump(1) format.\n\
      --no-tcpdump-nano      --write-tcpdump uses microsecond precision.\n\
      --no-payload           Drop payloads from tcpdump output.\n\
  -f, --filter FILTER        Apply tcpdump(1) filter FILTER to data.\n\
  -A, --anonymize            Anonymize IP addresses (preserves prefix & class).\n\
      --no-promiscuous       Do not put interfaces into promiscuous mode.\n\
      --bad-packets          Print %<!bad%> messages for bad headers.\n\
      --sample PROB          Sample packets with PROB probability.\n\
      --multipacket          Produce multiple entries for a flow identifier\n\
                             representing multiple packets (NetFlow only).\n");
    merrh.message("\
      --collate              Collate packets from data sources by timestamp.\n\
      --interval TIME        Stop after TIME has elapsed in trace time.\n\
      --skip-packets N       Skip the first N packets.\n\
      --limit-packets N      Stop after processing N packets.\n\
      --map-address ADDRS    When done, print to stderr the anonymized IP\n\
                             addresses and/or prefixes corresponding to ADDRS.\n\
      --record-counts TIME   Record packet counts every TIME seconds in output.\n\
      --random-seed SEED     Set random seed to SEED (default is random).\n\
      --no-mmap              Don%,t memory-map input files.\n\
      --no-headers           Don%,t print summary dump headers.\n\
  -q, --quiet                Don%,t print progress bar.\n\
      --config               Output Click configuration and exit.\n\
  -V, --verbose              Report errors verbosely.\n\
  -h, --help                 Print this message and exit.\n\
  -v, --version              Print version number and exit.\n\
\n\
Report bugs to <ekohler@gmail.com>.\n");
}

static void
write_sampling_prob_message(Router *r, const String &sample_elt)
{
    Element *sample = r->find(sample_elt);
    const Handler *h = Router::handler(sample, "sampling_prob");
    if (sample && h) {
	String s = h->call_read(sample);
	ToIPSummaryDump* td = static_cast<ToIPSummaryDump*>(r->find("to_dump"));
	if (td)
	    td->write_line("!sampling_prob " + s + "\n");
    }
}

static int
record_drops_hook(const String &, Element *, void *, ErrorHandler *)
{
    int max_drops = 0;
    bool less_than = false;
    bool all_known = true;
    for (int i = 0; i < router->nelements(); i++) {
	FromDevice* fd = static_cast<FromDevice*>(router->element(i)->cast("FromDevice"));
	if (fd) {
	    int md;
	    bool known;
	    fd->kernel_drops(known, md);
	    if (md < 0)
		all_known = false;
	    else if (!known)
		less_than = true;
	    max_drops += md;
	}
    }

    ToIPSummaryDump* td = static_cast<ToIPSummaryDump*>(router->find("to_dump"));
    if (td) {
	String head = "!counts out " + String(td->output_count()) + " kdrop ";
	if (!all_known)
	    td->write_line(head + "??\n");
	else if (less_than)
	    td->write_line(head + "<" + String(max_drops) + "\n");
	else
	    td->write_line(head + String(max_drops) + "\n");
    }

    return 0;
}

static int
parse_timestamp(Clp_Parser *clp, const char *arg, int complain, void *)
{
    if (cp_time(arg, (Timestamp *)&clp->val))
	return 1;
    else if (complain)
	return Clp_OptionError(clp, "'%O' expects a time value, not '%s'", arg);
    else
	return 0;
}



struct Options {
    bool anonymize;
    bool multipacket;
    double sample;
    bool do_sample;
    bool promisc;
    bool bad_packets;
    bool force_ip;
    int mmap;
    int snaplen;
    String filter;
    String filename;
    String ipsumdump_format;
    String dag_encap;

    enum { SAMPLED = 1, FILTERED = 2 };
};

static uint32_t
add_source(StringAccum &sa, int num, int action, const Options &opt)
{
    uint32_t result = 0;
    const char *force_ip = (opt.force_ip ? ", FORCE_IP true" : "");
    sa << "src" << num << " :: ";

    switch (action) {

      case INTERFACE_OPT:
	sa << "FromDevice(" << cp_quote(opt.filename)
	   << ", SNIFFER true, SNAPLEN " << opt.snaplen << force_ip;
	if (opt.promisc)
	    sa << ", PROMISC true";
#if FROMDEVICE_PCAP
	if (opt.filter)
	    sa << ", BPF_FILTER " << cp_quote(opt.filter);
	result |= Options::FILTERED;
#endif
	sa << ");\n";
	return result;

      case READ_DUMP_OPT:
	sa << "FromDump(" << cp_quote(opt.filename);
	goto dump_common;

      case READ_NLANR_DUMP_OPT:
	sa << "FromNLANRDump(" << cp_quote(opt.filename);
	goto dump_common;

      case READ_DAG_DUMP_OPT:
	sa << "FromDAGDump(" << cp_quote(opt.filename);
	if (opt.dag_encap)
	    sa << ", ENCAP " << opt.dag_encap;
	goto dump_common;

      case READ_DAG_PPP_DUMP_OPT:
	sa << "FromDAGDump(" << cp_quote(opt.filename) << ", ENCAP PPP";
	goto dump_common;

      dump_common:
	sa << force_ip << ", STOP true";
	if (opt.do_sample)
	    sa << ", SAMPLE " << opt.sample;
	if (opt.mmap >= 0)
	    sa << ", MMAP " << opt.mmap;
	sa << ");\n";
	return Options::SAMPLED;

      case READ_ASCII_TCPDUMP_OPT:
	sa << "FromTcpdump(" << cp_quote(opt.filename) << ", STOP true";
	if (opt.do_sample)
	    sa << ", SAMPLE " << opt.sample;
	sa << ");\n";
	return Options::SAMPLED;

      case READ_NETFLOW_SUMMARY_OPT:
	sa << "FromNetFlowSummaryDump(" << cp_quote(opt.filename)
	   << ", STOP true, ZERO true";
	if (opt.multipacket)
	    sa << ", MULTIPACKET true";
	sa << ");\n";
	return 0;

      case READ_IPSUMDUMP_OPT:
	sa << "FromIPSummaryDump(" << cp_quote(opt.filename)
	   << ", STOP true, ZERO true";
	if (opt.do_sample)
	    sa << ", SAMPLE " << opt.sample;
	if (opt.multipacket)
	    sa << ", MULTIPACKET true";
	if (opt.ipsumdump_format)
	    sa << ", CONTENTS " << opt.ipsumdump_format;
	sa << ");\n";
	return Options::SAMPLED;

      default:
	assert(0);

    }
}


int
main(int argc, char *argv[])
{
    Clp_Parser *clp = Clp_NewParser
	(argc, argv, sizeof(options) / sizeof(options[0]), options);
    program_name = Clp_ProgramName(clp);
    Clp_AddType(clp, CLP_TIMESTAMP_TYPE, 0, parse_timestamp, 0);

    click_static_initialize();
    ErrorHandler *errh = ErrorHandler::default_handler();
    ErrorHandler *p_errh = new PrefixErrorHandler(errh, program_name + String(": "));

    String write_dump;
    String output;
    Vector<uint32_t> map_prefixes;
    bool config = false;
    bool verbose = false;
    Vector<int> log_contents;
    int action = 0;
    bool do_seed = true;
    bool collate = false;
    bool quiet = false;
    bool quiet_explicit = false;
    bool bad_packets = false;
    bool binary = false;
    bool header = true;
    bool write_dump_payload = true;
    bool write_dump_nano = true;
    Vector<String> files;
    const char *record_drops = 0;
    unsigned skip_packets = 0;
    unsigned limit_packets = 0;
    Timestamp interval;

    Options options;
    options.anonymize = options.multipacket = options.do_sample =
	options.force_ip = false;
    options.promisc = true;
    options.mmap = options.snaplen = -1;

    while (1) {
	int opt = Clp_Next(clp);
	switch (opt) {

	  case OUTPUT_OPT:
	    if (output)
		die_usage("%<--output%> already specified");
	    output = clp->vstr;
	    break;

	  case INTERFACE_OPT:
	    quiet = true;
	    goto do_action;

	  case READ_DUMP_OPT:
	  case READ_NETFLOW_SUMMARY_OPT:
	  case READ_ASCII_TCPDUMP_OPT:
	  case READ_IPSUMDUMP_OPT:
	  case READ_DAG_PPP_DUMP_OPT:
	  case READ_NLANR_DUMP_OPT:
	  do_action:
	    if (action && action != opt)
		die_usage("data source option already specified");
	    action = opt;
	    break;

	  case READ_DAG_DUMP_OPT:
	    if (action)
		die_usage("data source option already specified");
	    action = opt;
	    if (clp->have_val)
		options.dag_encap = clp->vstr;
	    break;

	  case IPSUMDUMP_FORMAT_OPT:
	    if (options.ipsumdump_format)
		die_usage("IP summary dump format already specified");
	    else if (action && action != READ_IPSUMDUMP_OPT)
		die_usage("%<--format%> only useful with %<--ipsumdump%>");
	    action = READ_IPSUMDUMP_OPT;
	    options.ipsumdump_format = clp->vstr;
	    break;

	  case WRITE_DUMP_OPT:
	    if (write_dump)
		die_usage("%<--write-tcpdump%> already specified");
	    write_dump = clp->vstr;
	    break;

	  case NO_PAYLOAD_OPT:
	    write_dump_payload = false;
	    break;

        case WRITE_TCPDUMP_NANO_OPT:
            write_dump_nano = !clp->negated;
            break;

	  case FILTER_OPT:
	    if (options.filter)
		die_usage("%<--filter%> already specified");
	    options.filter = clp->vstr;
	    options.force_ip = true;
	    break;

	  case ANONYMIZE_OPT:
	    options.anonymize = !clp->negated;
	    options.force_ip = true;
	    break;

	  case MULTIPACKET_OPT:
	    options.multipacket = !clp->negated;
	    break;

	  case PROMISCUOUS_OPT:
	    options.promisc = !clp->negated;
	    break;

	  case WRITE_DROPS_OPT:
	    record_drops = clp->vstr;
	    break;

	  case SKIP_PACKETS_OPT:
	    skip_packets = (clp->negated ? 0 : clp->val.u);
	    break;

	  case LIMIT_PACKETS_OPT:
	    limit_packets = (clp->negated ? 0 : clp->val.u);
	    break;

	  case BINARY_OPT:
	    binary = !clp->negated;
	    break;

	  case MAP_PREFIX_OPT: {
	      String arg(clp->vstr);
	      char *data = arg.mutable_data();
	      int len = arg.length();
	      for (int i = 0; i < len; i++)
		  if (data[i] == ',')
		      data[i] = ' ';

	      Vector<String> v;
	      cp_spacevec(arg, v);

	      for (int i = 0; i < v.size(); i++) {
		  IPAddress addr, mask;
		  if (!cp_ip_prefix(v[i], &addr, &mask, true))
		      die_usage("can%,t parse %<%s%> as an IP address (%s)", v[i].c_str(), Clp_CurOptionName(clp));
		  map_prefixes.push_back(addr.addr());
		  map_prefixes.push_back(mask.addr());
	      }

	      options.force_ip = true;
	      break;
	  }

	  case SAMPLE_OPT:
	    if (clp->negated)
		options.do_sample = false;
	    else {
		options.do_sample = true;
		if (clp->val.d < 0 || clp->val.d > 1)
		    die_usage("%<--sample%> probability must be between 0 and 1");
		options.sample = clp->val.d;
	    }
	    break;

	  case COLLATE_OPT:
	    collate = !clp->negated;
	    break;

	  case RANDOM_SEED_OPT:
	    do_seed = false;
	    srandom(clp->val.u);
	    break;

	  case QUIET_OPT:
	    quiet = !clp->negated;
	    quiet_explicit = true;
	    break;

	  case BAD_PACKETS_OPT:
	    bad_packets = !clp->negated;
	    break;

	  case INTERVAL_OPT:
	    interval = *reinterpret_cast<Timestamp *>(&clp->val);
	    break;

	  case MMAP_OPT:
	    options.mmap = !clp->negated;
	    break;

	  case HEADER_OPT:
	    header = !clp->negated;
	    break;

	  case CONFIG_OPT:
	    config = true;
	    break;

	  case HELP_OPT:
	    usage(false);
	    exit(0);
	    break;

	  case HELP_DATA_OPT:
	    usage(true);
	    exit(0);
	    break;

	  case VERSION_OPT:
	    printf("Ipsumdump %s (libclick-%s)\n", IPSUMDUMP_VERSION, CLICK_VERSION);
	    printf("Copyright (c) 2001-2014 Eddie Kohler and others\n\
This is free software; see the source for copying conditions.\n\
There is NO warranty, not even for merchantability or fitness for a\n\
particular purpose.\n");
	    exit(0);
	    break;

	  case VERBOSE_OPT:
	    verbose = !clp->negated;
	    break;

	  case Clp_NotOption:
	    files.push_back(clp->vstr);
	    break;

	  case Clp_BadOption:
	    die_usage(0);
	    break;

	  case Clp_Done:
	    goto done;

	  default:
	    assert(opt >= FIRST_LOG_OPT);
	    log_contents.push_back(opt - FIRST_LOG_OPT);
	    if (opt == PAYLOAD_OPT || opt == PAYLOAD_MD5_OPT || opt == PAYLOAD_MD5_HEX_OPT)
		options.snaplen = 2000;
	    options.force_ip = true;
	    break;

	}
    }

  done:
    // check file usage
    if (!output)
	output = "-";
    if (output == "-" && write_dump == "-" && log_contents.size() > 0)
	p_errh->fatal("standard output used for both summary output and tcpdump output");

    // set random seed if appropriate
    if (do_seed && (options.do_sample || options.anonymize))
	click_random_srandom();

    // setup
    StringAccum sa;
    StringAccum script_sa;

    // clean up options
    if (action == 0)
	action = READ_DUMP_OPT;
    if (action == INTERFACE_OPT) {
	if (files.size() == 0)
	    p_errh->fatal("%<-i%> option requires at least one DEVNAME");
	else if (collate)
	    p_errh->fatal("%<--collate%> may not be used with %<--interface%>");
    }
    if (options.snaplen < 0)
	options.snaplen = (write_dump ? 2000 : 68);
    if (collate && files.size() < 2)
	collate = false;
    if (files.size() == 0)
	files.push_back("-");

    // source elements
    Vector<uint32_t> source_flags;
    uint32_t any_source_flags = 0;
    for (int i = 0; i < files.size(); i++) {
	options.filename = files[i];
	source_flags.push_back(add_source(sa, i, action, options));
	any_source_flags |= source_flags.back();
    }

    // collate source streams
    if (collate) {
	sa << "collate :: { tss :: TimeSortedSched(STOP true) -> Unqueue -> output;";
	for (int i = 0; i < files.size(); i++)
	    sa << " input [" << i << "] -> [" << i << "] tss;";
	sa << " };\n\n";
    } else {
	sa << "collate :: {";
	for (int i = 0; i < files.size(); i++)
	    sa << " input [" << i << "] -> output;";
	sa << " };\n\n";
    }

    // connect sources to collation
    for (int i = 0; i < files.size(); i++) {
	sa << "src" << i << " -> ";
	if (options.filter && !(source_flags[i] & Options::FILTERED) && (any_source_flags & Options::FILTERED))
	    sa << "IPFilter(0 " << options.filter << ") -> ";
	if (options.do_sample && !(source_flags[i] & Options::SAMPLED) && (any_source_flags & Options::SAMPLED))
	    sa << "samp" << i << " :: RandomSample(" << options.sample << ") -> ";
	sa << "[" << i << "] collate;\n";
    }

    // output path
    sa << "\ncollate\n";
    if (options.filter && !(any_source_flags & Options::FILTERED))
	sa << "  -> IPFilter(0 " << options.filter << ")\n";
    if (options.do_sample && !(any_source_flags & Options::SAMPLED))
	sa << "  -> samp0 :: RandomSample(" << options.sample << ")\n";
    if (options.anonymize)
	sa << "  -> anon :: AnonymizeIPAddr(CLASS 4, SEED false)\n";
    if (action != INTERFACE_OPT && interval) {
	sa << "  -> TimeFilter(INTERVAL " << interval << ", END_CALL manager.goto stop)\n";
	if (files.size() > 1 && !collate) {
	    p_errh->warning("%<--collate%> missing");
	    p_errh->message("(%<--interval%> works best with %<--collate%> when you have\nmultiple data sources.)");
	}
    }
    if (skip_packets || limit_packets) {
	const char *goswitch;
	sa << "  -> switch :: Switch\n";
	if (skip_packets) {
	    sa << "  -> Counter(COUNT_CALL " << skip_packets << " switch.switch 1) -> Discard;\n";
	    goswitch = "switch [1]";
	} else
	    goswitch = " ";
	if (limit_packets) {
	    sa << goswitch << " -> Counter(COUNT_CALL " << limit_packets << " switch_stop.run)\n";
	    script_sa << "switch_stop :: Script(TYPE PASSIVE, write switch.switch -1, write manager.goto stop);\n";
	} else
	    sa << goswitch;
    }

    // elements to write tcpdump file
    if (write_dump) {
	if (!write_dump_payload)
	    sa << "  -> TruncateIPPayload\n";
	sa << "  -> ToDump(" << write_dump << ", USE_ENCAP_FROM";
	for (int i = 0; i < files.size(); i++)
	    sa << " src" << i;
	sa << ", NANO " << write_dump_nano
           << ", SNAPLEN " << options.snaplen << ")\n";
    }

    // elements to dump summary log
    if (log_contents.size() == 0) {
	if (!write_dump) {
	    errh->warning("no dump content options, so I%,m not creating a summary dump");
	    sa << "  -> Discard;\n";
	}
	output = "";		// we're not using the normal output file
    } else {
	sa << "  -> to_dump :: ToIPSummaryDump(" << output << ", CONTENTS";
	for (int i = 0; i < log_contents.size(); i++)
	    sa << ' ' << cp_quote(field_names[log_contents[i]]);
	if (binary)
	    sa << ", BINARY true";
	if (action == READ_DUMP_OPT)
	    sa << ", CAREFUL_TRUNC false";
	sa << ", VERBOSE true, BAD_PACKETS " << bad_packets << ", BANNER ";
	// create banner
	StringAccum banner;
	for (int i = 0; i < argc; i++)
	    banner << argv[i] << ' ';
	banner.pop_back();
	sa << cp_quote(banner.take_string());
	if (!header)
	    sa << ", HEADER false";
	sa << ");\n";
	script_sa << "Script(TYPE SIGNAL HUP, write to_dump.flush);\n";
    }

    // record drops
    sa << "\n";
    if (record_drops)
	sa << "Script(wait " << record_drops << ", write record_counts, loop);\n";

    // progress bar
    if (!quiet) {
	sa << "progress :: ProgressBar(";
	for (int i = 0; i < files.size(); i++)
	    sa << "src" << i << ".filepos ";
	sa.pop_back();
	sa << ", ";
	for (int i = 0; i < files.size(); i++)
	    sa << "src" << i << ".filesize ";
	sa.pop_back();
	sa << ", UPDATE 0.1";
	if (!quiet_explicit)
	    sa << ", DELAY 2s";
	if (output == "-" || write_dump == "-")
	    sa << ", CHECK_STDOUT true";
	sa << ");\n";
    }

    // set-uid-root privilege
    if (geteuid() != getuid() || getegid() != getgid())
	sa << "ChangeUID();\n";

    sa << "manager :: DriverManager(";
    int stop_driver_count = 1;
    if (action != INTERFACE_OPT)
	stop_driver_count += files.size() + (collate ? 1 : 0);
    else {
	if (interval)
	    sa << ", wait " << interval;
	if (!interval || collate)
	    stop_driver_count++;
    }
    if (stop_driver_count > 1)
	sa << ", pause " << stop_driver_count - 1;
    // complete progress bar
    if (!quiet)
	sa << ", write progress.mark_done";
    sa << ", label stop";
    // print '!counts' message if appropriate
    if (action == INTERFACE_OPT)
	sa << ", write record_counts";
    sa << ");\n";

    sa << script_sa << "Script(TYPE SIGNAL INT TERM, write manager.goto stop, exit);\n";

    // output config if required
    if (config) {
	printf("%s", sa.c_str());
	exit(0);
    }

    // do NOT catch SIGPIPE; it kills us immediately

    Router::add_write_handler(0, "record_counts", record_drops_hook, 0);

    // lex configuration
    BailErrorHandler berrh(errh);
    PrefixErrorHandler verrh(&berrh, String::make_stable("{context:no}"));
    router = click_read_router(sa.take_string(), true, (verbose ? errh : &verrh));
    if (!router)
	exit(1);

    // output sample probability if appropriate
    if (options.do_sample) {
	String sample_elt = (source_flags[0] & Options::SAMPLED ? "src0" : "samp0");
	write_sampling_prob_message(router, sample_elt);
    }

    // run driver
    router->activate(errh);
    started = true;
    router->master()->thread(0)->driver();

    // print result of mapping addresses &/or prefixes
    if (map_prefixes.size()) {
	// collect results
	Vector<uint32_t> results;
	if (options.anonymize) {
	    Element *anon = router->find("anon");
	    assert(anon);
	    for (int i = 0; i < map_prefixes.size(); i += 2) {
		IPAddress addr(map_prefixes[i]);
		anon->local_llrpc(CLICK_LLRPC_MAP_IPADDRESS, addr.data());
		results.push_back(addr.addr());
	    }
	} else
	    for (int i = 0; i < map_prefixes.size(); i += 2)
		results.push_back(map_prefixes[i]);

	// then print results
	for (int i = 0; i < map_prefixes.size(); i += 2) {
	    IPAddress addr(map_prefixes[i]), mask(map_prefixes[i+1]),
		new_addr(results[i/2]);
	    addr &= mask;
	    new_addr &= mask;
	    if (mask == 0xFFFFFFFFU)
		fprintf(stderr, "%s -> %s\n", addr.unparse().c_str(), new_addr.unparse().c_str());
	    else
		fprintf(stderr, "%s -> %s\n", addr.unparse_with_mask(mask).c_str(), new_addr.unparse_with_mask(mask).c_str());
	}
    }

    // exit
    delete router;
    exit(0);
}
