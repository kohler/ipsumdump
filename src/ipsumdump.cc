// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * ipsumdump.cc -- driver for the ipsumdump program
 * Eddie Kohler
 *
 * Copyright (c) 2001-4 International Computer Science Institute
 * Copyright (c) 2004-5 Regents of the University of California
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
#include <sys/types.h>
#include <unistd.h>

#include "fromipsumdump.hh"
#include "toipsumdump.hh"
#include "fromdevice.hh"
#include <click/standard/drivermanager.hh>

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

// data sources
#define INTERFACE_OPT		400
#define READ_DUMP_OPT		401
#define READ_NETFLOW_SUMMARY_OPT 402
#define READ_IPSUMDUMP_OPT	403
#define READ_ASCII_TCPDUMP_OPT	404
#define IPSUMDUMP_FORMAT_OPT	405
#define READ_NLANR_DUMP_OPT	406
#define READ_DAG_DUMP_OPT	407
#define READ_DAG_PPP_DUMP_OPT	408

static const char* const field_names[] = {
    "timestamp", "first_timestamp", "ip_src", "ip_dst", // 0-4
    "sport", "dport", "ip_len", "ip_id",		// 5-7
    "ip_proto", "tcp_seq", "tcp_ack", "tcp_flags",	// 8-11
    "tcp_opt", "tcp_sack", "payload_len", "count",	// 12-15
    "ip_frag", "ip_fragoff", "payload", "ip_capture_len", // 16-19
    "link"						// 20
};

// options for logging
#define FIRST_LOG_OPT	1000
#define TIMESTAMP_OPT	1000
#define FIRST_TIMESTAMP_OPT 1001
#define SRC_OPT		1002
#define DST_OPT		1003
#define SPORT_OPT	1004
#define DPORT_OPT	1005
#define LENGTH_OPT	1006
#define IPID_OPT	1007
#define PROTO_OPT	1008
#define TCP_SEQ_OPT	1009
#define TCP_ACK_OPT	1010
#define TCP_FLAGS_OPT	1011
#define TCP_OPT_OPT	1012
#define TCP_SACK_OPT	1013
#define PAYLOAD_LEN_OPT	1014
#define COUNT_OPT	1015
#define FRAG_OPT	1016
#define FRAGOFF_OPT	1017
#define PAYLOAD_OPT	1018
#define IPCAPLEN_OPT	1019
#define LINK_OPT	1020

#define CLP_TIMESTAMP_TYPE	(Clp_FirstUserType)

static Clp_Option options[] = {

    { "help", 'h', HELP_OPT, 0, 0 },
    { "version", 'v', VERSION_OPT, 0, 0 },
    { "verbose", 'V', VERBOSE_OPT, 0, Clp_Negate },

    { "interface", 'i', INTERFACE_OPT, 0, 0 },
    { "tcpdump", 'r', READ_DUMP_OPT, 0, 0 },
    { "netflow-summary", 0, READ_NETFLOW_SUMMARY_OPT, 0, 0 },
    { "ipsumdump", 0, READ_IPSUMDUMP_OPT, 0, 0 },
    { "tcpdump-text", 0, READ_ASCII_TCPDUMP_OPT, 0, 0 },
    { "nlanr", 0, READ_NLANR_DUMP_OPT, 0, 0 },
    { "dag", 0, READ_DAG_DUMP_OPT, 0, 0 },
    { "dag-ppp", 0, READ_DAG_PPP_DUMP_OPT, 0, 0 },
    { "format", 0, IPSUMDUMP_FORMAT_OPT, Clp_ArgString, 0 },
    { "write-tcpdump", 'w', WRITE_DUMP_OPT, Clp_ArgString, 0 },
    { "filter", 'f', FILTER_OPT, Clp_ArgString, 0 },
    { "anonymize", 'A', ANONYMIZE_OPT, 0, Clp_Negate },
    { "binary", 'b', BINARY_OPT, 0, Clp_Negate },
    { "map-prefix", 0, MAP_PREFIX_OPT, Clp_ArgString, 0 },
    { "map-address", 0, MAP_PREFIX_OPT, Clp_ArgString, 0 },
    { "mmap", 0, MMAP_OPT, 0, Clp_Negate },
    { "multipacket", 0, MULTIPACKET_OPT, 0, Clp_Negate },
    { "sample", 0, SAMPLE_OPT, Clp_ArgDouble, Clp_Negate },
    { "collate", 0, COLLATE_OPT, 0, Clp_Negate },
    { "random-seed", 0, RANDOM_SEED_OPT, Clp_ArgUnsigned, 0 },
    { "promiscuous", 0, PROMISCUOUS_OPT, 0, Clp_Negate },
    { "record-counts", 0, WRITE_DROPS_OPT, Clp_ArgString, 0 },
    { "quiet", 'q', QUIET_OPT, 0, Clp_Negate },
    { "bad-packets", 0, BAD_PACKETS_OPT, 0, Clp_Negate },
    { "interval", 0, INTERVAL_OPT, CLP_TIMESTAMP_TYPE, 0 },
    { "limit-packets", 0, LIMIT_PACKETS_OPT, Clp_ArgUnsigned, Clp_Negate },

    { "output", 'o', OUTPUT_OPT, Clp_ArgString, 0 },
    { "config", 0, CONFIG_OPT, 0, 0 },

    { "timestamp", 't', TIMESTAMP_OPT, 0, 0 },
    { "first-timestamp", 'T', FIRST_TIMESTAMP_OPT, 0, 0 },
    { "src", 's', SRC_OPT, 0, 0 },
    { "dst", 'd', DST_OPT, 0, 0 },
    { "sport", 'S', SPORT_OPT, 0, 0 },
    { "dport", 'D', DPORT_OPT, 0, 0 },
    { "length", 'l', LENGTH_OPT, 0, 0 },
    { "id", 0, IPID_OPT, 0, 0 },
    { "protocol", 'p', PROTO_OPT, 0, 0 },
    { "tcp-seq", 'Q', TCP_SEQ_OPT, 0, 0 },
    { "tcp-ack", 'K', TCP_ACK_OPT, 0, 0 },
    { "tcp-flags", 'F', TCP_FLAGS_OPT, 0, 0 },
    { "tcp-opt", 'O', TCP_OPT_OPT, 0, 0 },
    { "tcp-sack", 0, TCP_SACK_OPT, 0, 0 },
    { "payload-length", 'L', PAYLOAD_LEN_OPT, 0, 0 },
    { "packet-count", 'c', COUNT_OPT, 0, 0 },
    { "fragment", 'g', FRAG_OPT, 0, 0 },
    { "fragoff", 'G', FRAGOFF_OPT, 0, 0 },
    { "fragment-offset", 0, FRAGOFF_OPT, 0, 0 },
    { "payload", 0, PAYLOAD_OPT, 0, 0 },
    { "capture-length", 0, IPCAPLEN_OPT, 0, 0 },
    { "link", 0, LINK_OPT, 0, 0 }

};

static const char *program_name;
static Router *router = 0;
static bool started = false;

void
die_usage(String specific = String())
{
    ErrorHandler *errh = ErrorHandler::default_handler();
    if (specific)
	errh->error("%s: %s", program_name, specific.c_str());
    errh->fatal("Usage: %s [-i | -r] [CONTENT OPTIONS] [DEVNAMES or FILES]...\n\
Try '%s --help' for more information.",
		program_name, program_name);
    // should not get here, but just in case...
    exit(1);
}

void
usage()
{
  printf("\
'Ipsumdump' reads IP packets from the tcpdump(1) files, or network interfaces,\n\
and summarizes their contents in an ASCII log.\n\
\n\
Usage: %s [CONTENT OPTIONS] [-i DEVNAMES | FILES] > LOGFILE\n\
\n\
Options that determine summary dump contents (can give multiple options):\n\
  -t, --timestamp            Include packet timestamps.\n\
  -T, --first-timestamp      Include flow-begin timestamps.\n\
  -s, --src                  Include IP source addresses.\n\
  -d, --dst                  Include IP destination addresses.\n\
  -S, --sport                Include TCP/UDP source ports.\n\
  -D, --dport                Include TCP/UDP destination ports.\n\
  -l, --length               Include IP lengths.\n\
  -p, --protocol             Include IP protocols.\n\
      --id                   Include IP IDs.\n\
  -g, --fragment             Include IP fragment flags ('F' or '.').\n\
  -G, --fragment-offset      Include IP fragment offsets.\n\
  -F, --tcp-flags            Include TCP flags word.\n\
  -Q, --tcp-seq              Include TCP sequence numbers.\n\
  -K, --tcp-ack              Include TCP acknowledgement numbers.\n\
  -O, --tcp-opt              Include TCP options.\n\
      --tcp-sack             Include TCP selective acknowledgement options.\n\
  -L, --payload-length       Include payload lengths (no IP/UDP/TCP headers).\n\
      --payload              Include packet payloads as quoted strings.\n\
      --capture-length       Include lengths of captured IP data.\n\
  -c, --packet-count         Include packet counts (usually 1).\n\
      --link                 Include link numbers (NLANR/NetFlow).\n\
\n", program_name);
  printf("\
Data source options (give exactly one):\n\
  -r, --tcpdump              Read packets from tcpdump(1) FILES (default).\n\
      --netflow-summary      Read summarized NetFlow FILES.\n\
      --ipsumdump            Read from existing ipsumdump FILES.\n\
      --format FORMAT        Read ipsumdump FILES with format FORMAT.\n\
      --tcpdump-text         Read packets from tcpdump(1) text output FILES.\n\
      --nlanr                Read packets from NLANR-format FILES (fr/fr+/tsh).\n\
      --dag                  Read packets from DAG-format FILES.\n\
      --dag-ppp              Read packets from DAG-format FILES with PPP encap.\n\
  -i, --interface            Read packets from network devices DEVNAMES until\n\
                             interrupted.\n\
\n");
  printf("\
Other options:\n\
  -o, --output FILE          Write summary dump to FILE (default stdout).\n\
  -w, --write-tcpdump FILE   Also dump packets to FILE in tcpdump(1) format.\n\
  -b, --binary               Create binary output file.\n\
  -f, --filter FILTER        Apply tcpdump(1) filter FILTER to data.\n\
  -A, --anonymize            Anonymize IP addresses (preserves prefix & class).\n\
      --no-promiscuous       Do not put interfaces into promiscuous mode.\n\
      --bad-packets          Print '!bad' messages for bad headers.\n\
      --sample PROB          Sample packets with PROB probability.\n\
      --multipacket          Produce multiple entries for a flow identifier\n\
                             representing multiple packets (NetFlow only).\n");
  printf("\
      --collate              Collate packets from data sources by timestamp.\n\
      --interval TIME        Stop after TIME has elapsed in trace time.\n\
      --limit-packets N      Stop after processing N packets.\n\
      --map-address ADDRS    When done, print to stderr the anonymized IP\n\
                             addresses and/or prefixes corresponding to ADDRS.\n\
      --record-counts TIME   Record packet counts every TIME seconds in output.\n\
      --random-seed SEED     Set random seed to SEED (default is random).\n\
      --no-mmap              Don't memory-map input files.\n\
  -q, --quiet                Do not print progress bar.\n\
      --config               Output Click configuration and exit.\n\
  -V, --verbose              Report errors verbosely.\n\
  -h, --help                 Print this message and exit.\n\
  -v, --version              Print version number and exit.\n\
\n\
Report bugs to <kohler@cs.ucla.edu>.\n");
}

// Stop the driver this many aggregate times to end the program.
static int stop_driver_count = 1;

static void
catch_signal(int sig)
{
    signal(sig, SIG_DFL);
    if (!started)
	kill(getpid(), sig);
    else {
	DriverManager *dm = (DriverManager *)(router->attachment("DriverManager"));
	router->set_runcount(dm->stopped_count() - stop_driver_count);
    }
}

static void
catch_sighup(int sig)
{
    if (!started) {
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
    } else {
	signal(sig, catch_sighup);
	ToIPSummaryDump* td = static_cast<ToIPSummaryDump*>(router->find("to_dump"));
	if (td)
	    td->flush_buffer();
    }
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
	    td->write_line("!sampling_prob " + s);
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
stop_hook(const String &s_in, Element *, void *, ErrorHandler *errh)
{
    int n = 1;
    String s = cp_uncomment(s_in);
    DriverManager *dm = (DriverManager *)(router->attachment("DriverManager"));
    if (!s || cp_integer(s, &n))
	router->adjust_runcount(-n);
    else if (s == "cold")
	router->set_runcount(dm->stopped_count() - stop_driver_count);
    else if (s == "switch") {
	HandlerCall::call_write(router->find("switch/s"), "switch", "1", errh);
	router->set_runcount(dm->stopped_count() - stop_driver_count);
    } else
	return errh->error("bad argument to 'stop'");
    return 0;
}

static String
source_output_port(bool collate, int i)
{
    if (collate)
	return "[" + String(i) + "]collate";
    else
	return "shunt";
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
    String filter;
    String ipsumdump_format;
    Vector<uint32_t> map_prefixes;
    bool config = false;
    bool verbose = false;
    bool anonymize = false;
    bool multipacket = false;
    double sample = 0;
    bool do_sample = false;
    bool collate = false;
    Vector<int> log_contents;
    int action = 0;
    bool do_seed = true;
    bool promisc = true;
    bool quiet = false;
    bool quiet_explicit = false;
    bool bad_packets = false;
    bool binary = false;
    int snaplen = -1;
    Vector<String> files;
    const char *record_drops = 0;
    unsigned limit_packets = 0;
    int mmap = -1;
    Timestamp interval;
    
    while (1) {
	int opt = Clp_Next(clp);
	switch (opt) {

	  case OUTPUT_OPT:
	    if (output)
		die_usage("'--output' already specified");
	    output = clp->arg;
	    break;
	    
	  case INTERFACE_OPT:
	  case READ_DUMP_OPT:
	  case READ_NETFLOW_SUMMARY_OPT:
	  case READ_IPSUMDUMP_OPT:
	  case READ_ASCII_TCPDUMP_OPT:
	  case READ_DAG_DUMP_OPT:
	  case READ_DAG_PPP_DUMP_OPT:
	  case READ_NLANR_DUMP_OPT:
	    if (action)
		die_usage("data source option already specified");
	    action = opt;
	    break;
	    
	  case IPSUMDUMP_FORMAT_OPT:
	    if (ipsumdump_format)
		die_usage("'--format' already specified");
	    else if (action && action != READ_IPSUMDUMP_OPT)
		die_usage("'--format' only useful with '--ipsumdump'");
	    action = READ_IPSUMDUMP_OPT;
	    ipsumdump_format = clp->arg;
	    break;
	    
	  case WRITE_DUMP_OPT:
	    if (write_dump)
		die_usage("'--write-tcpdump' already specified");
	    write_dump = clp->arg;
	    break;

	  case FILTER_OPT:
	    if (filter)
		die_usage("'--filter' already specified");
	    filter = clp->arg;
	    break;

	  case ANONYMIZE_OPT:
	    anonymize = !clp->negated;
	    break;

	  case MULTIPACKET_OPT:
	    multipacket = !clp->negated;
	    break;

	  case PROMISCUOUS_OPT:
	    promisc = !clp->negated;
	    break;

	  case WRITE_DROPS_OPT:
	    record_drops = clp->arg;
	    break;

	  case LIMIT_PACKETS_OPT:
	    limit_packets = (clp->negated ? 0 : clp->val.u);
	    break;

	  case BINARY_OPT:
	    binary = !clp->negated;
	    break;

	  case MAP_PREFIX_OPT: {
	      String arg(clp->arg);
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
		      die_usage("can't parse '" + v[i] + "' as an IP address (" + String(Clp_CurOptionName(clp)) + ")");
		  map_prefixes.push_back(addr.addr());
		  map_prefixes.push_back(mask.addr());
	      }
	      break;
	  }

	  case SAMPLE_OPT:
	    if (clp->negated)
		do_sample = false;
	    else {
		do_sample = true;
		if (clp->val.d < 0 || clp->val.d > 1)
		    die_usage("'--sample' probability must be between 0 and 1");
		sample = clp->val.d;
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
	    mmap = !clp->negated;
	    break;
	    
	  case CONFIG_OPT:
	    config = true;
	    break;
	    
	  case HELP_OPT:
	    usage();
	    exit(0);
	    break;

	  case VERSION_OPT:
	    printf("Ipsumdump %s (libclick-%s)\n", IPSUMDUMP_VERSION, CLICK_VERSION);
	    printf("Copyright (c) 2001-2003 International Computer Science Institute\n\
Copyright (c) 2004-2005 Regents of the University of California\n\
This is free software; see the source for copying conditions.\n\
There is NO warranty, not even for merchantability or fitness for a\n\
particular purpose.\n");
	    exit(0);
	    break;

	  case VERBOSE_OPT:
	    verbose = !clp->negated;
	    break;

	  case Clp_NotOption:
	    files.push_back(cp_quote(clp->arg));
	    break;
	    
	  case Clp_BadOption:
	    die_usage();
	    break;

	  case Clp_Done:
	    goto done;

	  default:
	    assert(opt >= FIRST_LOG_OPT);
	    log_contents.push_back(opt - FIRST_LOG_OPT);
	    if (opt == PAYLOAD_OPT)
		snaplen = 2000;
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
    if (do_seed && (do_sample || anonymize))
	click_random_srandom();

    // setup
    String shunt_internals = "";
    StringAccum psa;
    String sample_elt;
    if (snaplen < 0)
	snaplen = (write_dump ? 2000 : 68);
    if (collate && files.size() < 2)
	collate = false;
    
    // elements to read packets
    if (action == 0)
	action = READ_DUMP_OPT;
    if (action == INTERFACE_OPT) {
	if (files.size() == 0)
	    p_errh->fatal("'-i' option takes at least one DEVNAME");
	if (collate)
	    p_errh->fatal("'--collate' may not be used with '--interface' yet");
	String config = ", SNIFFER true, SNAPLEN " + String(snaplen) + ", FORCE_IP true";
	if (promisc)
	    config += ", PROMISC true";
#if FROMDEVICE_PCAP
	if (filter)
	    config += ", BPF_FILTER " + cp_quote(filter);
	filter = String();
#endif
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromDevice(" << files[i] << config << ") -> " << source_output_port(collate, i) << ";\n";
	if (do_sample) {
	    shunt_internals = " -> samp :: RandomSample(" + String(sample) + ")";
	    sample_elt = "shunt/samp";
	}
	quiet = true;		// does not support filepos handlers
	
    } else if (action == READ_DUMP_OPT || action == READ_NLANR_DUMP_OPT
	       || action == READ_DAG_DUMP_OPT || action == READ_DAG_PPP_DUMP_OPT) {
	String eclass = (action == READ_DUMP_OPT ? "FromDump" : (action == READ_NLANR_DUMP_OPT ? "FromNLANRDump" : "FromDAGDump"));
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", FORCE_IP true, STOP true";
	if (do_sample)
	    config += ", SAMPLE " + String(sample);
	if (mmap >= 0)
	    config += ", MMAP " + String(mmap);
	if (action == READ_DAG_PPP_DUMP_OPT)
	    config += ", ENCAP PPP";
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: " << eclass << "(" << files[i] << config << ") -> " << source_output_port(collate, i) << ";\n";
	sample_elt = "src0";
	
    } else if (action == READ_ASCII_TCPDUMP_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", STOP true";
	if (do_sample)
	    config += ", SAMPLE " + String(sample);
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromTcpdump(" << files[i] << config << ") -> " << source_output_port(collate, i) << ";\n";
	sample_elt = "src0";
	
    } else if (action == READ_NETFLOW_SUMMARY_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", STOP true, ZERO true";
	if (multipacket)
	    config += ", MULTIPACKET true";
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromNetFlowSummaryDump(" << files[i] << config << ") -> " << source_output_port(collate, i) << ";\n";
	if (do_sample) {
	    shunt_internals = " -> samp :: RandomSample(" + String(sample) + ")";
	    sample_elt = "shunt/samp";
	    if (!multipacket)
		p_errh->warning("'--sample' option will sample flows, not packets\n(If you want to sample packets, use '--multipacket'.)");
	}
	
    } else if (action == READ_IPSUMDUMP_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", STOP true, ZERO true";
	if (do_sample)
	    config += ", SAMPLE " + String(sample);
	if (multipacket)
	    config += ", MULTIPACKET true";
	if (ipsumdump_format)
	    config += ", DEFAULT_CONTENTS " + ipsumdump_format;
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromIPSummaryDump(" << files[i] << config << ") -> " << source_output_port(collate, i) << ";\n";
	sample_elt = "src0";
	
    } else
	die_usage("must supply a data source option");

    // print collation/shunt
    StringAccum sa;
    sa << "shunt :: { input" << shunt_internals << " -> output };\n";
    if (collate)
	sa << "collate :: TimeSortedSched(STOP true) -> Unqueue -> shunt;\n";
    sa << psa;
    
    // possible elements to filter and/or anonymize and/or stop
    sa << "shunt\n";
    if (filter)
	sa << "  -> IPFilter(0 " << filter << ")\n";
    if (anonymize)
	sa << "  -> anon :: AnonymizeIPAddr(CLASS 4, SEED false)\n";
    if (action != INTERFACE_OPT && interval) {
	sa << "  -> TimeFilter(INTERVAL " << interval << ", END_CALL stop cold)\n";
	if (files.size() > 1 && !collate) {
	    p_errh->warning("'--collate' missing");
	    p_errh->message("('--interval' works best with '--collate' when you have\nmultiple data sources.)");
	}
    }
    if (limit_packets)
	sa << "  -> switch :: { input -> s :: Switch -> output; s[1] -> Discard }\n"
	   << "  -> Counter(COUNT_CALL " << limit_packets << " stop switch)\n";

    // elements to write tcpdump file
    if (write_dump) {
	sa << "  -> ToDump(" << write_dump << ", USE_ENCAP_FROM";
	for (int i = 0; i < files.size(); i++)
	    sa << " src" << i;
	sa << ", SNAPLEN " << snaplen << ")\n";
    }
    
    // elements to dump summary log
    if (log_contents.size() == 0) {
	if (!write_dump) {
	    errh->warning("no dump content options, so I'm not creating a summary dump");
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
	sa << cp_quote(banner.take_string()) << ");\n";
    }

    // record drops
    if (record_drops)
	sa << "PokeHandlers(" << record_drops << ", record_counts '', loop);\n";

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

    sa << "DriverManager(";
    stop_driver_count = 1;
    if (action != INTERFACE_OPT)
	stop_driver_count += files.size() + (collate ? 1 : 0);
    else {
	if (interval)
	    sa << ", wait_for " << interval;
	if (!interval || collate)
	    stop_driver_count++;
    }
    if (stop_driver_count > 1)
	sa << ", wait_stop " << stop_driver_count - 1;
    // complete progress bar
    if (!quiet)
	sa << ", write_skip progress.mark_done";
    // print '!counts' message if appropriate
    if (action == INTERFACE_OPT)
	sa << ", write record_counts ''";
    sa << ");\n";

    // output config if required
    if (config) {
	printf("%s", sa.cc());
	exit(0);
    }

    // catch control-C
    signal(SIGINT, catch_signal);
    signal(SIGTERM, catch_signal);
    signal(SIGHUP, catch_sighup);
    // do NOT catch SIGPIPE; it kills us immediately

    Router::add_write_handler(0, "record_counts", record_drops_hook, 0);
    Router::add_write_handler(0, "stop", stop_hook, 0);

    // lex configuration
    BailErrorHandler berrh(errh);
    VerboseFilterErrorHandler verrh(&berrh, ErrorHandler::ERRVERBOSITY_CONTEXT + 1);
    router = click_read_router(sa.take_string(), true, (verbose ? errh : &verrh));
    if (!router)
	exit(1);
    
    // output sample probability if appropriate
    if (do_sample)
	write_sampling_prob_message(router, sample_elt);
    
    // run driver
    router->activate(errh);
    started = true;
    router->master()->thread(0)->driver();

    // print result of mapping addresses &/or prefixes
    if (map_prefixes.size()) {
	// collect results
	Vector<uint32_t> results;
	if (anonymize) {
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
		fprintf(stderr, "%s -> %s\n", addr.unparse().cc(), new_addr.unparse().cc());
	    else
		fprintf(stderr, "%s -> %s\n", addr.unparse_with_mask(mask).cc(), new_addr.unparse_with_mask(mask).cc());
	}
    }
    
    // exit
    delete router;
    exit(0);
}
