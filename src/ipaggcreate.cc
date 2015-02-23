// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * ipsumdump.cc -- driver for the ipsumdump program
 * Eddie Kohler
 *
 * Copyright (c) 2001-2004 International Computer Science Institute
 * Copyright (c) 2004-2008 Regents of the University of California
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
#include <click/straccum.hh>
#include <click/handlercall.hh>
#include <click/variableenv.hh>
#include <click/master.hh>
#include "aggcounter.hh"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#define HELP_OPT		300
#define VERSION_OPT		301
#define OUTPUT_OPT		302
#define CONFIG_OPT		303
#define WRITE_DUMP_OPT		304
#define FILTER_OPT		305
#define VERBOSE_OPT		306
#define ANONYMIZE_OPT		307
#define MULTIPACKET_OPT		309
#define SAMPLE_OPT		310
#define COLLATE_OPT		311
#define RANDOM_SEED_OPT		312
#define PROMISCUOUS_OPT		313
#define INTERVAL_OPT		315
#define TIME_OFFSET_OPT		316
#define BINARY_OPT		317
#define START_TIME_OPT		318
#define QUIET_OPT		319

// data sources
#define INTERFACE_OPT		400
#define READ_DUMP_OPT		401
#define READ_NETFLOW_SUMMARY_OPT 402
#define READ_IPSUMDUMP_OPT	403
#define READ_ASCII_TCPDUMP_OPT	404
#define READ_NLANR_DUMP_OPT	405
#define READ_DAG_DUMP_OPT	406
#define READ_DAG_PPP_DUMP_OPT	407
#define READ_TUDUMP_OPT		408
#define READ_IPADDR_OPT		409
#define READ_BROCONN_OPT	410
#define IPSUMDUMP_FORMAT_OPT	450

// aggregates
#define AGG_SRC_OPT		500
#define AGG_DST_OPT		501
#define AGG_LENGTH_OPT		502
#define AGG_FLOWS_OPT		503
#define AGG_UNI_FLOWS_OPT	504
#define AGG_ADDRPAIR_OPT	505
#define AGG_UNI_ADDRPAIR_OPT	506
#define AGG_IP_OPT		507

#define AGG_BYTES_OPT		600
#define AGG_PACKETS_OPT		601
#define LIMIT_AGG_OPT		602
#define SPLIT_AGG_OPT		603
#define SPLIT_TIME_OPT		604
#define SPLIT_PACKETS_OPT	605
#define SPLIT_BYTES_OPT		606

#define CLP_TIMESTAMP_TYPE	(Clp_ValFirstUser)

static const Clp_Option options[] = {

    { "help", 'h', HELP_OPT, 0, 0 },
    { "version", 'v', VERSION_OPT, 0, 0 },
    { "verbose", 'V', VERBOSE_OPT, 0, Clp_Negate },

    { "interface", 'i', INTERFACE_OPT, 0, 0 },
    { "tcpdump", 'r', READ_DUMP_OPT, 0, 0 },
    { "ipsumdump", 0, READ_IPSUMDUMP_OPT, 0, 0 },
    { "format", 0, IPSUMDUMP_FORMAT_OPT, Clp_ValString, 0 },
    { "nlanr", 0, READ_NLANR_DUMP_OPT, 0, 0 },
    { "dag", 0, READ_DAG_DUMP_OPT, Clp_ValString, Clp_Optional },
    { "dag-ppp", 0, READ_DAG_PPP_DUMP_OPT, 0, 0 },
    { "tu-summary", 0, READ_TUDUMP_OPT, 0, 0 },
    { "ip-addresses", 0, READ_IPADDR_OPT, 0, 0 },
    { "bro-conn-summary", 0, READ_BROCONN_OPT, 0, 0 },
    { "netflow-summary", 0, READ_NETFLOW_SUMMARY_OPT, 0, 0 },
    { "tcpdump-text", 0, READ_ASCII_TCPDUMP_OPT, 0, 0 },

    { "write-tcpdump", 'w', WRITE_DUMP_OPT, Clp_ValString, 0 },
    { "filter", 'f', FILTER_OPT, Clp_ValString, 0 },
    { "anonymize", 'A', ANONYMIZE_OPT, 0, Clp_Negate },
    { "binary", 'b', BINARY_OPT, 0, Clp_Negate },
    { "multipacket", 0, MULTIPACKET_OPT, 0, Clp_Negate },
    { "sample", 0, SAMPLE_OPT, Clp_ValDouble, Clp_Negate },
    { "collate", 0, COLLATE_OPT, 0, Clp_Negate },
    { "random-seed", 0, RANDOM_SEED_OPT, Clp_ValUnsigned, 0 },
    { "promiscuous", 0, PROMISCUOUS_OPT, 0, Clp_Negate },
    { "quiet", 'q', QUIET_OPT, 0, Clp_Negate },

    { "output", 'o', OUTPUT_OPT, Clp_ValString, 0 },
    { "config", 0, CONFIG_OPT, 0, 0 },

    { "src", 's', AGG_SRC_OPT, 0, 0 },
    { "dst", 'd', AGG_DST_OPT, 0, 0 },
    { "length", 'l', AGG_LENGTH_OPT, 0, 0 },
    { "ip", 0, AGG_IP_OPT, Clp_ValString, 0 },
    { "flows", 0, AGG_FLOWS_OPT, 0, 0 },
    { "unidirectional-flows", 0, AGG_UNI_FLOWS_OPT, 0, 0 },
    { "uni-flows", 0, AGG_UNI_FLOWS_OPT, 0, 0 },
    { "address-pairs", 0, AGG_ADDRPAIR_OPT, 0, 0 },
    { "unidirectional-address-pairs", 0, AGG_UNI_ADDRPAIR_OPT, 0, 0 },
    { "uni-address-pairs", 0, AGG_UNI_ADDRPAIR_OPT, 0, 0 },

    { "packets", 0, AGG_PACKETS_OPT, 0, 0 },
    { "bytes", 'B', AGG_BYTES_OPT, 0, 0 },
    { "time-offset", 'T', TIME_OFFSET_OPT, CLP_TIMESTAMP_TYPE, 0 },
    { "interval", 't', INTERVAL_OPT, CLP_TIMESTAMP_TYPE, 0 },
    { "start-time", 0, START_TIME_OPT, CLP_TIMESTAMP_TYPE, 0 },
    { "limit-aggregates", 0, LIMIT_AGG_OPT, Clp_ValUnsigned, 0 },
    { "limit-labels", 0, LIMIT_AGG_OPT, Clp_ValUnsigned, 0 },
    { "split-aggregates", 0, SPLIT_AGG_OPT, Clp_ValUnsigned, 0 },
    { "split-labels", 0, SPLIT_AGG_OPT, Clp_ValUnsigned, 0 },
    { "split-time", 0, SPLIT_TIME_OPT, CLP_TIMESTAMP_TYPE, 0 },
    { "split-packets", 0, SPLIT_PACKETS_OPT, Clp_ValUnsigned, 0 },
    { "split-count", 0, SPLIT_PACKETS_OPT, Clp_ValUnsigned, 0 },
    { "split-bytes", 0, SPLIT_BYTES_OPT, Clp_ValUnsigned, 0 },

};

static const char *program_name;

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
Try %<%s --help%> for more information.",
		program_name, program_name);
    // should not get here, but just in case...
    exit(1);
}

void
usage()
{
    printf("\
'Ipaggcreate' reads IP packets from tcpdump(1) or other packet traces, labels\n\
each packet, and outputs a simply-formatted \"aggregate\" file that reports the\n\
number of packets or bytes observed per label.\n\
\n\
Usage: %s [OPTIONS] [-i DEVNAMES | FILES] > AGGFILE\n\
\n\
Label options (give exactly one):\n\
  -s, --src                  Label by IP source address.\n\
  -d, --dst                  Label by IP destination address (default).\n\
  -l, --length               Label by IP length.\n\
      --ip FIELD             Label by IP FIELD (ex: 'ip src/8', 'ip ttl').\n\
      --flows                Label by flow ID (label number meaningless).\n\
      --unidirectional-flows Label by unidirectional flow ID.\n\
      --address-pairs        Label by IP address pair.\n\
      --unidirectional-address-pairs  Label by ordered IP address pair.\n\
\n", program_name);
    printf("\
Measurement options:\n\
      --packets              Count packets (default).\n\
  -B, --bytes                Count bytes.\n\
\n");
    printf("\
Data source options (give exactly one):\n\
  -r, --tcpdump              Read tcpdump(1) FILES (default).\n\
  -i, --interface            Read network devices DEVNAMES until interrupted.\n\
      --ipsumdump            Read ipsumdump FILES.\n\
      --format FORMAT        Read ipsumdump FILES with format FORMAT.\n\
      --dag[=ENCAP]          Read DAG-format FILES.\n\
      --nlanr                Read NLANR-format FILES (fr/fr+/tsh).\n\
      --ip-addresses         Read a list of IP addresses, one per line.\n\
      --tu-summary           Read TU summary dump FILES.\n\
      --bro-conn-summary     Read Bro connection summary FILES.\n\
      --netflow-summary      Read summarized NetFlow FILES.\n\
      --tcpdump-text         Read tcpdump(1) text output FILES.\n\
\n");
    printf("\
Limit and split options:\n\
  -T, --time-offset TIME     Ignore first TIME in input.\n\
      --start-time TIME      Ignore packets with timestamps before TIME.\n\
  -t, --interval TIME        Output TIME worth of packets. Example: '1hr'.\n\
      --limit-labels K       Stop once K distinct labels are encountered.\n\
      --split-time TIME      Output new file every TIME worth of packets.\n\
      --split-labels K       Output new file every K distinct labels.\n\
      --split-packets N      Output new file every N packets.\n\
      --split-bytes N        Output new file every N bytes.\n\
\n");
    printf("\
Other options:\n\
  -o, --output FILE          Write summary dump to FILE (default stdout).\n\
  -b, --binary               Output aggregate file in binary.\n\
  -w, --write-tcpdump FILE   Also dump packets to FILE in tcpdump(1) format.\n\
  -f, --filter FILTER        Apply tcpdump(1) filter FILTER to data.\n\
  -A, --anonymize            Anonymize IP addresses (preserves prefix & class).\n\
      --no-promiscuous       Do not put interfaces into promiscuous mode.\n\
      --sample PROB          Sample packets with PROB probability.\n\
      --multipacket          Produce multiple entries for a flow identifier\n\
                             representing multiple packets (NetFlow only).\n\
      --collate              Collate packets from data sources by timestamp.\n\
      --random-seed SEED     Set random seed to SEED (default is random).\n\
  -q, --quiet                Do not print progress bar.\n\
      --config               Output Click configuration and exit.\n\
  -V, --verbose              Report errors verbosely.\n\
  -h, --help                 Print this message and exit.\n\
  -v, --version              Print version number and exit.\n\
\n\
Report bugs to <kohler@cs.ucla.edu>.\n");
}

static int
parse_timestamp(Clp_Parser *clp, const char *arg, int complain, void *)
{
    if (cp_time(arg, (Timestamp *)&clp->val))
	return 1;
    else if (complain)
	return Clp_OptionError(clp, "%<%O%> expects a time value, not %<%s%>", arg);
    else
	return 0;
}

static StringAccum banner_sa;

static String output;
static int multi_output = -1;
static Vector<String> output_calls;
static bool binary = false;
static bool collate = false;

static bool
check_multi_output(const String &s)
{
    bool percent_d = false;
    int pos = 0;
    while ((pos = s.find_left('%', pos)) >= 0) {
	for (pos++; pos < s.length() && isdigit(s[pos]); pos++)
	    /* nada */;
	if (pos >= s.length())
	    return false;
	else if (s[pos] == 'd' || s[pos] == 'i' || s[pos] == 'x' || s[pos] == 'X') {
	    if (percent_d)
		return false;
	    percent_d = true;
	} else if (s[pos] == '%')
	    pos++;
	else
	    return false;
    }
    return percent_d;
}



struct Options {
    bool anonymize;
    bool multipacket;
    double sample;
    bool do_sample;
    bool promisc;
    bool bad_packets;
    bool mirror;
    int mmap;
    int snaplen;
    String filter;
    String filename;
    String ipsumdump_format;
    String dag_encap;
    String time_config;
    Timestamp split_time;
    int nfiles;

    enum { SAMPLED = 1, FILTERED = 2, TIMED = 4, MIRRORED = 8 };
};

static uint32_t
add_source(StringAccum &sa, int num, int action, const Options &opt)
{
    uint32_t result = 0;
    sa << "src" << num << " :: ";

    switch (action) {

      case INTERFACE_OPT:
	sa << "FromDevice(" << cp_quote(opt.filename)
	   << ", SNIFFER true, SNAPLEN " << opt.snaplen << ", FORCE_IP true";
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
	sa << ", FORCE_IP true, STOP true";
	if (opt.do_sample && !opt.mirror) {
	    sa << ", SAMPLE " << opt.sample;
	    result |= Options::SAMPLED;
	}
	if (opt.time_config && opt.nfiles == 1) {
	    sa << ", " << opt.time_config;
	    result |= Options::TIMED;
	}
	if (opt.mmap >= 0)
	    sa << ", MMAP " << opt.mmap;
	sa << ");\n";
	return result;

      case READ_ASCII_TCPDUMP_OPT:
	sa << "FromTcpdump(" << cp_quote(opt.filename) << ", STOP true";
	if (opt.do_sample && !opt.mirror) {
	    sa << ", SAMPLE " << opt.sample;
	    result |= Options::SAMPLED;
	}
	sa << ");\n";
	return result;

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
	if (opt.do_sample && !opt.mirror) {
	    sa << ", SAMPLE " << opt.sample;
	    result |= Options::SAMPLED;
	}
	if (opt.multipacket)
	    sa << ", MULTIPACKET true";
	if (opt.ipsumdump_format)
	    sa << ", CONTENTS " << opt.ipsumdump_format;
	sa << ");\n";
	return result;

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
    //String output;
    String agg;
    bool agg_flows = false;
    bool agg_flows_addrpair = false;
    bool agg_bidi = true;
    String aggctr_pb;
    uint32_t aggctr_limit_nnz = 0;
    uint32_t aggctr_limit_count = 0;
    uint32_t aggctr_limit_bytes = 0;
    bool config = false;
    bool verbose = false;
    //bool collate;
    int action = 0;
    bool do_seed = true;
    bool quiet = false;
    //bool binary;
    Vector<String> files;
    Timestamp time_offset;
    Timestamp interval;
    Timestamp start_time;

    Options options;
    options.anonymize = options.multipacket = options.do_sample = options.mirror = false;
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
	  case READ_IPSUMDUMP_OPT:
	  case READ_ASCII_TCPDUMP_OPT:
	  case READ_DAG_PPP_DUMP_OPT:
	  case READ_NLANR_DUMP_OPT:
	  case READ_TUDUMP_OPT:
	  case READ_IPADDR_OPT:
	  case READ_BROCONN_OPT:
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
		die_usage("%<--format%> already specified");
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

	  case FILTER_OPT:
	    if (options.filter)
		die_usage("%<--filter%> already specified");
	    options.filter = clp->vstr;
	    break;

	  case ANONYMIZE_OPT:
	    options.anonymize = !clp->negated;
	    break;

	  case MULTIPACKET_OPT:
	    options.multipacket = !clp->negated;
	    break;

	  case PROMISCUOUS_OPT:
	    options.promisc = !clp->negated;
	    break;

	  case BINARY_OPT:
	    binary = !clp->negated;
	    break;

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
	    break;

	  case TIME_OFFSET_OPT:
	    time_offset = *((const Timestamp *)&clp->val);
	    break;

	  case START_TIME_OPT:
	    start_time = *((const Timestamp *)&clp->val);
	    break;

	  case INTERVAL_OPT:
	    interval = *((const Timestamp *)&clp->val);
	    break;

	  case AGG_SRC_OPT:
	    if (agg || agg_flows)
		die_usage("aggregate specified twice");
	    agg = "ip src";
	    break;

	  case AGG_DST_OPT:
	    if (agg || agg_flows)
		die_usage("aggregate specified twice");
	    agg = "ip dst";
	    break;

	  case AGG_LENGTH_OPT:
	    if (agg || agg_flows)
		die_usage("aggregate specified twice");
	    agg = "ip len";
	    break;

	  case AGG_IP_OPT:
	    if (agg || agg_flows)
		die_usage("aggregate specified twice");
	    agg = clp->vstr;
	    break;

	  case AGG_FLOWS_OPT:
	  case AGG_UNI_FLOWS_OPT:
	  case AGG_ADDRPAIR_OPT:
	  case AGG_UNI_ADDRPAIR_OPT:
	    if (agg || agg_flows)
		die_usage("aggregate specified twice");
	    agg_flows = true;
	    agg_flows_addrpair = (opt == AGG_ADDRPAIR_OPT || opt == AGG_UNI_ADDRPAIR_OPT);
	    agg_bidi = (opt == AGG_FLOWS_OPT || opt == AGG_ADDRPAIR_OPT);
	    break;

	  case AGG_BYTES_OPT:
	  case AGG_PACKETS_OPT:
	    if (aggctr_pb)
		die_usage("%<--bytes%> or %<--packets%> specified twice");
	    aggctr_pb = "BYTES " + cp_unparse_bool(opt == AGG_BYTES_OPT);
	    break;

	  case LIMIT_AGG_OPT:
	    aggctr_limit_nnz = clp->val.u;
	    break;

	  case SPLIT_AGG_OPT:
	    aggctr_limit_nnz = clp->val.u;
	    goto multi_output;

	  case SPLIT_PACKETS_OPT:
	    aggctr_limit_count = clp->val.u;
	    goto multi_output;

	  case SPLIT_BYTES_OPT:
	    aggctr_limit_bytes = clp->val.u;
	    goto multi_output;

	  case SPLIT_TIME_OPT:
	    options.split_time = *((const Timestamp *)&clp->val);
	    goto multi_output;

	  multi_output:
	    if (multi_output >= 0)
		die_usage("supply at most one of the %<--split%> options");
	    multi_output = 0;
	    break;

	  case CONFIG_OPT:
	    config = true;
	    break;

	  case HELP_OPT:
	    usage();
	    exit(0);
	    break;

	  case VERSION_OPT:
	    printf("Ipaggcreate %s (libclick-%s)\n", IPSUMDUMP_VERSION, CLICK_VERSION);
	    printf("Copyright (c) 2001-2014 Eddie Kohler\n\
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
	    die_usage(0);
	    break;

	}
    }

  done:
    // check file usage
    if (!output)
	output = "-";
    if (multi_output >= 0 && !check_multi_output(output))
	p_errh->fatal("When generating multiple files, you must supply %<--output%>,\nwhich should contain exactly one %<%%d%> or equivalent.");
    if (output == "-" && write_dump == "-")
	p_errh->fatal("standard output used for both summary output and tcpdump output");

    // determine aggregate
    if (!agg && !agg_flows)
	agg = "ip dst";
    if (agg.substring(0, 3) == "src" || agg.substring(0, 3) == "dst")
	agg = "ip " + agg;
    if (agg.substring(0, 3) == "ip_")
	agg = "ip " + agg.substring(3);

    // set random seed if appropriate
    if (do_seed && (options.do_sample || options.anonymize))
	click_random_srandom();

    // figure out time argument
    StringAccum time_config_sa;
    if (start_time && time_offset)
	p_errh->fatal("specify at most one of %<--start-time%> and %<--time-offset%>");
    else if (time_offset)
	time_config_sa << ", START_AFTER " << time_offset;
    else if (start_time)
	time_config_sa << ", START " << start_time;
    if (interval && options.split_time)
	p_errh->fatal("supply at most one of %<--interval%> and %<--split-time%>");
    else if (interval)
	time_config_sa << ", INTERVAL " << interval;
    if (time_config_sa)
	options.time_config = time_config_sa.take_string().substring(2);

    // setup
    StringAccum sa;

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
    options.nfiles = files.size();

    // prepare ipsumdump format
    if (options.ipsumdump_format) {
	if (action != READ_IPSUMDUMP_OPT)
	    die_usage("%<--format%> option requires %<--ipsumdump%>");
    } else if (action == READ_TUDUMP_OPT) {
	options.ipsumdump_format = "timestamp ip_src sport ip_dst dport proto payload_len";
	action = READ_IPSUMDUMP_OPT;
    } else if (action == READ_IPADDR_OPT) {
	if (agg.substring(0, 6) == "ip src" || agg.substring(0, 6) == "ip dst")
	    options.ipsumdump_format = "ip_" + agg.substring(3, 3);
	else
	    die_usage("can%,t aggregate %<%s%> with %<--ip-addresses%>", agg.c_str());
	action = READ_IPSUMDUMP_OPT;
    } else if (action == READ_BROCONN_OPT) {
	options.ipsumdump_format = "timestamp ip_src ip_dst direction";
	action = READ_IPSUMDUMP_OPT;
	options.mirror = true;
    }

    // source elements
    Vector<uint32_t> source_flags;
    uint32_t all_source_flags = ~0U, any_source_flags = 0;
    for (int i = 0; i < files.size(); i++) {
	options.filename = files[i];
	source_flags.push_back(add_source(sa, i, action, options));
	all_source_flags &= source_flags.back();
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
	if (options.mirror && !(source_flags[i] & Options::MIRRORED) && (any_source_flags & Options::MIRRORED))
	    sa << "{ input -> t :: Tee -> output; t[1] -> IPMirror -> output } -> ";
	if (options.filter && !(source_flags[i] & Options::FILTERED) && (any_source_flags & Options::FILTERED))
	    sa << "IPFilter(0 " << options.filter << ") -> ";
	if (options.do_sample && !(source_flags[i] & Options::SAMPLED) && (any_source_flags & Options::SAMPLED))
	    sa << "samp" << i << " :: RandomSample(" << options.sample << ") -> ";
	sa << "[" << i << "] collate;\n";
    }

    // output path
    sa << "\ncollate\n";
    if (options.mirror && !(any_source_flags & Options::MIRRORED))
	sa << "  -> { input -> t :: Tee -> output; t[1] -> IPMirror -> output }\n";
    if (options.filter && !(any_source_flags & Options::FILTERED))
	sa << "  -> IPFilter(0 " << options.filter << ")\n";
    if (options.do_sample && !(any_source_flags & Options::SAMPLED))
	sa << "  -> samp0 :: RandomSample(" << options.sample << ")\n";
    if (options.anonymize)
	sa << "  -> anon :: AnonymizeIPAddr(CLASS 4, SEED false)\n";
    if ((options.time_config && !(all_source_flags & Options::TIMED))
	|| options.split_time) {
	sa << "  -> time :: TimeFilter(";
	if (options.time_config && !(all_source_flags & Options::TIMED))
	    sa << options.time_config << ", ";
	if (options.split_time) {
	    sa << "INTERVAL " << options.split_time << ", END_CALL trigger.run";
	    output_calls.push_back("time.start $(time.end)");
	    output_calls.push_back("time.extend_interval " + options.split_time.unparse());
	} else
	    sa << "STOP true";
	sa << ")\n";
    }

    // possible elements to write tcpdump file
    if (write_dump) {
	sa << "  -> ToDump(" << write_dump << ", USE_ENCAP_FROM";
	for (int i = 0; i < files.size(); i++)
	    sa << " src" << i;
	sa << ", SNAPLEN " << options.snaplen << ")\n";
    }

    // elements to aggregate
    bool agg_is_ip = false;
    if (agg_flows) {
	if (agg_flows_addrpair)
	    sa << "  -> AggregateIPAddrPair\n";
	else
	    sa << "  -> agg :: AggregateIPFlows\n";
	if (!agg_bidi)
	    sa << "  -> AggregatePaint(1, INCREMENTAL true)\n";
    } else {
	if (agg.substring(0, 6) == "ip src" || agg.substring(0, 6) == "ip dst")
	    agg_is_ip = true;
	sa << "  -> AggregateIP(" << agg;
	if (!binary && agg_is_ip)
	    sa << ", UNSHIFT_IP_ADDR true";
	sa << ")\n";
    }

    // elements to count aggregates
    if (!aggctr_pb)
	aggctr_pb = "BYTES false";
    sa << "  -> ac :: AggregateCounter(" << aggctr_pb << ", IP_BYTES true";
    if (aggctr_limit_nnz && multi_output >= 0) {
	sa << ", AGGREGATE_CALL " << aggctr_limit_nnz << " trigger.run";
	output_calls.push_back("ac.aggregate_call '" + String(aggctr_limit_nnz) + " trigger.run'");
    } else if (aggctr_limit_nnz)
	sa << ", AGGREGATE_STOP " << aggctr_limit_nnz;
    sa << ")\n";

    // remains
    if (aggctr_limit_count) {
	sa << "  -> counter :: Counter(COUNT_CALL " << aggctr_limit_count << " trigger.run)\n";
	output_calls.push_back("counter.reset");
    } else if (aggctr_limit_bytes) {
	sa << "  -> counter :: Counter(BYTE_COUNT_CALL " << aggctr_limit_bytes << " trigger.run)\n";
	output_calls.push_back("counter.reset");
    }
    sa << "  -> tr :: TimeRange\n";
    sa << "  -> d :: Discard;\n";
    sa << "ac[1] -> d;\n\n";

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
	StringAccum pb_banner;
	for (int i = 0; i < files.size(); i++)
	    pb_banner << (i > 0 ? ", " : "") << files[i];
	String banner = cp_quote(pb_banner.take_string().substring(0, 20));
	sa << ", UPDATE .1, BANNER " << banner;
	if (output == "-" || write_dump == "-")
	    sa << ", CHECK_STDOUT true";
	sa << ");\n";
    }

    // set-uid-root privilege
    if (geteuid() != getuid() || getegid() != getgid())
	sa << "ChangeUID();\n";

    int stop_driver_count = files.size() + (collate ? 1 : 0) + 1;
    sa << "manager :: DriverManager(pause " << (stop_driver_count - 1);
    // manipulate progress bar
    if (!quiet)
	sa << ", write progress.mark_done";
    if (agg_flows && !agg_flows_addrpair)
	sa << ", write agg.clear";
    sa << ", write trigger.run, label stop);\n";

    // Signals.  Do not catch SIGPIPE; it kills us immediately
    sa << "Script(TYPE SIGNAL INT TERM, write trigger.run, "
       << "write manager.goto stop, exit);\n";

    // write script
    sa << "\ntrigger :: Script(TYPE PASSIVE";
    if (multi_output >= 0) {
	sa << ",\n\tinit onum 0,";
	if (!options.split_time)
	    sa << " goto done $(eq $(ac.nagg) 0),";
	sa << "\n\tset onum $(add $onum 1)";
    }

    // banner
    {
	StringAccum bsa, argsa;
	for (int i = 0; i < argc; i++)
	    argsa << argv[i] << ' ';
	argsa.pop_back();
	bsa << "!creator " << cp_quote(argsa.take_string()) << "\n";
	bsa << "!counts " << (aggctr_pb == "BYTES false" ? "packets\n" : "bytes\n");
	sa << ",\n\twriteq ac.banner \"";
	String b = cp_quote(bsa.take_string());
	if (b && b[0] == '\"')
	    sa.append(b.begin() + 1, b.end() - 1);
	else
	    sa << b;
	if (options.split_time)
	    sa << "!times $(time.start) $(time.end) " << options.split_time << "\\n";
	else
	    sa << "!times $(tr.range) $(tr.interval)\\n";
	if (multi_output >= 0)
	    sa << "!section $onum\\n";
	sa << "\"";
    }

    // write file
    sa << ",\n\twrite ac.write_" << (binary ? "" : (agg_is_ip ? "ip_" : "text_")) << "file ";
    if (multi_output < 0)
	sa << cp_quote(output);
    else
	sa << "\"$(sprintf " << cp_quote(output) << " $onum)\"";
    sa << ",\n\tgoto ok $(ge $? 0), write manager.goto stop, goto done";

    sa << ",\n\tlabel ok, write ac.clear, write tr.reset";
    for (int i = 0; i < output_calls.size(); i++)
	sa << ",\n\twrite " << output_calls[i];
    sa << ",\n\tlabel done";
    sa << ");\n";

    // output config if required
    if (config) {
	printf("%s", sa.c_str());
	exit(0);
    }

    // lex configuration
    BailErrorHandler berrh(errh);
    PrefixErrorHandler verrh(&berrh, String::make_stable("{context:no}"));
    Router *router = click_read_router(sa.take_string(), true, (verbose ? errh : &verrh));
    if (!router)
	exit(1);

    // run driver
    router->activate(errh);
    router->master()->thread(0)->driver();

    // exit
    delete router;
    exit(errh->nerrors() > 0 ? 1 : 0);
}
