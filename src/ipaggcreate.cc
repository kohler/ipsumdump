#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <click/config.h>
#include <click/clp.h>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/router.hh>
#include <click/lexer.hh>
#include <click/straccum.hh>
#include <click/handlercall.hh>
#include "aggcounter.hh"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include <click/standard/drivermanager.hh>

#define HELP_OPT	300
#define VERSION_OPT	301
#define OUTPUT_OPT	302
#define CONFIG_OPT	303
#define WRITE_DUMP_OPT	304
#define FILTER_OPT	305
#define VERBOSE_OPT	306
#define ANONYMIZE_OPT	307
#define MULTIPACKET_OPT	309
#define SAMPLE_OPT	310
#define COLLATE_OPT	311
#define RANDOM_SEED_OPT	312
#define INTERVAL_OPT	315
#define TIME_OFFSET_OPT	316
#define BINARY_OPT	317
#define ASCII_OPT	318
#define QUIET_OPT	320

// data sources
#define READ_DUMP_OPT		401
#define READ_NETFLOW_SUMMARY_OPT 402
#define READ_IPSUMDUMP_OPT	403
#define READ_TUDUMP_OPT		404
#define READ_IPADDR_OPT		405
#define READ_BROCONN_OPT	406
#define IPSUMDUMP_FORMAT_OPT	450

// aggregates
#define AGG_SRC_OPT	500
#define AGG_DST_OPT	501
#define AGG_LENGTH_OPT	502
#define AGG_FLOWS_OPT	503
#define AGG_UNI_FLOWS_OPT 504
#define AGG_ADDRPAIR_OPT 505
#define AGG_UNI_ADDRPAIR_OPT 506

#define AGG_BYTES_OPT	600
#define AGG_PACKETS_OPT	601
#define LIMIT_AGG_OPT	602
#define SPLIT_AGG_OPT	603
#define SPLIT_TIME_OPT	604
#define SPLIT_PACKETS_OPT 605
#define SPLIT_BYTES_OPT	606

#define CLP_TIMEVAL_TYPE	(Clp_MaxDefaultType + 1)

static Clp_Option options[] = {

    { "help", 'h', HELP_OPT, 0, 0 },
    { "version", 'v', VERSION_OPT, 0, 0 },
    { "verbose", 'V', VERBOSE_OPT, 0, Clp_Negate },

    { "tcpdump", 'r', READ_DUMP_OPT, 0, 0 },
    { "read-tcpdump", 0, READ_DUMP_OPT, 0, 0 },
    { "netflow-summary", 0, READ_NETFLOW_SUMMARY_OPT, 0, 0 },
    { "read-netflow-summary", 0, READ_NETFLOW_SUMMARY_OPT, 0, 0 },
    { "ipsumdump", 0, READ_IPSUMDUMP_OPT, 0, 0 },
    { "read-ipsumdump", 0, READ_IPSUMDUMP_OPT, 0, 0 },
    { "tu-summary", 0, READ_TUDUMP_OPT, 0, 0 },
    { "read-tu-summary", 0, READ_TUDUMP_OPT, 0, 0 },
    { "ip-addresses", 0, READ_IPADDR_OPT, 0, 0 },
    { "read-ip-addresses", 0, READ_IPADDR_OPT, 0, 0 },
    { "format", 0, IPSUMDUMP_FORMAT_OPT, Clp_ArgString, 0 },
    { "bro-conn-summary", 0, READ_BROCONN_OPT, 0, 0 },
    { "read-bro-conn-summary", 0, READ_BROCONN_OPT, 0, 0 },
    
    { "write-tcpdump", 'w', WRITE_DUMP_OPT, Clp_ArgString, 0 },
    { "filter", 'f', FILTER_OPT, Clp_ArgString, 0 },
    { "anonymize", 'A', ANONYMIZE_OPT, 0, Clp_Negate },
    { "binary", 'B', BINARY_OPT, 0, Clp_Negate },
    { "ascii", 0, ASCII_OPT, 0, Clp_Negate },
    { "multipacket", 0, MULTIPACKET_OPT, 0, Clp_Negate },
    { "sample", 0, SAMPLE_OPT, Clp_ArgDouble, Clp_Negate },
    { "collate", 0, COLLATE_OPT, 0, Clp_Negate },
    { "random-seed", 0, RANDOM_SEED_OPT, Clp_ArgUnsigned, 0 },
    { "quiet", 'q', QUIET_OPT, 0, Clp_Negate },

    { "output", 'o', OUTPUT_OPT, Clp_ArgString, 0 },
    { "config", 0, CONFIG_OPT, 0, 0 },

    { "interval", 't', INTERVAL_OPT, CLP_TIMEVAL_TYPE, 0 },
    { "time-offset", 'T', TIME_OFFSET_OPT, CLP_TIMEVAL_TYPE, 0 },

    { "src", 's', AGG_SRC_OPT, 0, 0 },
    { "dst", 'd', AGG_DST_OPT, 0, 0 },
    { "length", 'l', AGG_LENGTH_OPT, 0, 0 },
    { "flows", 0, AGG_FLOWS_OPT, 0, 0 },
    { "unidirectional-flows", 0, AGG_UNI_FLOWS_OPT, 0, 0 },
    { "uni-flows", 0, AGG_UNI_FLOWS_OPT, 0, 0 },
    { "address-pairs", 0, AGG_ADDRPAIR_OPT, 0, 0 },
    { "unidirectional-address-pairs", 0, AGG_UNI_ADDRPAIR_OPT, 0, 0 },
    { "uni-address-pairs", 0, AGG_UNI_ADDRPAIR_OPT, 0, 0 },
    { "bytes", 'b', AGG_BYTES_OPT, 0, 0 },
    { "packets", 'p', AGG_PACKETS_OPT, 0, 0 },
    { "limit-aggregates", 0, LIMIT_AGG_OPT, Clp_ArgUnsigned, 0 },
    { "split-aggregates", 0, SPLIT_AGG_OPT, Clp_ArgUnsigned, 0 },
    { "split-time", 0, SPLIT_TIME_OPT, CLP_TIMEVAL_TYPE, 0 },
    { "split-packets", 0, SPLIT_PACKETS_OPT, Clp_ArgUnsigned, 0 },
    { "split-count", 0, SPLIT_PACKETS_OPT, Clp_ArgUnsigned, 0 },
    { "split-bytes", 0, SPLIT_BYTES_OPT, Clp_ArgUnsigned, 0 },

};

static const char *program_name;
static Router *router = 0;
static bool started = false;

void
die_usage(const char *specific = 0)
{
    ErrorHandler *errh = ErrorHandler::default_handler();
    if (specific)
	errh->error("%s: %s", program_name, specific);
    errh->fatal("Usage: %s [-i | -r] [CONTENT OPTIONS] [DEVNAMES or FILES]...\n\
Try `%s --help' for more information.",
		program_name, program_name);
    // should not get here, but just in case...
    exit(1);
}

void
usage()
{
  printf("\
`ipaggcreate' reads IP packets from the tcpdump(1) files, or other related\n\
files, and aggregates their contents into a simple file.\n\
\n\
Usage: %s [OPTIONS] [FILES] > AGGFILE\n\
\n\
Aggregate options (give exactly one):\n\
  -s, --src                  Aggregate by IP source address.\n\
  -d, --dst                  Aggregate by IP destination address (default).\n\
  -l, --length               Aggregate by IP length.\n\
      --flows                Aggregate by flow ID (agg. number meaningless).\n\
      --unidirectional-flows Aggregate by unidirectional flow ID.\n\
      --address-pairs        Aggregate by IP address pairs.\n\
      --unidirectional-address-pairs\n\
\n\
Other aggregate options:\n\
  -p, --packets              Count number of packets (default).\n\
  -b, --bytes                Count number of bytes.\n\
  -T, --time-offset TIME     Ignore first TIME in input.\n\
  -t, --interval TIME        Output TIME worth of packets. Example: `1hr'.\n\
      --limit-aggregates K   Stop once K aggregates are encountered.\n\
      --split-aggregates K   Output new file every K aggregates.\n\
      --split-time TIME      Output new file every TIME worth of packets.\n\
      --split-count N        Output new file every N packets.\n\
      --split-bytes N        Output new file every N bytes.\n\
\n\
Data source options (give exactly one):\n\
  -r, --tcpdump              Read packets from tcpdump(1) FILES (default).\n\
      --netflow-summary      Read summarized NetFlow FILES.\n\
      --ipsumdump            Read ipsumdump FILES.\n\
      --format FORMAT        Read ipsumdump FILES with format FORMAT.\n\
      --tu-summary           Read TU summary dump FILES.\n\
      --ip-addresses         Read a list of IP addresses, one per line.\n\
      --bro-conn-summary     Read Bro connection summary FILES.\n\
\n\
Other options:\n\
  -o, --output FILE          Write summary dump to FILE (default stdout).\n\
  -w, --write-tcpdump FILE   Also dump packets to FILE in tcpdump(1) format.\n\
  -f, --filter FILTER        Apply tcpdump(1) filter FILTER to data.\n\
  -A, --anonymize            Anonymize IP addresses (preserves prefix & class).\n\
      --sample PROB          Sample packets with PROB probability.\n\
      --multipacket          Produce multiple entries for a flow identifier\n\
                             representing multiple packets (NetFlow only).\n\
      --collate              Collate packets from data sources by timestamp.\n\
      --random-seed SEED     Set random seed to SEED (default is random).\n\
  -B, --binary               Output aggregate file in binary.\n\
      --ascii                Output aggregate file in ASCII (default).\n\
  -q, --quiet                Do not print progress bar.\n\
      --config               Output Click configuration and exit.\n\
  -V, --verbose              Report errors verbosely.\n\
  -h, --help                 Print this message and exit.\n\
  -v, --version              Print version number and exit.\n\
\n\
Report bugs to <kohler@aciri.org>.\n", program_name);
}

// Stop the driver this many aggregate times to end the program.
static int stop_driver_count = 1;

static void
catch_signal(int sig)
{
    signal(sig, SIG_DFL);
    if (!started)
	kill(getpid(), sig);
    DriverManager *dm = (DriverManager *)(router->attachment("DriverManager"));
    router->set_driver_reservations(dm->stopped_count() - stop_driver_count);
}

static int
parse_timeval(Clp_Parser *clp, const char *arg, int complain, void *)
{
    if (cp_timeval(arg, (struct timeval *)&clp->val))
	return 1;
    else if (complain)
	return Clp_OptionError(clp, "`%O' expects a time value, not `%s'", arg);
    else
	return 0;
}

extern void export_elements(Lexer *);

static StringAccum banner_sa;

static String::Initializer string_init;
static String output;
static int multi_output = -1;
static String output_call_str;
static bool binary = false;
static bool collate = false;

static String
source_config(const String &filename, const String &config, int)
{
    return cp_quote(filename) + config;
}

static String
source_output_port(int i)
{
    if (collate)
	return "[" + String(i) + "]collate";
    else
	return "shunt";
}

static int
stop_handler(const String &s, Element *, void *, ErrorHandler *)
{
    int n = 1;
    (void) cp_integer(cp_uncomment(s), &n);
    router->adjust_driver_reservations(-n);
    return 0;
}

static int
output_handler(const String &, Element *, void *, ErrorHandler *errh)
{
    if (multi_output >= 0)
	multi_output++;		// files start from 1
    
    String tr_range = HandlerCall::call_read(router, "tr", "range");
    String tr_interval = HandlerCall::call_read(router, "tr", "interval");
    StringAccum bsa;
    bsa << banner_sa << "!times " << cp_uncomment(tr_range) << " " << cp_uncomment(tr_interval) << "\n";
    if (multi_output >= 0)
	bsa << "!section " << multi_output << "\n";
    (void) HandlerCall::call_write(router, "ac", "banner", bsa.take_string());

    String cur_output = output;
    if (multi_output >= 0) {
	StringAccum sa;
	if (char *x = sa.reserve(output.length() + 30)) {
	    int len = sprintf(x, output.cc(), multi_output);
	    sa.forward(len);
	} else
	    return errh->error("out of memory!");
	cur_output = sa.take_string();
    }
    AggregateCounter *ac = (AggregateCounter *)(router->find("ac"));
    int result = 0;
    if (multi_output < 0 || !ac->empty())
	result = HandlerCall::call_write(router, "ac", (binary ? "write_file" : "write_ascii_file"), cp_quote(cur_output), errh);
    else if (multi_output >= 0)	// skip empty files
	multi_output--;

    (void) HandlerCall::call_write(router, "ac", "clear");
    (void) HandlerCall::call_write(router, "tr", "reset");

    if (output_call_str)
	(void) HandlerCall::call_write(router, output_call_str, errh);
    
    return result;
}

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

int
main(int argc, char *argv[])
{
    Clp_Parser *clp = Clp_NewParser
	(argc, argv, sizeof(options) / sizeof(options[0]), options);
    program_name = Clp_ProgramName(clp);
    Clp_AddType(clp, CLP_TIMEVAL_TYPE, 0, parse_timeval, 0);
    
    String::static_initialize();
    cp_va_static_initialize();
    ErrorHandler *errh = new FileErrorHandler(stderr, "");
    ErrorHandler::static_initialize(errh);
    ErrorHandler *p_errh = new PrefixErrorHandler(errh, program_name + String(": "));

    String write_dump;
    //String output;
    String filter;
    String agg, agg_flows;
    String aggctr_pb;
    String ipsumdump_format;
    uint32_t aggctr_limit_nnz = 0;
    uint32_t aggctr_limit_count = 0;
    uint32_t aggctr_limit_bytes = 0;
    bool config = false;
    bool verbose = false;
    bool anonymize = false;
    bool multipacket = false;
    double sample = 0;
    bool do_sample = false;
    //bool collate;
    int action = 0;
    bool do_seed = true;
    bool progress_bar_ok = true;
    //bool binary;
    struct timeval time_offset;
    struct timeval interval;
    struct timeval split_time;
    Vector<String> files;
    timerclear(&time_offset);
    timerclear(&interval);
    timerclear(&split_time);
    
    while (1) {
	int opt = Clp_Next(clp);
	switch (opt) {

	  case OUTPUT_OPT:
	    if (output)
		die_usage("`--output' already specified");
	    output = clp->arg;
	    break;
	    
	  case READ_DUMP_OPT:
	  case READ_NETFLOW_SUMMARY_OPT:
	  case READ_IPSUMDUMP_OPT:
	  case READ_TUDUMP_OPT:
	  case READ_IPADDR_OPT:
	  case READ_BROCONN_OPT:
	    if (action)
		die_usage("data source option already specified");
	    action = opt;
	    break;

	  case IPSUMDUMP_FORMAT_OPT:
	    if (ipsumdump_format)
		die_usage("`--ipsumdump-format' already specified");
	    ipsumdump_format = clp->arg;
	    break;
	    
	  case WRITE_DUMP_OPT:
	    if (write_dump)
		die_usage("`--write-tcpdump' already specified");
	    write_dump = clp->arg;
	    break;

	  case FILTER_OPT:
	    if (filter)
		die_usage("`--filter' already specified");
	    filter = clp->arg;
	    break;

	  case ANONYMIZE_OPT:
	    anonymize = !clp->negated;
	    break;

	  case MULTIPACKET_OPT:
	    multipacket = !clp->negated;
	    break;

	  case BINARY_OPT:
	    binary = !clp->negated;
	    break;

	  case ASCII_OPT:
	    binary = clp->negated;
	    break;

	  case SAMPLE_OPT:
	    if (clp->negated)
		do_sample = false;
	    else {
		do_sample = true;
		if (clp->val.d < 0 || clp->val.d > 1)
		    die_usage("`--sample' probability must be between 0 and 1");
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
	    progress_bar_ok = clp->negated;
	    break;
	    
	  case TIME_OFFSET_OPT:
	    time_offset = *((const struct timeval *)&clp->val);
	    break;
	    
	  case INTERVAL_OPT:
	    interval = *((const struct timeval *)&clp->val);
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

	  case AGG_FLOWS_OPT:
	  case AGG_UNI_FLOWS_OPT:
	  case AGG_ADDRPAIR_OPT:
	  case AGG_UNI_ADDRPAIR_OPT:
	    if (agg || agg_flows)
		die_usage("aggregate specified twice");
	    agg_flows = (opt == AGG_FLOWS_OPT || opt == AGG_UNI_FLOWS_OPT ? "PORTS true, " : "PORTS false, ");
	    agg_flows += (opt == AGG_UNI_FLOWS_OPT || opt == AGG_UNI_ADDRPAIR_OPT ? "BIDI false" : "BIDI true");
	    break;

	  case AGG_BYTES_OPT:
	  case AGG_PACKETS_OPT:
	    if (aggctr_pb)
		die_usage("`--bytes' or `--packets' specified twice");
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
	    split_time = *((const struct timeval *)&clp->val);
	    goto multi_output;

	  multi_output:
	    if (multi_output >= 0)
		die_usage("supply at most one of the `--split' options");
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
	    printf("ipaggcreate %s (libclick-%s)\n", "0", CLICK_VERSION);
	    printf("Copyright (C) 2001 International Computer Science Institute\n\
This is free software; see the source for copying conditions.\n\
There is NO warranty, not even for merchantability or fitness for a\n\
particular purpose.\n");
	    exit(0);
	    break;

	  case VERBOSE_OPT:
	    verbose = !clp->negated;
	    break;

	  case Clp_NotOption:
	    files.push_back(clp->arg);
	    break;
	    
	  case Clp_BadOption:
	    die_usage();
	    break;

	  case Clp_Done:
	    goto done;

	  default:
	    die_usage();
	    break;
	    
	}
    }
  
  done:
    // check file usage
    if (!output)
	output = "-";
    if (multi_output >= 0 && !check_multi_output(output))
	p_errh->fatal("When generating multiple files, you must supply `--output',\nwhich should contain exactly one `%%d' or equivalent.");
    if (output == "-" && write_dump == "-")
	p_errh->fatal("standard output used for both summary output and tcpdump output");

    // determine aggregate
    if (!agg && !agg_flows)
	agg = "ip dst";
    
    // set random seed if appropriate
    if (do_seed && (do_sample || anonymize))
	click_random_srandom();

    // figure out time argument
    StringAccum time_config_sa;
    if (timerisset(&time_offset))
	time_config_sa << ", START_AFTER " << time_offset;
    if (timerisset(&interval) && timerisset(&split_time))
	p_errh->fatal("supply at most one of `--interval' and `--split-time'");
    else if (timerisset(&interval))
	time_config_sa << ", INTERVAL " << interval;
    else if (timerisset(&split_time))
	time_config_sa << ", INTERVAL " << split_time;
    String time_config = (time_config_sa ? time_config_sa.take_string().substring(2) : String());
    
    // other setup
    StringAccum shunt_sa;
    StringAccum psa;
    StringAccum output_call_sa;
    String sample_elt;
    int snaplen = (write_dump ? 2000 : 68);
    bool allow_ipsumdump_sample = true;
    if (collate && files.size() < 2)
	collate = false;
    
    // elements to read packets
    if (action == 0)
	action = (ipsumdump_format ? READ_IPSUMDUMP_OPT : READ_DUMP_OPT);

    // prepare ipsumdump format
    if (ipsumdump_format) {
	if (action != READ_IPSUMDUMP_OPT)
	    die_usage("`--format' option requires `--ipsumdump'");
    } else if (action == READ_TUDUMP_OPT) {
	ipsumdump_format = "timestamp 'ip src' sport 'ip dst' dport proto 'payload len'";
	action = READ_IPSUMDUMP_OPT;
    } else if (action == READ_IPADDR_OPT) {
	if (agg == "ip src" || agg == "ip dst")
	    ipsumdump_format = "'" + agg + "'";
	else
	    die_usage("can't aggregate `" + agg + "' with `--ip-addresses'");
	action = READ_IPSUMDUMP_OPT;
    } else if (action == READ_BROCONN_OPT) {
	ipsumdump_format = "timestamp 'ip src' 'ip dst' direction";
	shunt_sa << " -> { input -> t :: Tee -> output; t[1] -> IPMirror -> output }\n";
	action = READ_IPSUMDUMP_OPT;
	allow_ipsumdump_sample = false;
    }
    
    if (action == READ_DUMP_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", FORCE_IP true, STOP true";
	if (do_sample) {
	    config += ", SAMPLE " + String(sample);
	    sample_elt = "src0";
	}
	if (time_config && files.size() == 1) {
	    config += ", " + time_config;
	    time_config = String();
	}
	if (timerisset(&split_time)) {
	    config += ", END_CALL output";
	    output_call_sa << "src0.extend_interval " << split_time;
	}
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromDump(" << source_config(files[i], config, i) << ") -> " << source_output_port(i) << ";\n";
	
    } else if (action == READ_NETFLOW_SUMMARY_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", STOP true";
	if (multipacket)
	    config += ", MULTIPACKET true";
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromNetFlowSummaryDump(" << source_config(files[i], config, i) << ") -> " << source_output_port(i) << ";\n";
	if (do_sample && !multipacket)
	    p_errh->warning("`--sample' option will sample flows, not packets\n(If you want to sample packets, use `--multipacket'.)");
	
    } else if (action == READ_IPSUMDUMP_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", STOP true, ZERO true";
	if (do_sample && allow_ipsumdump_sample) {
	    config += ", SAMPLE " + String(sample);
	    sample_elt = "src0";
	}
	if (multipacket)
	    config += ", MULTIPACKET true";
	if (ipsumdump_format)
	    config += ", DEFAULT_CONTENTS " + ipsumdump_format;
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromIPSummaryDump(" << source_config(files[i], config, i) << ") -> " << source_output_port(i) << ";\n";
	
    } else
	die_usage("must supply a data source option");

    // print collation/shunt
    StringAccum sa;
    if (do_sample && !sample_elt) {
	shunt_sa << " -> samp :: RandomSample(" << sample << ")";
	sample_elt = "shunt/samp";
    }
    sa << "shunt :: { input" << shunt_sa << " -> output };\n";
    if (collate)
	sa << "collate :: MergeByTimestamp(STOP true, NULL_IS_DEAD true) -> shunt;\n";
    sa << psa;
    
    // possible elements to filter and/or anonymize
    sa << "shunt\n";
    if (time_config || (timerisset(&split_time) && !output_call_sa)) {
	sa << "  -> time :: TimeFilter(";
	if (time_config)
	    sa << time_config << ", ";
	if (timerisset(&split_time)) {
	    sa << "END_CALL output";
	    output_call_sa << "time.extend_interval " << split_time;
	} else
	    sa << "STOP true";
	sa << ")\n";
    }
    if (filter)
	sa << "  -> IPFilter(0 " << filter << ")\n";
    if (anonymize)
	sa << "  -> anon :: AnonymizeIPAddr(CLASS 4, SEED false)\n";

    // possible elements to write tcpdump file
    if (write_dump) {
	sa << "  -> { input -> t :: Tee -> output;\n        t[1] -> ToDump(" << write_dump << ", USE_ENCAP_FROM";
	for (int i = 0; i < files.size(); i++)
	    sa << " src" << i;
	sa << ", SNAPLEN " << snaplen << ") }\n";
    }
    
    // elements to aggregate
    if (agg_flows)
	sa << "  -> AggregateFlows(" << agg_flows << ")\n";
    else
	sa << "  -> AggregateIP(" << agg << ")\n";

    "$Id: ipaggcreate.cc,v 1.19 2002-01-28 05:54:32 kohler Exp $";
    // elements to count aggregates
    sa << "  -> ac :: AggregateCounter(";
    sa << (aggctr_pb ? aggctr_pb : String("BYTES false")) << ", IP_BYTES true";
    if (aggctr_limit_nnz && multi_output >= 0) {
	sa << ", CALL_AFTER_AGG " << aggctr_limit_nnz << " output";
	output_call_sa << "ac.call_after_agg '" << aggctr_limit_nnz << " output'";
    } else if (aggctr_limit_nnz)
	sa << ", STOP_AFTER_AGG " << aggctr_limit_nnz;
    sa << ")\n";

    // remains
    if (aggctr_limit_count) {
	sa << "  -> counter :: Counter(CALL_AFTER_COUNT " << aggctr_limit_count << " output)\n";
	output_call_sa << "counter.reset";
    } else if (aggctr_limit_bytes) {
	sa << "  -> counter :: Counter(CALL_AFTER_BYTES " << aggctr_limit_bytes << " output)\n";
	output_call_sa << "counter.reset";
    }
    sa << "  -> tr :: TimeRange\n";
    sa << "  -> d :: Discard;\n";
    sa << "ac[1] -> d;\n";

    // progress bar
    if (progress_bar_ok) {
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
    
    // DriverManager
    if (!output)
	output = "-";
    stop_driver_count = files.size() + (collate ? 1 : 0) + 1;
    sa << "DriverManager(wait_stop " << (stop_driver_count - 1);
    // manipulate progress bar
    if (progress_bar_ok)
	sa << ", write_skip progress.mark_done";
    sa << ", write_skip output);\n";
    sa << "// Outside of ipaggcreate, try a handler like\n// `write " << (binary ? "ac.write_file" : "ac.write_ascii_file") << " " << cp_quote(output) << "' instead of `write_skip output'.\n";

    // output config if required
    if (config) {
	printf("%s", sa.cc());
	exit(0);
    }

    // catch control-C
    signal(SIGINT, catch_signal);
    signal(SIGTERM, catch_signal);
    // do NOT catch SIGPIPE; it kills us immediately

    // initialize banner
    {
	StringAccum bsa;
	for (int i = 0; i < argc; i++)
	    bsa << argv[i] << ' ';
	bsa.pop_back();
	banner_sa << "!creator " << cp_quote(bsa.take_string()) << "\n";
	banner_sa << "!counts " << (aggctr_pb == "BYTES false" ? "packets\n" : "bytes\n");
    }
    output_call_str = output_call_sa.take_string();

    // lex configuration
    BailErrorHandler berrh(errh);
    ErrorHandler *click_errh = (verbose ? errh : &berrh);
    Lexer *lexer = new Lexer(click_errh);
    export_elements(lexer);
    int cookie = lexer->begin_parse(sa.take_string(), "<internal>", 0);
    while (lexer->ystatement())
	/* do nothing */;
    router = lexer->create_router();
    lexer->end_parse(cookie);
    router->add_global_write_handler("stop", stop_handler, 0);
    router->add_global_write_handler("output", output_handler, 0);
    if (errh->nerrors() > 0 || router->initialize(click_errh, verbose) < 0)
	exit(1);
    
    // run driver
    started = true;
    router->thread(0)->driver();

    // exit
    delete router;
    exit(0);
}
