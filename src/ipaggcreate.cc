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
#define READ_DUMP_OPT	401
#define READ_NETFLOW_SUMMARY_OPT 402
#define READ_IPSUMDUMP_OPT 403
#define READ_TUDUMP_OPT	404

// aggregates
#define AGG_SRC_OPT	500
#define AGG_DST_OPT	501
#define AGG_LENGTH_OPT	502

#define AGG_BYTES_OPT	600
#define AGG_PACKETS_OPT	601
#define LIMIT_AGG_OPT	602
#define SPLIT_AGG_OPT	603
#define SPLIT_TIME_OPT	604

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
    { "bytes", 'b', AGG_BYTES_OPT, 0, 0 },
    { "packets", 'p', AGG_PACKETS_OPT, 0, 0 },
    { "limit-aggregates", 0, LIMIT_AGG_OPT, Clp_ArgUnsigned, 0 },
    { "split-aggregates", 0, SPLIT_AGG_OPT, Clp_ArgUnsigned, 0 },
    { "split-time", 0, SPLIT_TIME_OPT, CLP_TIMEVAL_TYPE, 0 },

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
`Aciri-aggcreate' reads IP packets from the tcpdump(1) files, or other related\n\
files, and aggregates their contents into a simple file.\n\
\n\
Usage: %s [OPTIONS] [FILES] > AGGFILE\n\
\n\
Aggregate options (give exactly one):\n\
  -s, --src                  Aggregate by IP source address.\n\
  -d, --dst                  Aggregate by IP destination address (default).\n\
  -l, --length               Aggregate by IP length.\n\
\n\
Other aggregate options:\n\
  -p, --packets              Count number of packets (default).\n\
  -b, --bytes                Count number of bytes.\n\
  -T, --time-offset TIME     Ignore first TIME in input.\n\
  -t, --interval TIME        Output TIME worth of packets. Example: `1hr'.\n\
      --limit-aggregates K   Stop once K aggregates are encountered.\n\
      --split-aggregates K   Output new file every K aggregates.\n\
      --split-time TIME      Output new file every TIME worth of packets.\n\
\n\
Data source options (give exactly one):\n\
  -r, --tcpdump              Read packets from tcpdump(1) FILES (default).\n\
      --netflow-summary      Read summarized NetFlow FILES.\n\
      --ipsumdump            Read from existing ipsumdump FILES.\n\
      --tu-summary           Read TU summary dump FILES.\n\
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

static String
source_output_port(bool collate, int i)
{
    if (collate)
	return "[" + String(i) + "]collate";
    else
	return "shunt";
}

static StringAccum banner_sa;

static uint32_t aggctr_limit_nnz = 0;
static String::Initializer string_init;
static String output;
static int multi_output = -1;
static bool binary = false;
static String end_call_str;

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

    if (multi_output >= 0) {
	if (aggctr_limit_nnz)
	    (void) HandlerCall::call_write(router, "ac", "call_after_agg", String(aggctr_limit_nnz) + " output", errh);
	else if (end_call_str)
	    (void) HandlerCall::call_write(router, end_call_str, errh);
    }
    
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
    String agg_ip;
    bool agg_len = false;
    String aggctr_pb;
    //uint32_t aggctr_limit_nnz;
    bool config = false;
    bool verbose = false;
    bool anonymize = false;
    bool multipacket = false;
    double sample = 0;
    bool do_sample = false;
    bool collate = false;
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
	    if (action)
		die_usage("data source option already specified");
	    action = opt;
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
	    if (agg_ip || agg_len)
		die_usage("aggregate specified twice");
	    agg_ip = "ip src";
	    break;
	    
	  case AGG_DST_OPT:
	    if (agg_ip || agg_len)
		die_usage("aggregate specified twice");
	    agg_ip = "ip dst";
	    break;
	    	    
	  case AGG_LENGTH_OPT:
	    if (agg_ip || agg_len)
		die_usage("aggregate specified twice");
	    agg_len = true;
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
	    if (multi_output >= 0)
		die_usage("supply at most one of `--split-aggregates' and `--split-time'");
	    aggctr_limit_nnz = clp->val.u;
	    multi_output = 0;
	    break;

	  case SPLIT_TIME_OPT:
	    if (multi_output >= 0)
		die_usage("supply at most one of `--split-aggregates' and `--split-time'");
	    split_time = *((const struct timeval *)&clp->val);
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
	    printf("aciri-aggcreate %s (libclick-%s)\n", "0", CLICK_VERSION);
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
    String shunt_internals = "";
    StringAccum psa;
    StringAccum end_call_sa;
    String sample_elt;
    int snaplen = (write_dump ? 2000 : 68);
    if (collate && files.size() < 2)
	collate = false;
    
    // elements to read packets
    if (action == 0)
	action = READ_DUMP_OPT;
    if (action == READ_DUMP_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", FORCE_IP true, STOP true";
	if (do_sample)
	    config += ", SAMPLE " + String(sample);
	if (time_config && files.size() == 1) {
	    config += ", " + time_config;
	    time_config = String();
	}
	if (timerisset(&split_time)) {
	    config += ", END_CALL output";
	    end_call_sa << "src0.extend_interval " << split_time;
	}
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromDump(" << cp_quote(files[i]) << config << ") -> " << source_output_port(collate, i) << ";\n";
	sample_elt = "src0";
	
    } else if (action == READ_NETFLOW_SUMMARY_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", STOP true";
	if (multipacket)
	    config += ", MULTIPACKET true";
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromNetFlowSummaryDump(" << cp_quote(files[i]) << config << ") -> " << source_output_port(collate, i) << ";\n";
	if (do_sample) {
	    shunt_internals = " -> samp :: RandomSample(" + String(sample) + ")";
	    sample_elt = "shunt/samp";
	    if (!multipacket)
		p_errh->warning("`--sample' option will sample flows, not packets\n(If you want to sample packets, use `--multipacket'.)");
	}
	progress_bar_ok = false;
	
    } else if (action == READ_IPSUMDUMP_OPT
	       || action == READ_TUDUMP_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", STOP true, ZERO true";
	if (do_sample)
	    config += ", SAMPLE " + String(sample);
	if (multipacket)
	    config += ", MULTIPACKET true";
	if (action == READ_TUDUMP_OPT)
	    config += ", DEFAULT_CONTENTS timestamp 'ip src' sport 'ip dst' dport proto 'payload len'";
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromIPSummaryDump(" << cp_quote(files[i]) << config << ") -> " << source_output_port(collate, i) << ";\n";
	sample_elt = "src0";
	
    } else
	die_usage("must supply a data source option");

    // print collation/shunt
    StringAccum sa;
    sa << "shunt :: { input" << shunt_internals << " -> output };\n";
    if (collate)
	sa << "collate :: MergeByTimestamp(STOP true, NULL_IS_DEAD true) -> shunt;\n";
    sa << psa;
    
    // possible elements to filter and/or anonymize
    sa << "shunt\n";
    if (time_config || (timerisset(&split_time) && !end_call_sa)) {
	sa << "  -> time :: TimeFilter(";
	if (time_config)
	    sa << time_config << ", ";
	if (timerisset(&split_time)) {
	    sa << "END_CALL output";
	    end_call_sa << "time.extend_interval " << split_time;
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
    if (!agg_ip && !agg_len)
	agg_ip = "ip dst";
    if (agg_ip)
	sa << "  -> AggregateIP(" << agg_ip << ")\n";
    else if (agg_len)
	sa << "  -> AggregateLength(IP true)\n";

    // elements to count aggregates
    sa << "  -> ac :: AggregateCounter(";
    sa << (aggctr_pb ? aggctr_pb : String("BYTES false")) << ", IP_BYTES true";
    if (aggctr_limit_nnz && multi_output >= 0)
	sa << ", CALL_AFTER_AGG " << aggctr_limit_nnz << " output";
    else if (aggctr_limit_nnz)
	sa << ", STOP_AFTER_AGG " << aggctr_limit_nnz;
    sa << ")\n";

    // remains
    sa << "  -> tr :: TimeRange\n";
    sa << "  -> d :: Discard;\n";
    sa << "ac[1] -> d;\n";

    // DriverManager
    if (!output)
	output = "-";
    
    stop_driver_count = files.size() + (collate ? 1 : 0) + 1;
    sa << "DriverManager(wait_stop " << (stop_driver_count - 1);
    // clear progress bar if appropriate
    if (progress_bar_ok && files.size() == 1)
	sa << ", write_skip progress.mark_done";
    sa << ", write_skip output);\n";
    sa << "// Outside of aciri-aggcreate, try a handler like\n// `write " << (binary ? "ac.write_file" : "ac.write_ascii_file") << " " << cp_quote(output) << "' instead of `write output'.\n";

    // progress bar
    if (progress_bar_ok && files.size() == 1) {
	String banner = cp_quote(files[0].substring(0, 20));
	sa << "progress :: ProgressBar(src0.filepos, src0.filesize, UPDATE .1, BANNER " << banner << ");\n";
    }
    
    // output config if required
    if (config) {
	printf("%s", sa.cc());
	exit(0);
    }

    // catch control-C
    signal(SIGINT, catch_signal);
    signal(SIGTERM, catch_signal);
#ifdef SIGTSTP
    signal(SIGTSTP, catch_signal);
#endif
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
    end_call_str = end_call_sa.take_string();

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
