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
#define MAP_PREFIX_OPT	308
#define MULTIPACKET_OPT	309
#define SAMPLE_OPT	310
#define COLLATE_OPT	311
#define RANDOM_SEED_OPT	312
#define PROMISCUOUS_OPT	313
#define WRITE_DROPS_OPT	314

// data sources
#define INTERFACE_OPT	400
#define READ_DUMP_OPT	401
#define READ_NETFLOW_SUMMARY_OPT 402
#define READ_IPSUMDUMP_OPT 403

static Clp_Option options[] = {

    { "help", 'h', HELP_OPT, 0, 0 },
    { "version", 'v', VERSION_OPT, 0, 0 },
    { "verbose", 'V', VERBOSE_OPT, 0, Clp_Negate },

    { "interface", 'i', INTERFACE_OPT, 0, 0 },
    { "tcpdump", 'r', READ_DUMP_OPT, 0, 0 },
    { "read-tcpdump", 0, READ_DUMP_OPT, 0, 0 },
    { "netflow-summary", 0, READ_NETFLOW_SUMMARY_OPT, 0, 0 },
    { "read-netflow-summary", 0, READ_NETFLOW_SUMMARY_OPT, 0, 0 },
    { "ipsumdump", 0, READ_IPSUMDUMP_OPT, 0, 0 },
    { "read-ipsumdump", 0, READ_IPSUMDUMP_OPT, 0, 0 },
    
    { "write-tcpdump", 'w', WRITE_DUMP_OPT, Clp_ArgString, 0 },
    { "filter", 'f', FILTER_OPT, Clp_ArgString, 0 },
    { "anonymize", 'A', ANONYMIZE_OPT, 0, Clp_Negate },
    { "map-prefix", 0, MAP_PREFIX_OPT, Clp_ArgString, 0 },
    { "map-address", 0, MAP_PREFIX_OPT, Clp_ArgString, 0 },
    { "multipacket", 0, MULTIPACKET_OPT, 0, Clp_Negate },
    { "sample", 0, SAMPLE_OPT, Clp_ArgDouble, Clp_Negate },
    { "collate", 0, COLLATE_OPT, 0, Clp_Negate },
    { "random-seed", 0, RANDOM_SEED_OPT, Clp_ArgUnsigned, 0 },
    { "promiscuous", 0, PROMISCUOUS_OPT, 0, Clp_Negate },
    { "record-counts", 0, WRITE_DROPS_OPT, Clp_ArgString, 0 },

    { "output", 'o', OUTPUT_OPT, Clp_ArgString, 0 },
    { "config", 0, CONFIG_OPT, 0, 0 },

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
`Ipsumdump' reads IP packets from the tcpdump(1) files, or network interfaces,\n\
and summarizes their contents in an ASCII log.\n\
\n\
Usage: %s [CONTENT OPTIONS] [-i DEVNAMES | FILES] > LOGFILE\n\
\n\
Options that determine summary dump contents (can give multiple options):\n\
  -t, --timestamp            Include packet timestamps.\n\
  -s, --src                  Include IP source addresses.\n\
  -d, --dst                  Include IP destination addresses.\n\
  -S, --sport                Include TCP/UDP source ports.\n\
  -D, --dport                Include TCP/UDP destination ports.\n\
  -l, --length               Include IP lengths.\n\
  -p, --protocol             Include IP protocols.\n\
      --id                   Include IP IDs.\n\
  -g, --fragment             Include IP fragment flags (`F' or `.').\n\
  -G, --fragment-offset      Include IP fragment offsets.\n\
  -Q, --tcp-seq              Include TCP sequence numbers.\n\
  -K, --tcp-ack              Include TCP acknowledgement numbers.\n\
  -F, --tcp-flags            Include TCP flags words.\n\
  -L, --payload-length       Include payload lengths (no IP/UDP/TCP headers).\n\
  -c, --packet-count         Include packet count (usually 1).\n\
Default contents option is `-sd' (log source and destination addresses).\n\
\n\
Data source options (give exactly one):\n\
  -i, --interface            Read packets from network devices DEVNAMES until\n\
                             interrupted.\n\
  -r, --tcpdump              Read packets from tcpdump(1) FILES (default).\n\
      --netflow-summary      Read summarized NetFlow FILES.\n\
      --ipsumdump            Read from existing ipsumdump FILES.\n\
\n\
Other options:\n\
  -o, --output FILE          Write summary dump to FILE (default stdout).\n\
  -w, --write-tcpdump FILE   Also dump packets to FILE in tcpdump(1) format.\n\
  -f, --filter FILTER        Apply tcpdump(1) filter FILTER to data.\n\
  -A, --anonymize            Anonymize IP addresses (preserves prefix & class).\n\
      --no-promiscuous       Do not put interfaces into promiscuous mode.\n\
      --sample PROB          Sample packets with PROB probability.\n\
      --multipacket          Produce multiple entries for a flow identifier\n\
                             representing multiple packets (NetFlow only).\n\
      --collate              Collate packets from data sources by timestamp.\n\
      --map-address ADDRS    When done, print to stderr the anonymized IP\n\
                             addresses and/or prefixes corresponding to ADDRS.\n\
      --record-counts TIME   Record packet counts every TIME seconds in output.\n\
      --random-seed SEED     Set random seed to SEED (default is random).\n\
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

extern void export_elements(Lexer *);

int
main(int argc, char *argv[])
{
    Clp_Parser *clp = Clp_NewParser
	(argc, argv, sizeof(options) / sizeof(options[0]), options);
    program_name = Clp_ProgramName(clp);
    
    String::static_initialize();
    cp_va_static_initialize();
    ErrorHandler *errh = new FileErrorHandler(stderr, "");
    ErrorHandler::static_initialize(errh);
    ErrorHandler *p_errh = new PrefixErrorHandler(errh, program_name + String(": "));

    String write_dump;
    String output;
    String filter;
    bool config = false;
    bool verbose = false;
    bool anonymize = false;
    bool multipacket = false;
    double sample = 0;
    bool do_sample = false;
    bool collate = false;
    int action = 0;
    bool do_seed = true;
    bool promisc = true;
    Vector<String> files;
    const char *record_drops = 0;
    
    while (1) {
	int opt = Clp_Next(clp);
	switch (opt) {

	  case OUTPUT_OPT:
	    if (output)
		die_usage("`--output' already specified");
	    output = clp->arg;
	    break;
	    
	  case INTERFACE_OPT:
	  case READ_DUMP_OPT:
	  case READ_NETFLOW_SUMMARY_OPT:
	  case READ_IPSUMDUMP_OPT:
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

	  case PROMISCUOUS_OPT:
	    promisc = !clp->negated;

	  case WRITE_DROPS_OPT:
	    record_drops = clp->arg;
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
	    files.push_back(cp_quote(clp->arg));
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
    if (output == "-" && write_dump == "-")
	p_errh->fatal("standard output used for both summary output and tcpdump output");

    // set random seed if appropriate
    if (do_seed && (do_sample || anonymize))
	click_random_srandom();

    // define shunt
    String shunt_internals = "";
    StringAccum psa;
    String sample_elt;
    int snaplen = (write_dump ? 2000 : 68);
    
    // elements to read packets
    if (action == 0)
	action = READ_DUMP_OPT;
    if (action == INTERFACE_OPT) {
	if (files.size() == 0)
	    p_errh->fatal("`-i' option takes at least one DEVNAME");
	if (collate)
	    p_errh->fatal("`--collate' may not be used with `--interface' yet");
	String config = ", SNAPLEN " + String(snaplen) + ", FORCE_IP true";
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
	
    } else if (action == READ_DUMP_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", FORCE_IP true, STOP true";
	if (do_sample)
	    config += ", SAMPLE " + String(sample);
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromDump(" << files[i] << config << ") -> " << source_output_port(collate, i) << ";\n";
	sample_elt = "src0";
	
    } else if (action == READ_NETFLOW_SUMMARY_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", STOP true";
	if (multipacket)
	    config += ", MULTIPACKET true";
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromNetFlowSummaryDump(" << files[i] << config << ") -> " << source_output_port(collate, i) << ";\n";
	if (do_sample) {
	    shunt_internals = " -> samp :: RandomSample(" + String(sample) + ")";
	    sample_elt = "shunt/samp";
	    if (!multipacket)
		p_errh->warning("`--sample' option will sample flows, not packets\n(If you want to sample packets, use `--multipacket'.)");
	}
	
    } else if (action == READ_IPSUMDUMP_OPT) {
	if (files.size() == 0)
	    files.push_back("-");
	String config = ", STOP true, ZERO true";
	if (do_sample)
	    config += ", SAMPLE " + String(sample);
	if (multipacket)
	    config += ", MULTIPACKET true";
	for (int i = 0; i < files.size(); i++)
	    psa << "src" << i << " :: FromIPSummaryDump(" << files[i] << config << ") -> " << source_output_port(collate, i) << ";\n";
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
    
    // elements to dump summary log
    if (!output)
	output = "-";
    sa << "  -> to_dump :: ToIPSummaryDump(" << output << ", CONTENTS";
    sa << ", VERBOSE true, BANNER ";
    // create banner
    StringAccum banner;
    for (int i = 0; i < argc; i++)
	banner << argv[i] << ' ';
    banner.pop_back();
    sa << cp_quote(banner.take_string()) << ");\n";

    // record drops
    if (record_drops)
	sa << "PokeHandlers(" << record_drops << ", record_counts '', loop);\n";

    sa << "DriverManager(";
    if ((files.size() > 1 && action != INTERFACE_OPT) || collate) {
	sa << "wait_stop " << (files.size() - 1) + (collate ? 1 : 0);
	stop_driver_count = files.size() + (collate ? 1 : 0);
    }
    // print `!counts' message if appropriate
    if (action == INTERFACE_OPT)
	sa << ", wait_stop, write record_counts ''";
    sa << ");\n";

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
    router->add_global_write_handler("record_counts", record_drops_hook, 0);
    if (errh->nerrors() > 0 || router->initialize(click_errh, verbose) < 0)
	exit(1);
    
    // run driver
    started = true;
    router->thread(0)->driver();

    // exit
    delete router;
    exit(0);
}
