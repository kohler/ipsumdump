#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <click/config.h>
#include <click/clp.h>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/router.hh>
#include <click/lexer.hh>
#include <click/llrpc.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "toipsumdump.hh"
#include "bailerror.hh"

#define HELP_OPT	300
#define VERSION_OPT	301
#define INTERFACE_OPT	302
#define READ_DUMP_OPT	303
#define OUTPUT_OPT	304
#define CONFIG_OPT	305
#define WRITE_DUMP_OPT	306
#define FILTER_OPT	307
#define VERBOSE_OPT	308
#define ANONYMIZE_OPT	309
#define MAP_PREFIX_OPT	310

// options for logging
#define FIRST_LOG_OPT	1000
#define TIMESTAMP_OPT	(1000 + ToIPSummaryDump::W_TIMESTAMP)
#define SRC_OPT		(1000 + ToIPSummaryDump::W_SRC)
#define DST_OPT		(1000 + ToIPSummaryDump::W_DST)
#define SPORT_OPT	(1000 + ToIPSummaryDump::W_SPORT)
#define DPORT_OPT	(1000 + ToIPSummaryDump::W_DPORT)
#define LENGTH_OPT	(1000 + ToIPSummaryDump::W_LENGTH)
#define IPID_OPT	(1000 + ToIPSummaryDump::W_IPID)
#define PROTO_OPT	(1000 + ToIPSummaryDump::W_PROTO)

static Clp_Option options[] = {

  { "help", 'h', HELP_OPT, 0, 0 },
  { "version", 'v', VERSION_OPT, 0, 0 },
  { "verbose", 'V', VERBOSE_OPT, 0, Clp_Negate },

  { "interface", 'i', INTERFACE_OPT, Clp_ArgString, 0 },
  { "read-tcpdump", 'r', READ_DUMP_OPT, Clp_ArgString, 0 },
  { "write-tcpdump", 'w', WRITE_DUMP_OPT, Clp_ArgString, 0 },
  { "filter", 'f', FILTER_OPT, Clp_ArgString, 0 },
  { "anonymize", 'A', ANONYMIZE_OPT, 0, Clp_Negate },
  { "map-prefix", 0, MAP_PREFIX_OPT, Clp_ArgString, 0 },
  { "map-address", 0, MAP_PREFIX_OPT, Clp_ArgString, 0 },
  
  { "output", 'o', OUTPUT_OPT, Clp_ArgString, 0 },
  { "config", 0, CONFIG_OPT, 0, 0 },

  { "log-timestamps", 't', TIMESTAMP_OPT, 0, Clp_Negate },
  { "log-src", 's', SRC_OPT, 0, Clp_Negate },
  { "log-dst", 'd', DST_OPT, 0, Clp_Negate },
  { "log-sport", 'S', SPORT_OPT, 0, Clp_Negate },
  { "log-dport", 'D', DPORT_OPT, 0, Clp_Negate },
  { "log-length", 'l', LENGTH_OPT, 0, Clp_Negate },
  { "log-id", 0, IPID_OPT, 0, Clp_Negate },
  { "log-protocol", 'p', PROTO_OPT, 0, Clp_Negate },
  
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
    errh->fatal("Usage: %s [-i INTERFACE | -r FILE] [OPTION]...\n\
Try `%s --help' for more information.",
		program_name, program_name);
    // should not get here, but just in case...
    exit(1);
}

void
usage()
{
  printf("\
`Aciri-ipsumdump' reads IP packets from the network or a tcpdump(1) file and\n\
summarizes their contents in an ASCII log. It generally runs until interrupted.\n\
\n\
Usage: %s [-i INTERFACE | -r FILE] [CONTENT OPTIONS] > LOGFILE\n\
\n\
Options that determine log contents (can give multiple options):\n\
  -t, --log-timestamps       Log packet timestamps.\n\
  -s, --log-src              Log IP source addresses.\n\
  -d, --log-dst              Log IP destination addresses.\n\
  -S, --log-sport            Log TCP/UDP source ports.\n\
  -D, --log-dport            Log TCP/UDP destination ports.\n\
  -l, --log-length           Log IP length field.\n\
  -p, --log-protocol         Log IP protocol.\n\
      --log-id               Log IP ID.\n\
Default contents option is `-sd' (log source and destination addresses).\n\
\n\
Other options:\n\
  -i, --interface DEVNAME    Read packets from network device DEVNAME.\n\
  -r, --read-tcpdump FILE    Read packets from tcpdump(1) file FILE.\n\
  -w, --write-tcpdump FILE   Also dump packets to FILE in tcpdump(1) format.\n\
  -o, --output FILE          Write summary dump to FILE (default stdout).\n\
  -A, --anonymize            Anonymize IP addresses (preserves prefix & class).\n\
      --map-addr ADDRS       When done, print to stdout the anonymized IP\n\
                             addresses and/or prefixes corresponding to ADDRS.\n\
      --config               Output Click configuration and exit.\n\
  -V, --verbose              Report errors verbosely.\n\
  -h, --help                 Print this message and exit.\n\
  -v, --version              Print version number and exit.\n\
\n\
Report bugs to <kohler@aciri.org>.\n", program_name);
}

static void
catch_sigint(int)
{
  signal(SIGINT, SIG_DFL);
  if (!started)
    kill(getpid(), SIGINT);
  router->please_stop_driver();
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

    String interface;
    String read_dump;
    String write_dump;
    String output;
    String filter;
    Vector<uint32_t> map_prefixes;
    bool config = false;
    bool verbose = false;
    bool anonymize = false;
    int log_contents = -1;
    
    while (1) {
	int opt = Clp_Next(clp);
	switch (opt) {

	  case OUTPUT_OPT:
	    if (output)
		die_usage("`--output' already specified");
	    output = clp->arg;
	    break;
	    
	  case INTERFACE_OPT:
	    if (interface)
		die_usage("`--interface' already specified");
	    interface = clp->arg;
	    break;
	    
	  case READ_DUMP_OPT:
	    if (read_dump)
		die_usage("`--read-tcpdump' already specified");
	    read_dump = clp->arg;
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
		      die_usage("bad argument to `--map-prefix'");
		  map_prefixes.push_back(addr.addr());
		  map_prefixes.push_back(mask.addr());
	      }
	      break;
	  }
	  
	  case CONFIG_OPT:
	    config = true;
	    break;
	    
	  case HELP_OPT:
	    usage();
	    exit(0);
	    break;

	  case VERSION_OPT:
	    printf("aciri-ipsumdump %s (libclick-%s)\n", IPSUMDUMP_VERSION, CLICK_VERSION);
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
	  case Clp_BadOption:
	    die_usage();
	    break;

	  case Clp_Done:
	    goto done;

	  default:
	    assert(opt >= FIRST_LOG_OPT);
	    if (log_contents < 0)
		log_contents = 0;
	    if (clp->negated)
		log_contents &= ~(1 << (opt - FIRST_LOG_OPT));
	    else
		log_contents |= (1 << (opt - FIRST_LOG_OPT));
	    break;
	    
	}
    }
  
  done:
    StringAccum sa;

    // check file usage
    if (!output)
	output = "-";
    if (output == "-" && write_dump == "-")
	p_errh->fatal("standard output used for both log output and tcpdump output");

    // elements to read packets
    if (interface && read_dump)
	die_usage("can't give both `--interface' and `--read-tcpdump'");
    else if (interface)
	sa << "FromDevice(" << interface << ", SNAPLEN 60, FORCE_IP true, BPF_FILTER " << cp_quote(filter) << ")\n";
    else if (read_dump) {
	sa << "FromDump(" << read_dump << ", FORCE_IP true, STOP true)\n";
	if (filter)
	    sa << "  -> IPClassifier(" << filter << ")\n";
    } else
	die_usage("must supply either `--interface' or `--read-tcpdump'");

    // possible elements to anonymize packets
    if (anonymize)
	sa << "  -> anon :: AnonymizeIPAddr(CLASS 4)\n";
    
    // possible elements to write tcpdump file
    if (write_dump)
	sa << "  -> { input -> t :: Tee -> output; t[1] -> ToDump(" << write_dump << ") }\n";
    
    // elements to dump summary log
    if (log_contents < 0)
	log_contents = (1 << ToIPSummaryDump::W_SRC) | (1 << ToIPSummaryDump::W_DST);
    else if (!log_contents)
	die_usage("nothing to log! (Supply one or more log contents options.)");
    if (!output)
	output = "-";
    sa << "  -> ToIPSummaryDump(" << output << ", CONTENTS";
    for (int i = 0; i < 31; i++)
	if (log_contents & (1 << i))
	    sa << ' ' << cp_quote(ToIPSummaryDump::content_name(i));
    sa << ", VERBOSE true, BANNER ";
    // create banner
    StringAccum banner;
    for (int i = 0; i < argc; i++)
	banner << argv[i] << ' ';
    banner.pop_back();
    sa << cp_quote(banner.take_string()) << ")\n";

    // output config if required
    if (config) {
	printf("%s", sa.cc());
	exit(0);
    }

    // catch control-C
    signal(SIGINT, catch_sigint);
    // do NOT ignore SIGPIPE

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
    if (errh->nerrors() > 0 || router->initialize(click_errh, verbose) < 0)
	exit(1);

    // run driver
    started = true;
    router->thread(0)->driver();

    // print result of mapping addresses &/or prefixes
    if (anonymize) {
	Element *anon = router->find("anon");
	assert(anon);
	for (int i = 0; i < map_prefixes.size(); i += 2) {
	    IPAddress addr(map_prefixes[i]), mask(map_prefixes[i+1]);
	    anon->local_llrpc(CLICK_LLRPC_MAP_IPADDRESS, addr.data());
	    addr &= mask;
	    if (mask == 0xFFFFFFFFU)
		printf("%s\n", addr.unparse().cc());
	    else
		printf("%s\n", addr.unparse_with_mask(mask).cc());
	}
    } else
	for (int i = 0; i < map_prefixes.size(); i += 2) {
	    IPAddress addr(map_prefixes[i]), mask(map_prefixes[i+1]);
	    if (mask == 0xFFFFFFFFU)
		printf("%s\n", addr.unparse().cc());
	    else
		printf("%s\n", addr.unparse_with_mask(mask).cc());
	}
    
    // exit
    delete router;
    exit(0);
}
