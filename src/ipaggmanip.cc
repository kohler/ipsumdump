#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <click/config.h>
#include <click/clp.h>
#include <click/error.hh>
#include <click/confparse.hh>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include "aggtree.hh"

#define HELP_OPT	300
#define VERSION_OPT	301
#define READ_FILE_OPT	302
#define OUTPUT_OPT	303

#define NNZ_ACT		400
#define NNZ_PREFIX_ACT	401
#define NNZ_DISCRIM_ACT	402
#define PREFIX_ACT	403

static Clp_Option options[] = {

  { "help", 'h', HELP_OPT, 0, 0 },
  { "version", 'v', VERSION_OPT, 0, 0 },

  { "read-file", 'r', READ_FILE_OPT, Clp_ArgString, 0 },
  { "output", 'o', OUTPUT_OPT, Clp_ArgString, 0 },

  { "num", 'n', NNZ_ACT, 0, 0 },
  { "num-nonzero", 'n', NNZ_ACT, 0, 0 },
  { "num-in-prefixes", 0, NNZ_PREFIX_ACT, 0, 0 },
  { "num-discriminated-by-prefix", 0, NNZ_DISCRIM_ACT, 0, 0 },
  { "prefix", 'p', PREFIX_ACT, Clp_ArgUnsigned, 0 },
  
};

static const char *program_name;

void
die_usage(const char *specific = 0)
{
    ErrorHandler *errh = ErrorHandler::default_handler();
    if (specific)
	errh->error("%s: %s", program_name, specific);
    errh->fatal("Usage: %s...\n\
Try `%s --help' for more information.",
		program_name, program_name);
    // should not get here, but just in case...
    exit(1);
}

void
usage()
{
  printf("\
%s kCRPA\n\
Report bugs to <kohler@aciri.org>.\n", program_name);
}

static void
write_vector(const Vector<uint32_t> &v, FILE *f)
{
    for (int i = 0; i < v.size(); i++)
	fprintf(f, (i ? " %u" : "%u"), v[i]);
    fprintf(f, "\n");
}

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

    int action = 0;
    uint32_t action_extra = 0;
    Vector<String> files;
    String output;
    
    while (1) {
	int opt = Clp_Next(clp);
	switch (opt) {

	  case OUTPUT_OPT:
	    if (output)
		die_usage("`--output' already specified");
	    output = clp->arg;
	    break;
	    
	  case READ_FILE_OPT:
	    files.push_back(clp->arg);
	    break;

	  case HELP_OPT:
	    usage();
	    exit(0);
	    break;

	  case VERSION_OPT:
	    printf("aciri-aggmanip %s (libclick-%s)\n", "0.0", CLICK_VERSION);
	    printf("Copyright (C) 2001 International Computer Science Institute\n\
This is free software; see the source for copying conditions.\n\
There is NO warranty, not even for merchantability or fitness for a\n\
particular purpose.\n");
	    exit(0);
	    break;

	  case NNZ_ACT:
	  case NNZ_PREFIX_ACT:
	  case NNZ_DISCRIM_ACT:
	    if (action)
		die_usage("action already specified");
	    action = opt;
	    break;

	  case PREFIX_ACT:
	    if (action)
		die_usage("action already specified");
	    if (clp->val.u > 32)
		die_usage("`--prefix' must be between 0 and 32");
	    action = opt;
	    action_extra = clp->val.u;
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
	    assert(0);
	    break;
	    
	}
    }
  
  done:
    // check file usage
    if (!files.size())
	files.push_back("-");
    if (!output)
	output = "-";

    FILE *out;
    if (output == "-")
	out = stdout;
    else
	out = fopen(output, "w");
    if (!out)
	errh->fatal("%s: %s", output.cc(), strerror(errno));
    
    for (int i = 0; i < files.size(); i++) {
	FILE *f;
	if (files[i] == "-") {
	    f = stdin;
	    files[i] = "<stdin>";
	} else
	    f = fopen(files[i], "rb");
	if (!f)
	    errh->fatal("%s: %s", files[i].cc(), strerror(errno));

	AggregateTree tree;
	tree.read_file(f, errh);

	if (f != stdin)
	    fclose(f);

	switch (action) {
	    
	  case NNZ_ACT:
	    fprintf(out, "%u\n", tree.num_nonzero());
	    break;

	  case NNZ_PREFIX_ACT: {
	      Vector<uint32_t> nnzp;
	      tree.num_nonzero_in_prefixes(nnzp);
	      write_vector(nnzp, out);
	      break;
	  }

	  case NNZ_DISCRIM_ACT: {
	      Vector<uint32_t> nnzp;
	      tree.num_discriminated_by_prefix(nnzp);
	      write_vector(nnzp, out);
	      break;
	  }

	  case PREFIX_ACT: {
	      tree.mask_to_prefix(action_extra);
	      tree.write_file(out, true, errh);
	      break;
	  }
	  
	}
    }
    
    exit(0);
}
