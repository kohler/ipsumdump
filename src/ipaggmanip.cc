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
#include "aggwtree.hh"

#define HELP_OPT	300
#define VERSION_OPT	301
#define READ_FILE_OPT	302
#define OUTPUT_OPT	303

#define FIRST_ACT		400
#define PREFIX_ACT		400
#define POSTERIZE_ACT		401
#define SAMPLE_ACT		402
#define CUT_SMALLER_ACT		403
#define CULL_HOSTS_ACT		404
#define CULL_HOSTS_BY_PACKETS_ACT 405
#define CULL_PACKETS_ACT	406

#define FIRST_END_ACT		500
#define NNZ_ACT			500
#define NNZ_PREFIX_ACT		501
#define NNZ_LEFT_PREFIX_ACT	502
#define NNZ_DISCRIM_ACT		503
#define AVG_VAR_ACT		504
#define AVG_VAR_PREFIX_ACT	505
#define HAAR_WAVELET_ENERGY_ACT	506
#define SIZES_ACT		507
#define SORTED_SIZES_ACT	508

static Clp_Option options[] = {

  { "help", 'h', HELP_OPT, 0, 0 },
  { "version", 'v', VERSION_OPT, 0, 0 },

  { "read-file", 'r', READ_FILE_OPT, Clp_ArgString, 0 },
  { "output", 'o', OUTPUT_OPT, Clp_ArgString, 0 },

  { "num", 'n', NNZ_ACT, 0, 0 },
  { "num-nonzero", 'n', NNZ_ACT, 0, 0 },
  { "nnz", 'n', NNZ_ACT, 0, 0 },
  { "num-in-prefixes", 0, NNZ_PREFIX_ACT, 0, 0 },
  { "nnz-in-prefixes", 0, NNZ_PREFIX_ACT, 0, 0 },
  { "num-in-left-prefixes", 0, NNZ_LEFT_PREFIX_ACT, 0, 0 },
  { "nnz-in-left-prefixes", 0, NNZ_LEFT_PREFIX_ACT, 0, 0 },
  { "num-discriminated-by-prefix", 0, NNZ_DISCRIM_ACT, 0, 0 },
  { "nnz-discriminated-by-prefix", 0, NNZ_DISCRIM_ACT, 0, 0 },
  { "prefix", 'p', PREFIX_ACT, Clp_ArgUnsigned, 0 },
  { "posterize", 'P', POSTERIZE_ACT, 0, 0 },
  { "average-and-variance", 0, AVG_VAR_ACT, 0, 0 },
  { "avg-var", 0, AVG_VAR_ACT, 0, 0 },
  { "average-and-variance-by-prefix", 0, AVG_VAR_PREFIX_ACT, 0, 0 },
  { "avg-var-by-prefix", 0, AVG_VAR_PREFIX_ACT, 0, 0 },
  { "sample", 0, SAMPLE_ACT, Clp_ArgUnsigned, 0 },
  { "cut-smaller", 0, CUT_SMALLER_ACT, Clp_ArgUnsigned, 0 },
  { "cull-hosts", 0, CULL_HOSTS_ACT, Clp_ArgUnsigned, 0 },
  { "cull-hosts-by-packets", 0, CULL_HOSTS_BY_PACKETS_ACT, Clp_ArgUnsigned, 0 },
  { "cull-packets", 0, CULL_PACKETS_ACT, Clp_ArgUnsigned, 0 },
  { "haar-wavelet-energy", 0, HAAR_WAVELET_ENERGY_ACT, 0, 0 },
  { "sizes", 0, SIZES_ACT, 0, 0 },
  { "sorted-sizes", 0, SORTED_SIZES_ACT, 0, 0 },
  
};

static const char *program_name;

static void
die_usage(const char *specific = 0)
{
    ErrorHandler *errh = ErrorHandler::default_handler();
    if (specific)
	errh->error("%s: %s", program_name, specific);
    errh->fatal("Usage: %s ACTION [FILE]\n\
Try `%s --help' for more information.",
		program_name, program_name);
    // should not get here, but just in case...
    exit(1);
}

static void
usage()
{
  printf("\
`Aciri-aggmanip' reads a summary of aggregated IP data from a file, transforms\n\
that summary or calculates one of its statistics, and writes the result to\n\
standard output.\n\
\n\
Usage: %s ACTION [ACTIONS...] [FILES] > OUTPUT\n\
\n\
Actions: (Results of final action sent to output.)\n\
  -n, --num-nonzero          Number of nonzero hosts.\n\
      --nnz-in-prefixes      Number of nonzero p-aggregates for all p.\n\
      --nnz-in-left-prefixes Number nonzero left-hand p-aggregates for all p.\n\
      --nnz-discriminated-by-prefix\n\
                             Number of nonzero hosts with discriminating prefix\n\
                             p for all p.\n\
      --sizes                All nonzero aggregate sizes in arbitrary order.\n\
      --sorted-sizes         All nonzero aggregate sizes in decreasing order\n\
                             by size.\n\
  -p, --prefix P             Aggregate to prefix level P.\n\
  -P, --posterize            Replace all nonzero counts with 1.\n\
      --sample N             Reduce counts by randomly sampling 1 in N.\n\
      --cull-hosts N         Reduce --num-nonzero to at most N by removing\n\
                             randomly selected hosts.\n\
      --cull-hosts-by-packets N\n\
                             Reduce --num-nonzero to at most N by removing\n\
                             randomly selected packets.\n\
      --cull-packets N       Reduce total number of packets to at most N by
                             removing randomly selected packets.\n\
      --cut-smaller N        Zero counts less than N.\n\
      --average-and-variance, --avg-var\n\
                             Average and variance of nonzero hosts.\n\
      --average-and-variance-by-prefix, --avg-var-by-prefix\n\
                             Average and variance of nonzero p-aggregates for\n\
                             all p.\n\
      --haar-wavelet-energy  Haar wavelet energy coefficients.\n\
\n\
Other options:\n\
  -r, --read FILE            Read summary from FILE (default stdin).\n\
  -o, --output FILE          Write output to FILE (default stdout).\n\
  -h, --help                 Print this message and exit.\n\
  -v, --version              Print version number and exit.\n\
\n\
Report bugs to <kohler@aciri.org>.\n", program_name);
}

static void
write_vector(const Vector<uint32_t> &v, FILE *f)
{
    for (int i = 0; i < v.size(); i++)
	fprintf(f, (i ? " %u" : "%u"), v[i]);
    fprintf(f, "\n");
}

static Vector<int> actions;
static Vector<uint32_t> extras;

static void
add_action(int action, uint32_t extra = 0)
{
    if (actions.size() && actions.back() >= FIRST_END_ACT)
	die_usage("can't add another action after that");
    actions.push_back(action);
    extras.push_back(extra);
}

static int
uint32_rev_compar(const void *ap, const void *bp)
{
    uint32_t a = *(reinterpret_cast<const uint32_t *>(ap));
    uint32_t b = *(reinterpret_cast<const uint32_t *>(bp));
    return b - a;
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
    //ErrorHandler *p_errh = new PrefixErrorHandler(errh, program_name + String(": "));

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
	  case NNZ_LEFT_PREFIX_ACT:
	  case NNZ_DISCRIM_ACT:
	  case POSTERIZE_ACT:
	  case AVG_VAR_ACT:
	  case AVG_VAR_PREFIX_ACT:
	  case HAAR_WAVELET_ENERGY_ACT:
	  case SIZES_ACT:
	  case SORTED_SIZES_ACT:
	    add_action(opt);
	    break;

	  case PREFIX_ACT:
	    if (clp->val.u > 32)
		die_usage("`--prefix' must be between 0 and 32");
	    add_action(opt, clp->val.u);
	    break;

	  case SAMPLE_ACT:
	  case CUT_SMALLER_ACT:
	  case CULL_HOSTS_ACT:
	  case CULL_HOSTS_BY_PACKETS_ACT:
	  case CULL_PACKETS_ACT:
	    add_action(opt, clp->val.u);
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

    if (!actions.size())
	die_usage("no action specified");
    
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

	// go through earlier actions
	for (int j = 0; j < actions.size(); j++) {
	    int action = actions[j];
	    uint32_t action_extra = extras[j];
	    switch (action) {
		
	      case PREFIX_ACT:
		tree.mask_data_to_prefix(action_extra);
		break;

	      case POSTERIZE_ACT:
		tree.posterize();
		break;

	      case SAMPLE_ACT:
		tree.sample(1. / action_extra);
		break;
		
	      case CUT_SMALLER_ACT:
		tree.cut_smaller(action_extra);
		break;

	      case CULL_HOSTS_ACT: {
		  AggregateWTree wtree(tree, false);
		  wtree.cull_hosts(action_extra);
		  tree = wtree;
		  break;
	      }
	      
	      case CULL_HOSTS_BY_PACKETS_ACT: {
		  AggregateWTree wtree(tree, true);
		  wtree.cull_hosts_by_packets(action_extra);
		  tree = wtree;
		  break;
	      }
	      
	      case CULL_PACKETS_ACT: {
		  AggregateWTree wtree(tree, true);
		  wtree.cull_packets(action_extra);
		  tree = wtree;
		  break;
	      }
	      
	    }
	}

	// output result of final action
	int action = actions.back();
	switch (action) {
	    
	  case NNZ_ACT:
	    fprintf(out, "%u\n", tree.num_nonzero());
	    break;

	  case NNZ_PREFIX_ACT: {
	      Vector<uint32_t> nnzp;
	      tree.nnz_in_prefixes(nnzp);
	      write_vector(nnzp, out);
	      break;
	  }

	  case NNZ_LEFT_PREFIX_ACT: {
	      Vector<uint32_t> nnzp;
	      tree.nnz_in_left_prefixes(nnzp);
	      write_vector(nnzp, out);
	      break;
	  }

	  case NNZ_DISCRIM_ACT: {
	      Vector<uint32_t> nnzp;
	      tree.nnz_discriminated_by_prefix(nnzp);
	      write_vector(nnzp, out);
	      break;
	  }

	  case AVG_VAR_ACT: {
	      double sum, sum_sq;
	      tree.sum_and_sum_sq(&sum, &sum_sq);
	      uint32_t nnz = tree.nnz();
	      fprintf(out, "%.20g %.20g\n", sum / nnz, (sum_sq - sum*sum/nnz) / nnz);
	      break;
	  }

	  case AVG_VAR_PREFIX_ACT: {
	      double avg[33], var[33];
	      for (int i = 32; i >= 0; i--) {
		  double sum, sum_sq;
		  tree.mask_data_to_prefix(i);
		  tree.sum_and_sum_sq(&sum, &sum_sq);
		  uint32_t nnz = tree.nnz();
		  avg[i] = sum / nnz;
		  var[i] = sum_sq / nnz - avg[i] * avg[i];
	      }
	      for (int i = 0; i <= 32; i++)
		  fprintf(out, "%.20g %.20g\n", avg[i], var[i]);
	      break;
	  }

	  case HAAR_WAVELET_ENERGY_ACT: {
	      Vector<double> energy;
	      tree.haar_wavelet_energy_coeff(energy);
	      for (int i = 0; i < 32; i++)
		  fprintf(out, "%.20g ", energy[i]);
	      fprintf(out, "\n");
	      break;
	  }

	  case SIZES_ACT:
	  case SORTED_SIZES_ACT: {
	      Vector<uint32_t> sizes;
	      tree.nonzero_sizes(sizes);
	      if (action == SORTED_SIZES_ACT && sizes.size())
		  qsort(&sizes[0], sizes.size(), sizeof(uint32_t), uint32_rev_compar);
	      write_vector(sizes, out);
	      break;
	  }
	  
	  case PREFIX_ACT:
	  case POSTERIZE_ACT:
	  case SAMPLE_ACT:
	  case CUT_SMALLER_ACT:
	  case CULL_HOSTS_ACT:
	  case CULL_HOSTS_BY_PACKETS_ACT:
	  case CULL_PACKETS_ACT:
	    tree.write_file(out, true, errh);
	    break;
	  
	}
    }
    
    exit(0);
}

