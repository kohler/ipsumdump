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
#include <math.h>

#include "aggtree.hh"
#include "aggwtree.hh"

#define DOUBLE_FACTOR		1000000000

#define HELP_OPT		300
#define VERSION_OPT		301
#define READ_FILE_OPT		302
#define OUTPUT_OPT		303
#define BINARY_OPT		304
#define ASCII_OPT		305
#define AND_OPT			306
#define OR_OPT			307
#define EACH_OPT		308
#define AND_LIST_OPT		309
#define MINUS_OPT		310
#define XOR_OPT			311
#define ASSIGN_COUNTS_OPT	312

#define FIRST_ACT		400
#define NO_ACT			400
#define PREFIX_ACT		401
#define POSTERIZE_ACT		402
#define SAMPLE_ACT		403
#define CUT_SMALLER_ACT		404
#define CUT_LARGER_ACT		405
#define CULL_ADDRS_ACT		406
#define CULL_ADDRS_BY_PACKETS_ACT 407
#define CULL_PACKETS_ACT	408
#define CUT_SMALLER_AGG_ACT	409
#define CUT_LARGER_AGG_ACT	410
#define CUT_SMALLER_ADDR_AGG_ACT 411
#define CUT_LARGER_ADDR_AGG_ACT	412
#define FAKE_BY_DISCRIM_ACT	413
#define FAKE_BY_BRANCHING_ACT	414
#define FAKE_BY_DIRICHLET_ACT	415

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
#define BALANCE_ACT		509
#define BALANCE_HISTOGRAM_ACT	510
#define ALL_NNZ_DISCRIM_ACT	511
#define COND_SPLIT_ACT		512
#define BRANCHING_ACT		513
#define ALL_BRANCHING_ACT	514
#define SIZE_COUNTS_ACT		515
#define AGG_SIZES_ACT		516
#define AGG_ADDRS_ACT		517
#define CORR_SIZE_AGG_ADDR_ACT	518

#define CLP_TWO_UINTS_TYPE	(Clp_MaxDefaultType + 1)

static Clp_Option options[] = {

  { "help", 'h', HELP_OPT, 0, 0 },
  { "version", 'v', VERSION_OPT, 0, 0 },

  { "read-file", 'r', READ_FILE_OPT, Clp_ArgString, 0 },
  { "output", 'o', OUTPUT_OPT, Clp_ArgString, 0 },
  { "binary", 'B', BINARY_OPT, 0, Clp_Negate },
  { "ascii", 0, ASCII_OPT, 0, Clp_Negate },
  { "and", '&', AND_OPT, 0, 0 },
  { "or", '|', OR_OPT, 0, 0 },
  { "minus", 0, MINUS_OPT, 0, 0 },
  { "xor", '^', XOR_OPT, 0, 0 },
  { "each", 'e', EACH_OPT, 0, 0 },
  { "and-list", 0, AND_LIST_OPT, 0, 0 },
  { "assign-counts", 0, ASSIGN_COUNTS_OPT, 0, 0 },

  { "num", 'n', NNZ_ACT, 0, 0 },
  { "num-nonzero", 'n', NNZ_ACT, 0, 0 },
  { "num-active", 'n', NNZ_ACT, 0, 0 },
  { "nnz", 'N', NNZ_ACT, 0, 0 },
  { "num-in-prefixes", 0, NNZ_PREFIX_ACT, 0, 0 },
  { "nnz-in-prefixes", 0, NNZ_PREFIX_ACT, 0, 0 },
  { "num-in-left-prefixes", 0, NNZ_LEFT_PREFIX_ACT, 0, 0 },
  { "nnz-in-left-prefixes", 0, NNZ_LEFT_PREFIX_ACT, 0, 0 },
  { "discriminating-prefix-counts", 0, NNZ_DISCRIM_ACT, 0, 0 },
  { "discpfx-counts", 0, NNZ_DISCRIM_ACT, 0, 0 },
  { "num-discriminated-by-prefix", 0, NNZ_DISCRIM_ACT, 0, 0 },
  { "all-discriminating-prefix-counts", 0, ALL_NNZ_DISCRIM_ACT, 0, 0 },
  { "all-discpfx-counts", 0, ALL_NNZ_DISCRIM_ACT, 0, 0 },
  { "all-num-discriminated-by-prefix", 0, ALL_NNZ_DISCRIM_ACT, 0, 0 },
  { "conditional-split-counts", 0, COND_SPLIT_ACT, Clp_ArgUnsigned, 0 },
  { "prefix", 'p', PREFIX_ACT, Clp_ArgUnsigned, 0 },
  { "posterize", 'P', POSTERIZE_ACT, 0, 0 },
  { "average-and-variance", 0, AVG_VAR_ACT, 0, 0 },
  { "avg-var", 0, AVG_VAR_ACT, 0, 0 },
  { "average-and-variance-by-prefix", 0, AVG_VAR_PREFIX_ACT, 0, 0 },
  { "avg-var-by-prefix", 0, AVG_VAR_PREFIX_ACT, 0, 0 },
  { "sample", 0, SAMPLE_ACT, Clp_ArgUnsigned, 0 },
  { "cut-smaller", 0, CUT_SMALLER_ACT, Clp_ArgUnsigned, 0 },
  { "cut-smaller-aggregates", 0, CUT_SMALLER_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-smaller-host-aggregates", 0, CUT_SMALLER_ADDR_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-smaller-address-aggregates", 0, CUT_SMALLER_ADDR_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-larger", 0, CUT_LARGER_ACT, Clp_ArgUnsigned, 0 },
  { "cut-larger-aggregates", 0, CUT_LARGER_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-larger-host-aggregates", 0, CUT_LARGER_ADDR_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-larger-address-aggregates", 0, CUT_LARGER_ADDR_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cull-addresses", 0, CULL_ADDRS_ACT, Clp_ArgUnsigned, 0 },
  { "cull-addrs", 0, CULL_ADDRS_ACT, Clp_ArgUnsigned, 0 },
  { "cull-hosts", 0, CULL_ADDRS_ACT, Clp_ArgUnsigned, 0 },
  { "cull-addresses-by-packets", 0, CULL_ADDRS_BY_PACKETS_ACT, Clp_ArgUnsigned, 0 },
  { "cull-addrs-by-packets", 0, CULL_ADDRS_BY_PACKETS_ACT, Clp_ArgUnsigned, 0 },
  { "cull-hosts-by-packets", 0, CULL_ADDRS_BY_PACKETS_ACT, Clp_ArgUnsigned, 0 },
  { "cull-packets", 0, CULL_PACKETS_ACT, Clp_ArgUnsigned, 0 },
  { "haar-wavelet-energy", 0, HAAR_WAVELET_ENERGY_ACT, 0, 0 },
  { "sizes", 0, SIZES_ACT, 0, 0 },
  { "sorted-sizes", 0, SORTED_SIZES_ACT, 0, 0 },
  { "size-counts", 0, SIZE_COUNTS_ACT, 0, 0 },
  { "container-sizes", 0, AGG_SIZES_ACT, Clp_ArgUnsigned, 0 },
  { "container-addresses", 0, AGG_ADDRS_ACT, Clp_ArgUnsigned, 0 },
  { "container-addrs", 0, AGG_ADDRS_ACT, Clp_ArgUnsigned, 0 },
  { "balance", 0, BALANCE_ACT, Clp_ArgUnsigned, 0 },
  { "balance-histogram", 0, BALANCE_HISTOGRAM_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "branching-counts", 0, BRANCHING_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "all-branching-counts", 0, ALL_BRANCHING_ACT, Clp_ArgUnsigned, 0 },
  { "fake-by-discriminating-prefixes", 0, FAKE_BY_DISCRIM_ACT, Clp_ArgDouble, Clp_Optional },
  { "fake-by-branching-counts", 0, FAKE_BY_BRANCHING_ACT, Clp_ArgUnsigned, 0 },
  { "fake-by-dirichlet", 0, FAKE_BY_DIRICHLET_ACT, 0, 0 },
  { "correlation-size-container-addresses", 0, CORR_SIZE_AGG_ADDR_ACT, Clp_ArgUnsigned, 0 },
  
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
  -|, --or                   Combine all packets from FILES.\n\
  -&, --and                  Combine FILES, but drop any address not present\n\
                             in every file.\n\
      --and-list             Output results for FILE1, then FILE1 & FILE2,\n\
                             then FILE1 & FILE2 & FILE3, and so on.\n\
      --minus                Drop any address in FILE1 present in any other\n\
                             FILE.\n\
  -^, --xor                  Combine FILES, but drop any address present in\n\
                             more than one FILE.\n\
  -e, --each                 Output result for each FILE separately.\n\
      --assign-counts        Two FILEs with same -N. Assign address counts from\n\
                             FILE1 randomly to addresses in FILE2.\n\
  Also say \"'(+' FILE FILE ... ')'\" to --or particular files, or\n\
  \"'(&' FILE ... ')'\" for --and, \"'(-' FILE ... ')'\" for --minus,\n\
  \"'(^' FILE ... ')'\" for --xor.\n\
\n\
  -N, --num-active           Number of active addresses.\n\
      --num-in-prefixes      Number of active p-aggregates for all p.\n\
      --num-in-left-prefixes Number of active left-hand p-aggregates for all p.\n\
      --discriminating-prefix-counts   Number of active addresses with\n\
                             discriminating prefix p for all p.\n\
      --all-discriminating-prefix-counts   Number of active p-aggregates with\n\
                             p-discriminating prefix q for all p, q.\n\
      --sizes                All active address sizes in address order.\n\
      --sorted-sizes         All active address sizes in reverse size order.\n\
      --size-counts          Counts of active aggregates with each size,\n\
                             in return-separated size-count pairs.\n\
      --container-sizes P    Sizes of P-aggregates containing each address, in\n\
                             address order.\n\
      --balance P            Print left-right balance at prefix level P.\n\
  -p, --prefix P             Aggregate to prefix level P.\n\
  -P, --posterize            Replace all nonzero counts with 1.\n\
      --sample N             Reduce counts by randomly sampling 1 in N.\n\
      --cull-addresses N     Reduce --num-active to at most N by removing\n\
                             randomly selected addresses.\n\
      --cull-addresses-by-packets N   Reduce --num-active to at most N by\n\
                             removing randomly selected packets.\n\
      --cull-packets N       Reduce total number of packets to at most N by
                             removing randomly selected packets.\n\
      --cut-smaller N        Zero counts less than N.\n\
      --cut-larger N         Zero counts greater than or equal to N.\n\
      --cut-smaller-aggregates P,N    Zero counts for P-aggregates with size\n\
                             less than N.
      --cut-larger-aggregates P,N     Zero counts for P-aggregates with size\n\
                             greater than or equal to N.
      --cut-smaller-address-aggregates P,N   Zero counts for P-aggregates with\n\
                             less than N active addresses.\n\
      --cut-larger-address-aggregates P,N    Zero counts for P-aggregates with\n\
                             greater than or equal to N active addresses.\n\
      --fake-by-discriminating-prefixes[=TYP]   Create fake posterized data\n\
                             sharing this data's --all-discriminating-prefix.\n\
                             TYP is a randomness factor between 0 and 1.\n\
      --fake-by-dirichlet\n\
      --average-and-variance, --avg-var\n\
                             Average and variance of active addresses.\n\
      --average-and-variance-by-prefix, --avg-var-by-prefix\n\
                             Average and variance of active p-aggregates for\n\
                             all p.\n\
      --haar-wavelet-energy  Haar wavelet energy coefficients.\n\
      --balance N\n\
      --balance-histogram N,NBUCKETS\n\
      --branching-counts P,STEP\n\
      --all-branching-counts STEP\n\
      --conditional-split-counts P\n\
      --correlation-size-container-addresses P\n\
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
write_vector(const uint32_t *v, int size, FILE *f)
{
    for (int i = 0; i < size; i++)
	fprintf(f, (i ? " %u" : "%u"), v[i]);
    fprintf(f, "\n");
}

static inline void
write_vector(const Vector<uint32_t> &v, FILE *f)
{
    write_vector((v.size() ? &v[0] : 0), v.size(), f);
}

static Vector<int> actions;
static Vector<uint32_t> extras;
static Vector<uint32_t> extras2;
static FILE *out;
static bool output_binary = true;
static Vector<String> files;
static int files_pos = 0;

static void
add_action(int action, uint32_t extra = 0, uint32_t extra2 = 0)
{
    if (actions.size() && actions.back() >= FIRST_END_ACT)
	die_usage("can't add another action after that");
    actions.push_back(action);
    extras.push_back(extra);
    extras2.push_back(extra2);
}

static int
uint32_compar(const void *ap, const void *bp)
{
    uint32_t a = *(reinterpret_cast<const uint32_t *>(ap));
    uint32_t b = *(reinterpret_cast<const uint32_t *>(bp));
    return a - b;
}

static int
uint32_rev_compar(const void *ap, const void *bp)
{
    uint32_t a = *(reinterpret_cast<const uint32_t *>(ap));
    uint32_t b = *(reinterpret_cast<const uint32_t *>(bp));
    return b - a;
}

static int
parse_two_uints(Clp_Parser *clp, const char *arg, int complain, void *)
{
    Vector<String> conf;
    cp_argvec(arg, conf);
    if (conf.size() == 2
	&& cp_va_parse(conf, 0, ErrorHandler::silent_handler(),
		       cpUnsigned, "arg 1", &clp->val.us[0],
		       cpUnsigned, "arg 2", &clp->val.us[1],
		       0) >= 0)
	return 1;
    else if (complain)
	return Clp_OptionError(clp, "`%O' expects two unsigned integers separated by a comma, not `%s'", arg);
    else
	return 0;
}

static void
read_aggregates(AggregateTree &tree, String &name, ErrorHandler *errh)
{
    FILE *f;
    if (name == "-") {
	f = stdin;
	name = "<stdin>";
    } else
	f = fopen(name, "rb");
    if (!f)
	errh->fatal("%s: %s", name.cc(), strerror(errno));
    tree.read_file(f, errh);
    if (f != stdin)
	fclose(f);
}

static String::Initializer initializer;
static String last_filename;

static void
read_next_file(AggregateTree &tree, ErrorHandler *errh, bool recurse = false)
{
    if (files_pos >= files.size()) {
	errh->error("out of files!");
	return;
    }
    
    if (!recurse)
	last_filename = "";
    else
	last_filename += " ";
    
    if (files[files_pos] == "(+" || files[files_pos] == "(|") {
	last_filename += "(+";
	files_pos++;
	while (files_pos < files.size() && files[files_pos] != ")")
	    read_next_file(tree, errh, true);
	if (files_pos >= files.size())
	    errh->warning("missing ')' at end of file list");
	files_pos++;
	last_filename += " )";
	
    } else if (files[files_pos] == "(&") {
	last_filename += "(&";
	files_pos++;
	AggregateTree tree2;
	
	bool read_yet = false;
	while (files_pos < files.size() && files[files_pos] != ")")
	    if (!read_yet)
		read_next_file(tree2, errh, true), read_yet = true;
	    else {
		AggregateTree tree3;
		read_next_file(tree3, errh, true);
		tree2.keep_common_hosts(tree3, true);
	    }
	
	tree += tree2;
	if (files_pos >= files.size())
	    errh->warning("missing ')' at end of file list");
	files_pos++;
	last_filename += " )";
	
    } else if (files[files_pos] == "(-") {
	last_filename += "(-";
	files_pos++;
	AggregateTree tree2;
	
	bool read_yet = false;
	while (files_pos < files.size() && files[files_pos] != ")")
	    if (!read_yet)
		read_next_file(tree2, errh, true), read_yet = true;
	    else {
		AggregateTree tree3;
		read_next_file(tree3, errh, true);
		tree2.drop_common_hosts(tree3);
	    }
	
	tree += tree2;
	if (files_pos >= files.size())
	    errh->warning("missing ')' at end of file list");
	files_pos++;
	last_filename += " )";
	
    } else if (files[files_pos] == "(^") {
	last_filename += "(^";
	files_pos++;
	AggregateTree tree_or;
	AggregateTree tree_or1;
	
	bool read_yet = false;
	while (files_pos < files.size() && files[files_pos] != ")")
	    if (!read_yet) {
		read_next_file(tree_or, errh, true);
		tree_or1 = tree_or;
		read_yet = true;
	    } else {
		AggregateTree tree3;
		read_next_file(tree3, errh, true);
		tree_or1.add_new_hosts(tree3);
		tree_or += tree3;
	    }

	tree_or.drop_common_unequal_hosts(tree_or1);
	tree += tree_or;
	if (files_pos >= files.size())
	    errh->warning("missing ')' at end of file list");
	files_pos++;
	last_filename += " )";
	
    } else {
	read_aggregates(tree, files[files_pos], errh);
	last_filename += files[files_pos];
	files_pos++;
    }
}

static bool
more_files()
{
    return (files_pos < files.size());
}

static double
correlation_coefficient(const Vector<uint32_t> &a, const Vector<uint32_t> &b)
{
    assert(a.size() == b.size());
    double a_sum = 0, b_sum = 0, a2_sum = 0, b2_sum = 0, ab_sum = 0;
    uint32_t n = a.size();
    
    for (uint32_t i = 0; i < n; i++) {
	a_sum += a[i];
	a2_sum += (double) a[i] * a[i];
	b_sum += b[i];
	b2_sum += (double) b[i] * b[i];
	ab_sum += (double) a[i] * b[i];
    }

    double a_avg = a_sum / n, b_avg = b_sum / n;
    double a_varx = a2_sum - a_sum * a_avg;
    double b_varx = b2_sum - b_sum * b_avg;
    double ab_covarx = ab_sum - a_avg * b_sum - b_avg * a_sum + n * a_avg * b_avg;
    return ab_covarx / sqrt(a_varx * b_varx);
}

static void
process_tree_actions(AggregateTree &tree, ErrorHandler *errh)
{
    (void) errh;
    
    // go through earlier actions
    for (int j = 0; j < actions.size(); j++) {
	int action = actions[j];
	uint32_t action_extra = extras[j];
	uint32_t action_extra2 = extras2[j];
	switch (action) {
		
	  case PREFIX_ACT:
	    tree.prefixize(action_extra);
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

	  case CUT_LARGER_ACT:
	    tree.cut_larger(action_extra);
	    break;

	  case CUT_SMALLER_AGG_ACT:
	    tree.cut_smaller_aggregates(action_extra, action_extra2);
#ifdef SELFTEST
	    {
		AggregateTree xtree;
		tree.make_prefix(action_extra, xtree);
		uint32_t nnz = xtree.nnz();
		xtree.cut_smaller(action_extra2);
		assert(xtree.nnz() == nnz);
	    }
#endif
	    break;

	  case CUT_LARGER_AGG_ACT:
	    tree.cut_larger_aggregates(action_extra, action_extra2);
#ifdef SELFTEST
	    {
		AggregateTree xtree;
		tree.make_prefix(action_extra, xtree);
		uint32_t nnz = xtree.nnz();
		xtree.cut_larger(action_extra2);
		assert(xtree.nnz() == nnz);
	    }
#endif
	    break;

	  case CUT_SMALLER_ADDR_AGG_ACT:
	    tree.cut_smaller_host_aggregates(action_extra, action_extra2);
	    break;
	    
	  case CUT_LARGER_ADDR_AGG_ACT:
	    tree.cut_larger_host_aggregates(action_extra, action_extra2);
	    break;
	    
	  case CULL_ADDRS_ACT: {
	      AggregateWTree wtree(tree, AggregateWTree::COUNT_ADDRS);
	      wtree.cull_addresses(action_extra);
	      //wtree.ok();
	      tree = wtree;
	      break;
	  }
	  
	  case CULL_ADDRS_BY_PACKETS_ACT: {
	      AggregateWTree wtree(tree, AggregateWTree::COUNT_PACKETS);
	      wtree.cull_addresses_by_packets(action_extra);
	      //wtree.ok();
	      tree = wtree;
	      break;
	  }
	  
	  case CULL_PACKETS_ACT: {
	      AggregateWTree wtree(tree, AggregateWTree::COUNT_PACKETS);
	      wtree.cull_packets(action_extra);
	      //wtree.ok();
	      tree = wtree;
	      break;
	  }

	  case FAKE_BY_DISCRIM_ACT: {
	      uint32_t dp[33][33];
	      AggregateWTree wtree(tree, AggregateWTree::COUNT_ADDRS_LEAF);
	      for (int p = 32; p >= 0; p--) {
		  wtree.num_discriminated_by_prefix(dp[p]);
		  if (p > 0)
		      wtree.prefixize(p - 1);
	      }
	      
	      AggregateWTree new_tree(AggregateWTree::COUNT_ADDRS_LEAF);
	      double randomness = (double)action_extra / DOUBLE_FACTOR;
	      for (int i = 0; i <= 32; i++)
		  new_tree.fake_by_discriminating_prefix(i, dp, randomness);

	      tree = new_tree;
	      break;
	  }

	  case FAKE_BY_BRANCHING_ACT: {
	      AggregateWTree new_tree(AggregateWTree::COUNT_ADDRS_LEAF);
	      for (int p = 0; p < 32; p += action_extra) {
		  int delta = (p + action_extra <= 32 ? action_extra : 32 - p);
		  Vector<uint32_t> v;
		  tree.branching_counts(p, delta, v);
		  new_tree.fake_by_branching_counts(p, delta, v);
	      }
	      tree = new_tree;
	      break;
	  }

	  case FAKE_BY_DIRICHLET_ACT: {
	      AggregateWTree new_tree(AggregateWTree::COUNT_ADDRS_LEAF);
	      new_tree.fake_by_dirichlet(tree.nnz());
	      tree = new_tree;
	      break;
	  }

	}
    }
}

static void
process_actions(AggregateTree &tree, ErrorHandler *errh)
{
    process_tree_actions(tree, errh);
    
    // output result of final action
    int action = actions.back();
    uint32_t action_extra = extras.back();
    uint32_t action_extra2 = extras2.back();
    switch (action) {
	
      case NNZ_ACT:
	fprintf(out, "%u\n", tree.num_nonzero());
	break;

      case NNZ_PREFIX_ACT: {
	  Vector<uint32_t> nnzp;
	  tree.num_active_prefixes(nnzp);
	  write_vector(nnzp, out);
	  break;
      }

      case NNZ_LEFT_PREFIX_ACT: {
	  Vector<uint32_t> nnzp;
	  tree.num_active_left_prefixes(nnzp);
	  write_vector(nnzp, out);
	  break;
      }

      case NNZ_DISCRIM_ACT: {
	  Vector<uint32_t> nnzp;
	  AggregateWTree wtree(tree, AggregateWTree::COUNT_ADDRS_LEAF);
	  wtree.num_discriminated_by_prefix(nnzp);
	  write_vector(nnzp, out);
	  break;
      }

      case ALL_NNZ_DISCRIM_ACT: {
	  uint32_t dp[33][33];
	  AggregateWTree wtree(tree, AggregateWTree::COUNT_ADDRS_LEAF);
	  for (int i = 32; i > 0; i--) {
	      wtree.num_discriminated_by_prefix(dp[i]);
	      wtree.prefixize(i - 1);
	  }
	  wtree.num_discriminated_by_prefix(dp[0]);
	  for (int i = 0; i <= 32; i++)
	      write_vector(dp[i], i + 1, out);
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
	      tree.prefixize(i);
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
	  tree.active_counts(sizes);
	  if (action == SORTED_SIZES_ACT && sizes.size())
	      qsort(&sizes[0], sizes.size(), sizeof(uint32_t), uint32_rev_compar);
	  write_vector(sizes, out);
	  break;
      }

      case AGG_SIZES_ACT:
      case AGG_ADDRS_ACT: {
	  AggregateTree agg_tree(tree);
	  if (action == AGG_ADDRS_ACT)
	      agg_tree.posterize();
	  agg_tree.prefixize(action_extra);
	  tree.take_nonzero_sizes(agg_tree, prefix_to_mask(action_extra));
	  Vector<uint32_t> sizes;
	  tree.active_counts(sizes);
	  write_vector(sizes, out);
	  break;
      }

      case CORR_SIZE_AGG_ADDR_ACT: {
	  Vector<uint32_t> sizes;
	  tree.active_counts(sizes);
	  
	  AggregateTree agg_tree(tree);
	  agg_tree.posterize();
	  agg_tree.prefixize(action_extra);
	  tree.take_nonzero_sizes(agg_tree, prefix_to_mask(action_extra));
	  Vector<uint32_t> agg_addrs;
	  tree.active_counts(agg_addrs);

	  fprintf(out, "%.20g\n", correlation_coefficient(sizes, agg_addrs));
	  //fprintf(out, "# bar %.20g %.20g\n# var %.20g %.20g\n# covar %.20g\n", a_avg, b_avg, a_varx, b_varx, ab_covarx);
	  break;
      }

      case SIZE_COUNTS_ACT: {
	  Vector<uint32_t> sizes;
	  tree.active_counts(sizes);
	  if (sizes.size())
	      qsort(&sizes[0], sizes.size(), sizeof(uint32_t), uint32_compar);
	  uint32_t count = 0;
	  uint32_t size = 0;
	  for (int i = 0; i < sizes.size(); i++) {
	      if (sizes[i] != size && count) {
		  fprintf(out, "%u %u\n", size, count);
		  count = 0;
	      }
	      size = sizes[i];
	      count++;
	  }
	  if (count)
	      fprintf(out, "%u %u\n", size, count);
	  break;
      }

      case BALANCE_ACT:
	tree.balance(action_extra, out);
	break;

      case COND_SPLIT_ACT: {
	  Vector<uint32_t> cond_split;
	  tree.conditional_split_counts(action_extra, cond_split);
	  write_vector(cond_split, out);
	  break;
      }

      case BRANCHING_ACT: {
	  Vector<uint32_t> v;
	  tree.branching_counts(action_extra, action_extra2, v);
	  write_vector(v, out);
	  break;
      }
      
      case ALL_BRANCHING_ACT: {
	  Vector<uint32_t> v;
	  for (uint32_t i = 0; i <= 32 - action_extra; i++) {
	      tree.branching_counts(i, action_extra, v);
	      write_vector(v, out);
	  }
	  break;
      }
      
      case BALANCE_HISTOGRAM_ACT: {
	  Vector<uint32_t> sizes;
	  tree.balance_histogram(action_extra, action_extra2, sizes);
	  
	  // print number of aggregates to help users
	  uint32_t total = 0;
	  for (int i = 0; i < sizes.size(); i++)
	      total += sizes[i];
	  fprintf(out, "# nnz %u\n", total);
	  
	  fprintf(out, "0 0 %u\n", sizes[0]);
	  double step = 1. / (double)action_extra2;
	  for (int i = 1; i < sizes.size() - 1; i++)
	      fprintf(out, "%g %g %u\n", (i - 1) * step, i * step, sizes[i]);
	  fprintf(out, "1 1 %u\n", sizes.back());
	  break;
      }
      
      case PREFIX_ACT:
      case POSTERIZE_ACT:
      case SAMPLE_ACT:
      case CUT_SMALLER_ACT:
      case CUT_LARGER_ACT:
      case CULL_ADDRS_ACT:
      case CULL_ADDRS_BY_PACKETS_ACT:
      case CULL_PACKETS_ACT:
      case CUT_SMALLER_AGG_ACT:
      case CUT_LARGER_AGG_ACT:
      case CUT_SMALLER_ADDR_AGG_ACT:
      case CUT_LARGER_ADDR_AGG_ACT:
      case FAKE_BY_DISCRIM_ACT:
      case FAKE_BY_BRANCHING_ACT:
      case FAKE_BY_DIRICHLET_ACT:
      case NO_ACT:
	tree.write_file(out, output_binary, errh);
	break;
	
    }
}

int
main(int argc, char *argv[])
{
    Clp_Parser *clp = Clp_NewParser
	(argc, argv, sizeof(options) / sizeof(options[0]), options);
    program_name = Clp_ProgramName(clp);
    Clp_AddType(clp, CLP_TWO_UINTS_TYPE, 0, parse_two_uints, 0);
    
    String::static_initialize();
    cp_va_static_initialize();
    ErrorHandler *errh = new FileErrorHandler(stderr, "");
    ErrorHandler::static_initialize(errh);
    //ErrorHandler *p_errh = new PrefixErrorHandler(errh, program_name + String(": "));

    String output;
    int combiner = 0;
    
    while (1) {
	int opt = Clp_Next(clp);
	switch (opt) {

	  case OUTPUT_OPT:
	    if (output)
		die_usage("`--output' already specified");
	    output = clp->arg;
	    break;

	  case BINARY_OPT:
	    output_binary = !clp->negated;
	    break;
	    
	  case ASCII_OPT:
	    output_binary = clp->negated;
	    break;
	    
	  case AND_OPT:
	  case OR_OPT:
	  case EACH_OPT:
	  case AND_LIST_OPT:
	  case MINUS_OPT:
	  case XOR_OPT:
	  case ASSIGN_COUNTS_OPT:
	    if (combiner)
		die_usage("combiner option already specified");
	    combiner = opt;
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
	  case SIZE_COUNTS_ACT:
	  case ALL_NNZ_DISCRIM_ACT:
	  case FAKE_BY_DIRICHLET_ACT:
	    add_action(opt);
	    break;

	  case PREFIX_ACT:
	  case AGG_SIZES_ACT:
	  case AGG_ADDRS_ACT:
	  case CORR_SIZE_AGG_ADDR_ACT:
	    if (clp->val.u > 32)
		die_usage("`" + String(Clp_CurOptionName(clp)) + "' must be between 0 and 32");
	    add_action(opt, clp->val.u);
	    break;

	  case BALANCE_ACT:
	  case ALL_BRANCHING_ACT:
	    if (clp->val.u > 31)
		die_usage("`" + String(Clp_CurOptionName(clp)) + "' must be between 0 and 31");
	    add_action(opt, clp->val.u);
	    break;

	  case FAKE_BY_BRANCHING_ACT:
	    if (clp->val.u == 0 || clp->val.u > 4)
		die_usage("`" + String(Clp_CurOptionName(clp)) + "' must be between 1 and 4");
	    add_action(opt, clp->val.u);
	    break;

	  case COND_SPLIT_ACT:
	    if (clp->val.u < 1 || clp->val.u > 31)
		die_usage("`--conditional-split-counts' arg must be between 1 and 31");
	    add_action(opt, clp->val.u);
	    break;

	  case CUT_SMALLER_AGG_ACT:
	  case CUT_LARGER_AGG_ACT:
	  case CUT_SMALLER_ADDR_AGG_ACT:
	  case CUT_LARGER_ADDR_AGG_ACT:
	  case BALANCE_HISTOGRAM_ACT:
	    if (clp->val.us[0] > 31)
		die_usage("`" + String(Clp_CurOptionName(clp)) + "' prefix must be between 0 and 31");
	    add_action(opt, clp->val.us[0], clp->val.us[1]);
	    break;

	  case BRANCHING_ACT:
	    if (clp->val.us[1] < 1 || clp->val.us[0] + clp->val.us[1] > 32)
		die_usage("bad `" + String(Clp_CurOptionName(clp)) + "' args");
	    add_action(opt, clp->val.us[0], clp->val.us[1]);
	    break;

	  case SAMPLE_ACT:
	  case CUT_SMALLER_ACT:
	  case CUT_LARGER_ACT:
	  case CULL_ADDRS_ACT:
	  case CULL_ADDRS_BY_PACKETS_ACT:
	  case CULL_PACKETS_ACT:
	    add_action(opt, clp->val.u);
	    break;

	  case FAKE_BY_DISCRIM_ACT:
	    if (!clp->have_arg)
		clp->val.d = 1;	// random
	    else if (clp->val.d < 0 || clp->val.d > 1)
		die_usage("`" + String(Clp_CurOptionName(clp)) + "' arg should be between 0 and 1");
	    add_action(opt, (uint32_t) (clp->val.d * DOUBLE_FACTOR));
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
    if (files.size() == 0)
	files.push_back("-");
    if (actions.size() == 0)
	add_action(NO_ACT);
    if (!output)
	output = "-";

    if (output == "-")
	out = stdout;
    else
	out = fopen(output, "w");
    if (!out)
	errh->fatal("%s: %s", output.cc(), strerror(errno));

    // read files
    switch (combiner) {

      case AND_OPT: {
	  AggregateTree tree;
	  read_next_file(tree, errh);
	  while (more_files()) {
	      AggregateTree tree2;
	      read_next_file(tree2, errh);
	      tree.keep_common_hosts(tree2, true);
	  }
	  process_actions(tree, errh);
	  break;
      }

      case AND_LIST_OPT: {
	  if (actions.back() < FIRST_END_ACT)
	      errh->fatal("last action must not produce a tree with `--and-list'");
	  AggregateTree tree;
	  read_next_file(tree, errh);
	  process_actions(tree, errh);
	  while (more_files()) {
	      AggregateTree tree2;
	      read_next_file(tree2, errh);
	      tree.keep_common_hosts(tree2, true);
	      process_actions(tree, errh);
	  }
	  break;
      }

      case OR_OPT: {
	  AggregateTree tree;
	  while (more_files())
	      read_next_file(tree, errh);
	  process_actions(tree, errh);
	  break;
      }

      case XOR_OPT: {
	  AggregateTree tree_or, tree_or1;
	  read_next_file(tree_or, errh);
	  tree_or1 = tree_or;
	  while (more_files()) {
	      AggregateTree t;
	      read_next_file(t, errh);
	      tree_or1.add_new_hosts(t);
	      tree_or += t;
	  }
	  tree_or.drop_common_unequal_hosts(tree_or1);
	  process_actions(tree_or, errh);
	  break;
      }

      case MINUS_OPT: {
	  AggregateTree tree;
	  read_next_file(tree, errh);
	  while (more_files()) {
	      AggregateTree tree2;
	      read_next_file(tree2, errh);
	      tree.drop_common_hosts(tree2);
	  }
	  process_actions(tree, errh);
	  break;
      }

      case EACH_OPT: {
	  if (actions.back() < FIRST_END_ACT)
	      errh->fatal("last action must not produce a tree with `--each'");
	  int ndone = 0;
	  while (more_files()) {
	      AggregateTree tree;
	      read_next_file(tree, errh);
	      if (ndone > 0 || more_files())
		  fprintf(out, "# %s\n", last_filename.cc());
	      process_actions(tree, errh);
	      ndone++;
	  }
	  break;
      }

      case ASSIGN_COUNTS_OPT: {
	  if (actions.back() >= FIRST_END_ACT)
	      errh->fatal("last action must produce a tree with `--assign-counts'");
	  AggregateTree tree1, tree2;
	  read_next_file(tree1, errh);
	  process_tree_actions(tree1, errh);
	  if (!more_files())
	      tree2 = tree1;
	  else {
	      read_next_file(tree2, errh);
	      process_tree_actions(tree2, errh);
	  }
	  if (more_files())
	      errh->fatal("`--assign-counts' takes exactly two trees");
	  if (tree1.nnz() != tree2.nnz())
	      errh->fatal("`--assign-counts' trees have different -N (%u vs. %u)", tree1.nnz(), tree2.nnz());

	  Vector<uint32_t> sizes;
	  tree1.active_counts(sizes);
	  tree2.randomly_assign_counts(sizes);
	  tree2.write_file(out, output_binary, errh);
	  break;
      }

      default: {
	  AggregateTree tree;
	  read_next_file(tree, errh);
	  if (more_files())
	      errh->fatal("supply `--and', `--or', or `--each' with multiple files");
	  process_actions(tree, errh);
	  break;
      }

    }
    
    
    exit(0);
}

