/*
 * ipaggmanip.cc -- driver for the ipaggmanip program
 * Eddie Kohler
 *
 * Copyright (c) 2001-2004 International Computer Science Institute
 * Copyright (c) 2004-2008 Regents of the University of California
 * Copyright (c) 2001-2014 Eddie Kohler
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
#include <click/ipaddress.hh>

#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <cerrno>
#include <cmath>

#include "aggtree.hh"
#include "aggwtree.hh"

#define DOUBLE_FACTOR		1000000000

#define HELP_OPT		300
#define VERSION_OPT		301
#define READ_FILE_OPT		302
#define OUTPUT_OPT		303
#define BINARY_OPT		304
#define ASCII_OPT		305
#define ASCII_IP_OPT		306
#define AND_OPT			307
#define OR_OPT			308
#define EACH_OPT		309
#define AND_LIST_OPT		310
#define MINUS_OPT		311
#define XOR_OPT			312
#define ASSIGN_COUNTS_OPT	313

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
#define REMAP_PREFIXES_ACT	416

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

#define CLP_TWO_UINTS_TYPE	(Clp_ValFirstUser)

static const Clp_Option options[] = {

  { "help", 'h', HELP_OPT, 0, 0 },
  { "version", 'v', VERSION_OPT, 0, 0 },

  { "read-file", 'r', READ_FILE_OPT, Clp_ValString, 0 },
  { "output", 'o', OUTPUT_OPT, Clp_ValString, 0 },
  { "binary", 'b', BINARY_OPT, 0, 0 },
  { "text", 'A', ASCII_OPT, 0, 0 },
  { "ip", 0, ASCII_IP_OPT, 0, 0 },
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
  { "num-labels", 'n', NNZ_ACT, 0, 0 },
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
  { "conditional-split-counts", 0, COND_SPLIT_ACT, Clp_ValUnsigned, 0 },
  { "prefix", 'p', PREFIX_ACT, Clp_ValUnsigned, 0 },
  { "posterize", 'P', POSTERIZE_ACT, 0, 0 },
  { "remap-prefixes", 0, REMAP_PREFIXES_ACT, Clp_ValString, 0 },
  { "average-and-variance", 0, AVG_VAR_ACT, 0, 0 },
  { "avg-var", 0, AVG_VAR_ACT, 0, 0 },
  { "average-and-variance-by-prefix", 0, AVG_VAR_PREFIX_ACT, 0, 0 },
  { "avg-var-by-prefix", 0, AVG_VAR_PREFIX_ACT, 0, 0 },
  { "sample", 0, SAMPLE_ACT, Clp_ValDouble, 0 },

  { "cut-smaller", 0, CUT_SMALLER_ACT, Clp_ValUnsigned, 0 },
  { "cut-smaller-aggregates", 0, CUT_SMALLER_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-smaller-host-aggregates", 0, CUT_SMALLER_ADDR_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-smaller-label-aggregates", 0, CUT_SMALLER_ADDR_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-smaller-address-aggregates", 0, CUT_SMALLER_ADDR_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-larger", 0, CUT_LARGER_ACT, Clp_ValUnsigned, 0 },
  { "cut-larger-aggregates", 0, CUT_LARGER_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-larger-host-aggregates", 0, CUT_LARGER_ADDR_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-larger-label-aggregates", 0, CUT_LARGER_ADDR_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "cut-larger-address-aggregates", 0, CUT_LARGER_ADDR_AGG_ACT, CLP_TWO_UINTS_TYPE, 0 },

  { "cull", 0, CULL_PACKETS_ACT, Clp_ValUnsigned, 0 },
  { "cull-labels", 0, CULL_ADDRS_ACT, Clp_ValUnsigned, 0 },
  { "cull-labels-by-packets", 0, CULL_ADDRS_BY_PACKETS_ACT, Clp_ValUnsigned, 0 },
  { "cull-addresses", 0, CULL_ADDRS_ACT, Clp_ValUnsigned, 0 },
  { "cull-addresses-by-packets", 0, CULL_ADDRS_BY_PACKETS_ACT, Clp_ValUnsigned, 0 },
  { "cull-addrs", 0, CULL_ADDRS_ACT, Clp_ValUnsigned, 0 },
  { "cull-addrs-by-packets", 0, CULL_ADDRS_BY_PACKETS_ACT, Clp_ValUnsigned, 0 },
  { "cull-packets", 0, CULL_PACKETS_ACT, Clp_ValUnsigned, 0 },

  { "haar-wavelet-energy", 0, HAAR_WAVELET_ENERGY_ACT, 0, 0 },

  { "sizes", 0, SIZES_ACT, 0, 0 },
  { "sorted-sizes", 0, SORTED_SIZES_ACT, 0, 0 },
  { "size-counts", 0, SIZE_COUNTS_ACT, 0, 0 },
  { "container-sizes", 0, AGG_SIZES_ACT, Clp_ValUnsigned, 0 },
  { "container-addresses", 0, AGG_ADDRS_ACT, Clp_ValUnsigned, 0 },
  { "container-addrs", 0, AGG_ADDRS_ACT, Clp_ValUnsigned, 0 },

  { "counts", 0, SIZES_ACT, 0, 0 },
  { "sorted-counts", 0, SORTED_SIZES_ACT, 0, 0 },
  { "count-counts", 0, SIZE_COUNTS_ACT, 0, 0 },
  { "container-counts", 0, AGG_SIZES_ACT, Clp_ValUnsigned, 0 },
  { "container-labels", 0, AGG_ADDRS_ACT, Clp_ValUnsigned, 0 },

  { "balance", 0, BALANCE_ACT, Clp_ValUnsigned, 0 },
  { "balance-histogram", 0, BALANCE_HISTOGRAM_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "branching-counts", 0, BRANCHING_ACT, CLP_TWO_UINTS_TYPE, 0 },
  { "all-branching-counts", 0, ALL_BRANCHING_ACT, Clp_ValUnsigned, 0 },
  { "fake-by-discriminating-prefixes", 0, FAKE_BY_DISCRIM_ACT, Clp_ValDouble, Clp_Optional },
  { "fake-by-branching-counts", 0, FAKE_BY_BRANCHING_ACT, Clp_ValUnsigned, 0 },
  { "fake-by-dirichlet", 0, FAKE_BY_DIRICHLET_ACT, 0, 0 },
  { "correlation-size-container-addresses", 0, CORR_SIZE_AGG_ADDR_ACT, Clp_ValUnsigned, 0 },

};

static const char *program_name;

static void
die_usage(String specific = String())
{
    ErrorHandler *errh = ErrorHandler::default_handler();
    if (specific)
	errh->error("%s: %s", program_name, specific.c_str());
    errh->fatal("Usage: %s ACTION [FILE]\n\
Try '%s --help' for more information.",
		program_name, program_name);
    // should not get here, but just in case...
    exit(1);
}

static void
usage()
{
  printf("\
'Ipaggmanip' reads an aggregate file summarizing IP trace data, transforms that\n\
file or calculates one of its statistics, and writes the result to standard\n\
output.  Aggregate files use ipaggcreate(1) format, and consist of pairs of\n\
\"labels\" and \"packet counts\".\n\
\n\
Usage: %s [TRANSFORMATION...] [ACTION] [FILES] > OUTPUT\n\
\n\
Transformations: (Input aggregate file, output aggregate file.)\n\
  -p, --prefix P             Aggregate to prefix level P.\n\
  -P, --posterize            Replace all nonzero counts with 1.\n\
      --sample N             Randomly sample packets with probability 1/N.\n\
      --cull N               Reduce to at most N packets by sampling packets.\n\
      --cull-labels N        Reduce to at most N labels by sampling labels.\n\
      --cull-labels-by-packets N\n\
                             Reduce to at most N labels by sampling packets.\n\
      --cut-{smaller,larger} N\n\
                             Drop labels with {<N,>=N} packets.\n\
      --cut-{smaller,larger}-aggregates P,N\n\
                             Drop P-aggregates that contain {<N,>=N} packets.\n\
      --cut-{smaller,larger}-label-aggregates P,N\n\
                             Drop P-aggregates that contain {<N,>=N} labels.\n\
      --fake-by-discriminating-prefixes[=TYP]\n\
                             Create fake posterized data sharing this data's\n\
                             --all-discriminating-prefix. TYP is a randomness\n\
                             factor between 0 and 1.\n\
      --fake-by-branching-counts\n\
      --fake-by-dirichlet\n\
      --remap-prefixes FOO\n\
\n", program_name);
  printf("Actions: (Input aggregate file, output other information.)\n\
  -n, --num-labels           Number of active labels (labels with >0 count).\n\
      --num-in-prefixes      Number of active p-aggregates for all p.\n\
      --num-in-left-prefixes Number of active left-hand p-aggregates for all p.\n\
      --discriminating-prefix-counts\n\
                             Number of active aggregates with discriminating\n\
                             prefix p for all p.\n\
      --all-discriminating-prefix-counts\n\
                             Number of active p-aggregates with\n\
                             p-discriminating prefix q for all p, q.\n\
      --counts               Counts in label order.\n\
      --sorted-counts        Counts in reverse count order.\n\
      --count-counts         For each unique count, print count and the number\n\
                             of labels that had that count.\n\
      --container-counts P   Count of each label's containing P-aggregate.\n\
      --balance P            Left-right balance at prefix level P.\n\
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
\n");
  printf("Multiple files:\n\
  Ipaggcreate normally performs an action on a single aggregate file.\n\
  -e, --each             Perform action on each FILE; output multiple results.\n\
  -|, --or               Combine by adding aggregates together.\n\
  -&, --and              Combine, but drop labels not present in every file.\n\
      --minus            Use FILE1, but drop labels present in any other FILE.\n\
  -^, --xor              Combine, but drop labels present in >1 FILE.\n\
      --and-list         Output results for FILE1, then FILE1 & FILE2,\n\
                         then FILE1 & FILE2 & FILE3, and so on.\n\
      --assign-counts    Input is two FILEs with same --num-labels; randomly\n\
                         assign counts from FILE1 to labels from FILE2.\n\
  Or say  '(+' FILE FILE ... ')'  to --or particular files,\n\
  '(&' FILE ... ')'  to --and,  '(-' FILE ... ')'  to --minus,\n\
  '(^' FILE ... ')'  to --xor.\n\
\n");
  printf("\
Other options:\n\
  -r, --read FILE        Read summary from FILE (default stdin).\n\
  -o, --output FILE      Write output to FILE (default stdout).\n\
  -b, --binary           Output aggregate files in binary.\n\
      --text             Output aggregate files in ASCII.\n\
      --ip               Output aggregate files in ASCII with IP addresses.\n\
  -h, --help             Print this message and exit.\n\
  -v, --version          Print version number and exit.\n\
\n\
Report bugs to <kohler@cs.ucla.edu>.\n");
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
static Vector<String> str_extras;
static FILE *out;
static AggregateTree::WriteFormat output_format = AggregateTree::WR_UNKNOWN;
static Vector<String> files;
static int files_pos = 0;

static void
add_action(int action, uint32_t extra = 0, uint32_t extra2 = 0, const String &extra_s = String())
{
    if (actions.size() && actions.back() >= FIRST_END_ACT)
	die_usage("can't add another action after that");
    actions.push_back(action);
    extras.push_back(extra);
    extras2.push_back(extra2);
    str_extras.push_back(extra_s);
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
	&& cp_va_kparse(conf, 0, ErrorHandler::silent_handler(),
			"ARG1", cpkP+cpkM, cpUnsigned, &clp->val.us[0],
			"ARG2", cpkP+cpkM, cpUnsigned, &clp->val.us[1],
			cpEnd) >= 0)
	return 1;
    else if (complain)
	return Clp_OptionError(clp, "'%O' expects two unsigned integers separated by a comma, not '%s'", arg);
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
	f = fopen(name.c_str(), "rb");
    if (!f)
	errh->fatal("%s: %s", name.c_str(), strerror(errno));
    tree.read_file(f, errh);
    if (output_format == AggregateTree::WR_UNKNOWN)
	output_format = tree.read_format();
    if (f != stdin)
	fclose(f);
}

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
    assert(&tree);

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
	    tree.sample(action_extra / (double)DOUBLE_FACTOR);
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

	  case REMAP_PREFIXES_ACT: {
	      // parse the string
	      const char *s = str_extras[j].data();
	      const char *ends = s + str_extras[j].length();
	      Vector<int> x1, x2, xp;
	      int max_p = 0;
	      while (s < ends) {
		  int v1 = 0, p1 = 0;
		  while (s < ends && (*s == '0' || *s == '1'))
		      v1 = (v1 << 1) + (*s - '0'), p1++, s++;
		  if (s >= ends || (*s != '=' && *s != '>' && *s != ':') || p1 == 0 || p1 > 31)
		      errh->fatal("syntax error 1 in --remap-prefixes argument (%c)", *s);
		  s++;

		  int v2 = 0, p2 = 0;
		  while (s < ends && (*s == '0' || *s == '1'))
		      v2 = (v2 << 1) + (*s - '0'), p2++, s++;
		  if ((s < ends && *s != ',') || p2 != p1)
		      errh->fatal("syntax error 2 in --remap-prefixes argument (%c)", *s);
		  s++;

		  x1.push_back(v1);
		  x2.push_back(v2);
		  xp.push_back(p1);
		  if (p1 > max_p)
		      max_p = p1;
	      }

	      // change into a map with a single prefix
	      Vector<uint32_t> map(1 << max_p, 0);
	      for (uint32_t i = 0; i < (1U << max_p); i++)
		  map[i] = i;
	      Vector<uint32_t> map_used(1 << max_p, 0);
	      for (int i = 0; i < x1.size(); i++) {
		  int pdiff = max_p - xp[i];
		  for (uint32_t k = 0; k < (1U << pdiff); k++) {
		      uint32_t v1 = (x1[i] << pdiff) | k;
		      uint32_t v2 = (x2[i] << pdiff) | k;
		      if (map_used[v1])
			  errh->error("prefix '%s/%d' mapped twice in --remap-prefixes", IPAddress(htonl(v1 << (32 - max_p))).s().c_str(), max_p);
		      map_used[v1]++;
		      map[v1] = v2;
		  }
	      }

	      // check double-mapping
	      map_used.assign(1 << max_p, 0);
	      for (uint32_t i = 0; i < (1U << max_p); i++) {
		  if (map_used[i] == 1)
		      errh->warning("prefix '%s/%d' repeatedly mapped to in --remap-prefixes", IPAddress(htonl(i << (32 - max_p))).s().c_str(), max_p);
		  map_used[i]++;
	      }

	      // actually map
	      AggregateTree new_tree;
	      tree.make_mapped(max_p, map, new_tree);
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
	  assert(&tree);
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
      case REMAP_PREFIXES_ACT:
      case NO_ACT:
	tree.write_file(out, output_format, errh);
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

    cp_va_static_initialize();
    ErrorHandler *errh = new FileErrorHandler(stderr, "");
    ErrorHandler::static_initialize(errh);
    //ErrorHandler *p_errh = new PrefixErrorHandler(errh, program_name + String(": "));

    String output;
    int combiner = 0;

    while (1) {
	int opt = Clp_Next(clp);
	String optname = String(Clp_CurOptionName(clp));
	switch (opt) {

	  case OUTPUT_OPT:
	    if (output)
		die_usage("'--output' already specified");
	    output = clp->vstr;
	    break;

	  case BINARY_OPT:
	    output_format = AggregateTree::WR_BINARY;
	    break;

	  case ASCII_OPT:
	    output_format = AggregateTree::WR_ASCII;
	    break;

	  case ASCII_IP_OPT:
	    output_format = AggregateTree::WR_ASCII_IP;
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
	    files.push_back(clp->vstr);
	    break;

	  case HELP_OPT:
	    usage();
	    exit(0);
	    break;

	  case VERSION_OPT:
	    printf("ipaggmanip %s (libclick-%s)\n", IPSUMDUMP_VERSION, CLICK_VERSION);
	    printf("Copyright (c) 2001-2014 Eddie Kohler and others\n\
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
		die_usage("'" + optname + "' must be between 0 and 32");
	    add_action(opt, clp->val.u);
	    break;

	  case BALANCE_ACT:
	  case ALL_BRANCHING_ACT:
	    if (clp->val.u > 31)
		die_usage("'" + optname + "' must be between 0 and 31");
	    add_action(opt, clp->val.u);
	    break;

	  case FAKE_BY_BRANCHING_ACT:
	    if (clp->val.u == 0 || clp->val.u > 4)
		die_usage("'" + optname + "' must be between 1 and 4");
	    add_action(opt, clp->val.u);
	    break;

	  case COND_SPLIT_ACT:
	    if (clp->val.u < 1 || clp->val.u > 31)
		die_usage("'--conditional-split-counts' arg must be between 1 and 31");
	    add_action(opt, clp->val.u);
	    break;

	  case CUT_SMALLER_AGG_ACT:
	  case CUT_LARGER_AGG_ACT:
	  case CUT_SMALLER_ADDR_AGG_ACT:
	  case CUT_LARGER_ADDR_AGG_ACT:
	  case BALANCE_HISTOGRAM_ACT:
	    if (clp->val.us[0] > 31)
		die_usage("'" + optname + "' prefix must be between 0 and 31");
	    add_action(opt, clp->val.us[0], clp->val.us[1]);
	    break;

	  case BRANCHING_ACT:
	    if (clp->val.us[1] < 1 || clp->val.us[0] + clp->val.us[1] > 32)
		die_usage("bad '" + optname + "' args");
	    add_action(opt, clp->val.us[0], clp->val.us[1]);
	    break;

	  case SAMPLE_ACT:
	    if (clp->val.d < 0 || clp->val.d > 1)
		die_usage("'" + optname + "' prob should be between 0 and 1");
	    add_action(opt, (uint32_t) (clp->val.d * DOUBLE_FACTOR));
	    break;

	  case CUT_SMALLER_ACT:
	  case CUT_LARGER_ACT:
	  case CULL_ADDRS_ACT:
	  case CULL_ADDRS_BY_PACKETS_ACT:
	  case CULL_PACKETS_ACT:
	    add_action(opt, clp->val.u);
	    break;

	  case FAKE_BY_DISCRIM_ACT:
	    if (!clp->have_val)
		clp->val.d = 1;	// random
	    else if (clp->val.d < 0 || clp->val.d > 1)
		die_usage("'" + optname + "' arg should be between 0 and 1");
	    add_action(opt, (uint32_t) (clp->val.d * DOUBLE_FACTOR));
	    break;

	  case REMAP_PREFIXES_ACT:
	    add_action(opt, 0, 0, clp->vstr);
	    break;

	  case Clp_NotOption:
	    files.push_back(clp->vstr);
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
	out = fopen(output.c_str(), "w");
    if (!out)
	errh->fatal("%s: %s", output.c_str(), strerror(errno));

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
	      errh->fatal("last action must not produce a tree with '--and-list'");
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
	      errh->fatal("last action must not produce a tree with '--each'");
	  int ndone = 0;
	  while (more_files()) {
	      AggregateTree tree;
	      read_next_file(tree, errh);
	      if (ndone > 0 || more_files())
		  fprintf(out, "# %s\n", last_filename.c_str());
	      process_actions(tree, errh);
	      ndone++;
	  }
	  break;
      }

      case ASSIGN_COUNTS_OPT: {
	  if (actions.back() >= FIRST_END_ACT)
	      errh->fatal("last action must produce a tree with '--assign-counts'");
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
	      errh->fatal("'--assign-counts' takes exactly two trees");
	  if (tree1.nnz() != tree2.nnz())
	      errh->fatal("'--assign-counts' trees have different -N (%u vs. %u)", tree1.nnz(), tree2.nnz());

	  Vector<uint32_t> sizes;
	  tree1.active_counts(sizes);
	  tree2.randomly_assign_counts(sizes);
	  tree2.write_file(out, output_format, errh);
	  break;
      }

      default: {
	  AggregateTree tree;
	  read_next_file(tree, errh);
	  if (more_files())
	      errh->fatal("supply %<--and%>, %<--or%>, or %<--each%> with multiple files");
	  process_actions(tree, errh);
	  break;
      }

    }


    exit(0);
}
