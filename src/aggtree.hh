#ifndef AGGTREE_HH
#define AGGTREE_HH
#include <click/vector.hh>
#include <click/error.hh>
#include <cstdio>
class AggregateWTree;
struct AggregateWTree_WNode;

class AggregateTree { public:

    enum WriteFormat { WR_UNKNOWN = -1, WR_ASCII = 0, WR_BINARY = 1, WR_ASCII_IP = 2 };

    AggregateTree();
    AggregateTree(const AggregateTree &);
    AggregateTree(const AggregateWTree &);
    ~AggregateTree();

    bool ok(ErrorHandler * = 0) const;

    uint32_t num_nonzero() const		{ return _num_nonzero; }
    uint32_t nnz() const			{ return _num_nonzero; }
    uint32_t nnz_match(uint32_t mask, uint32_t value) const;

    inline void add(uint32_t aggregate, int32_t count = 1);
    void zero_aggregate(int, uint32_t);
    void zero_masked_aggregate(uint32_t, uint32_t);

    void posterize();

    void prefixize(int prefix_len);
    void make_prefix(int prefix_len, AggregateTree &) const;

    void sample(double);
    void cut_smaller(uint32_t);
    void cut_larger(uint32_t);
    void cut_smaller_aggregates(int, uint32_t);
    void cut_larger_aggregates(int, uint32_t);
    void cut_smaller_host_aggregates(int, uint32_t);
    void cut_larger_host_aggregates(int, uint32_t);

    void make_mapped(int prefix_len, const Vector<uint32_t> &map, AggregateTree &) const;

    void num_active_prefixes(Vector<uint32_t> &) const;
    void num_active_left_prefixes(Vector<uint32_t> &) const;

    void haar_wavelet_energy_coeff(Vector<double> &) const;

    void active_counts(Vector<uint32_t> &) const;
    void randomly_assign_counts(const Vector<uint32_t> &);

    void sum_and_sum_sq(double *, double *) const;

    void balance(int prefix_len, FILE *) const;
    void balance_histogram(int prefix_len, uint32_t nbuckets, Vector<uint32_t> &) const;

    void branching_counts(int p, int layers_down, Vector<uint32_t> &) const;
    void subtree_counts(int p, int layers_down, Vector<uint32_t> &) const;
    void conditional_split_counts(int p, Vector<uint32_t> &) const;

    void keep_common_hosts(const AggregateTree &, bool add = false);
    void drop_common_hosts(const AggregateTree &);
    void drop_common_unequal_hosts(const AggregateTree &);
    void add_new_hosts(const AggregateTree &);
    void take_nonzero_sizes(const AggregateTree &, uint32_t mask =0xFFFFFFFFU);

    int read_file(FILE *, ErrorHandler *);
    WriteFormat read_format() const		{ return _read_format; }
    int write_file(FILE *, WriteFormat, ErrorHandler *) const;

    AggregateTree &operator=(const AggregateTree &);
    AggregateTree &operator+=(const AggregateTree &);
    AggregateTree &operator=(const AggregateWTree &);

    struct Node {
	uint32_t aggregate;
	uint32_t count;
	union {
	    Node *child[2];
	    AggregateWTree_WNode *wchild[2];
	};
    };

  private:

    Node *_root;
    Node *_free;
    enum { BLOCK_SIZE = 1024 };
    Vector<Node *> _blocks;

    uint32_t _num_nonzero;
    WriteFormat _read_format;

    inline Node *new_node();
    Node *new_node_block();
    inline void free_node(Node *);
    void initialize_root();
    void copy_nodes(const Node *, uint32_t = 0xFFFFFFFFU);
    void kill_all_nodes();

    Node *make_peer(uint32_t, Node *);
    Node *find_node(uint32_t);
    Node *find_existing_node(uint32_t) const;

    uint32_t node_ok(Node *, int, ErrorHandler *) const;
    void collapse_subtree(Node *);
    void node_zero_aggregate(Node *, uint32_t, uint32_t);
    void node_prefixize(Node *, int);
    uint32_t node_to_discriminated_by(Node *, const AggregateTree &, uint32_t, bool);
    void node_sample(Node *, uint32_t);
    void node_cut_smaller(Node *, uint32_t);
    void node_cut_larger(Node *, uint32_t);
    void node_cut_aggregates(Node *, uint32_t, uint32_t &, uint32_t &, uint32_t, bool smaller, bool hosts);
    void node_keep_common_hosts(Node *, const Node *[], int &, bool);
    void node_drop_common_hosts(Node *, const Node *[], int &);
    void node_drop_common_unequal_hosts(Node *, const Node *[], int &);
    void node_take_nonzero_sizes(Node *, const Node *[], int &, uint32_t);
    void node_randomly_assign_counts(Node *, Vector<uint32_t> &);

    void read_packed_file(FILE *, int file_byte_order);
    static void write_batch(FILE *, WriteFormat, uint32_t *, int, ErrorHandler *);
    static void write_nodes(Node *, FILE *, WriteFormat, uint32_t *, int &, int, ErrorHandler *);
    static void write_hex_nodes(Node *, FILE *, ErrorHandler *);

    friend class AggregateWTree;

};

inline AggregateTree::Node *
AggregateTree::new_node()
{
    if (_free) {
	Node *n = _free;
	_free = n->child[0];
	return n;
    } else
	return new_node_block();
}

inline void
AggregateTree::free_node(Node *n)
{
    n->child[0] = _free;
    _free = n;
}

inline void
AggregateTree::add(uint32_t aggregate, int32_t count)
{
    if (count == 0)
	/* nada */;
    else if (Node *n = find_node(aggregate)) {
	n->count += count;
	if (n->count == (uint32_t)count)
	    _num_nonzero++;
	else if (n->count == 0)
	    _num_nonzero--;
    }
}

static inline uint32_t
prefix_to_mask(int p)
{
    assert(p >= 0 && p <= 32);
    return (p == 0 ? 0 : (0xFFFFFFFFU << (32 - p)));
}

extern int mask_to_prefix(uint32_t);

#endif
