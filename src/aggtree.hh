#ifndef AGGTREE_HH
#define AGGTREE_HH
#include <click/vector.hh>
#include <click/error.hh>
#include <stdio.h>
class AggregateWTree;

class AggregateTree { public:

    AggregateTree();
    AggregateTree(const AggregateTree &);
    AggregateTree(const AggregateWTree &);
    ~AggregateTree();

    bool ok(ErrorHandler * = 0) const;

    uint32_t num_nonzero() const		{ return _num_nonzero; }
    uint32_t nnz() const			{ return _num_nonzero; }
    uint32_t nnz_match(uint32_t mask, uint32_t value) const;
    
    void add(uint32_t aggregate, int32_t count = 1);
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
    
    void nnz_in_prefixes(Vector<uint32_t> &) const;
    void nnz_in_left_prefixes(Vector<uint32_t> &) const;
    void nnz_discriminated_by_prefix(Vector<uint32_t> &) const;

    void haar_wavelet_energy_coeff(Vector<double> &) const;

    void nonzero_sizes(Vector<uint32_t> &) const;
    
    void sum_and_sum_sq(double *, double *) const;

    void balance(int prefix_len, FILE *) const;
    void balance_histogram(int prefix_len, uint32_t nbuckets, Vector<uint32_t> &) const;

    void keep_common_hosts(const AggregateTree &, bool add = false);
    void drop_common_hosts(const AggregateTree &);
    void drop_common_unequal_hosts(const AggregateTree &);
    void add_new_hosts(const AggregateTree &);
    
    int read_file(FILE *, ErrorHandler *);
    int write_file(FILE *, bool binary, ErrorHandler *) const;

    AggregateTree &operator=(const AggregateTree &);
    AggregateTree &operator+=(const AggregateTree &);
    AggregateTree &operator=(const AggregateWTree &);

    struct Node {
	uint32_t aggregate;
	uint32_t count;
	Node *child[2];
    };

  protected:
    
    Node *new_node();
    void free_node(Node *);
    void initialize_root();
    
  private:
    
    Node *_root;
    Node *_free;
    Vector<Node *> _blocks;

    uint32_t _num_nonzero;

    Node *new_node_block();
    void copy_nodes(const Node *, uint32_t = 0xFFFFFFFFU);
    void kill_all_nodes();

    Node *make_peer(uint32_t, Node *);
    Node *find_node(uint32_t);
    Node *find_existing_node(uint32_t) const;

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

    static void write_batch(FILE *f, bool, uint32_t *, int, ErrorHandler *);
    static void write_nodes(Node *, FILE *, bool, uint32_t *, int &, int, ErrorHandler *);

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

extern int bi_ffs(uint32_t);

#endif
