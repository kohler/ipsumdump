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

    static inline uint32_t prefix_to_mask(int);
    
    uint32_t num_nonzero() const		{ return _num_nonzero; }
    uint32_t nnz() const			{ return _num_nonzero; }
    uint32_t nnz_match(uint32_t mask, uint32_t value) const;
    
    void add(uint32_t aggregate, uint32_t count = 1);

    void posterize();
    
    void mask_data_to_prefix(int prefix_len);
    void make_prefix(int prefix_len, AggregateTree &);

    void sample(double);
    void cut_smaller(uint32_t);
    
    void nnz_in_prefixes(Vector<uint32_t> &) const;
    void nnz_in_left_prefixes(Vector<uint32_t> &) const;
    void nnz_discriminated_by_prefix(Vector<uint32_t> &) const;

    void haar_wavelet_energy_coeff(Vector<double> &) const;

    void sum_and_sum_sq(double *, double *) const;

    int read_file(FILE *, ErrorHandler *);
    int write_file(FILE *, bool binary, ErrorHandler *) const;

    AggregateTree &operator=(const AggregateTree &);
    AggregateTree &operator=(const AggregateWTree &);

    struct Node {
	uint32_t aggregate;
	uint32_t count;
	Node *child[2];
    };

  private:
    
    Node *_root;
    Node *_free;
    Vector<Node *> _blocks;

    uint32_t _num_nonzero;

    Node *new_node();
    Node *new_node_block();
    void free_node(Node *);
    void initialize_root();
    void copy_nodes(Node *, uint32_t = 0xFFFFFFFFU);
    void kill_all_nodes();

    Node *make_peer(uint32_t, Node *);
    Node *find_node(uint32_t);
    Node *find_existing_node(uint32_t) const;

    void collapse_subtree(Node *);
    void node_to_prefix(Node *, int);
    uint32_t node_to_discriminated_by(Node *, const AggregateTree &, uint32_t, bool);
    void node_sample(Node *, uint32_t);
    void node_cut_smaller(Node *, uint32_t);

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
AggregateTree::add(uint32_t aggregate, uint32_t count)
{
    if (Node *n = find_node(aggregate))
	if ((n->count += count) == count)
	    _num_nonzero++;
}

inline uint32_t
AggregateTree::prefix_to_mask(int p)
{
    assert(p >= 0 && p <= 32);
    return (p == 0 ? 0 : (0xFFFFFFFFU << (32 - p)));
}

extern int bi_ffs(uint32_t);

#endif
