#ifndef AGGWTREE_HH
#define AGGWTREE_HH
#include "aggtree.hh"

class AggregateWTree { public:

    static const int COUNT_HOSTS = 0;
    static const int COUNT_PACKETS = 1;

    AggregateWTree(int count_what);
    AggregateWTree(const AggregateWTree &);
    AggregateWTree(const AggregateTree &, int count_what);
    ~AggregateWTree();

    bool ok(ErrorHandler * = 0) const;

    uint32_t num_nonzero() const		{ return _num_nonzero; }
    uint32_t nnz() const			{ return _num_nonzero; }
    
    void add(uint32_t aggregate, int32_t count = 1);

    void cull_hosts(uint32_t nnz);
    void cull_hosts_by_packets(uint32_t nnz);
    void cull_packets(uint32_t np);

    void left_right_balance(FILE *, int p) const;
    
    int read_file(FILE *, ErrorHandler *);
    int write_file(FILE *, bool binary, ErrorHandler *) const;

    AggregateWTree &operator=(const AggregateWTree &);

    typedef AggregateTree::Node Node;
    struct WNode : public Node {
	uint32_t child_count[2];
    };

  public:
    
    WNode *_root;
    WNode *_free;
    Vector<WNode *> _blocks;

    uint32_t _num_nonzero;
    int _count_type;

    WNode *new_node();
    WNode *new_node_block();
    void free_node(WNode *);
    void initialize_root();
    void copy_nodes(Node *, uint32_t = 0xFFFFFFFFU);
    void kill_all_nodes();

    WNode *make_peer(uint32_t, WNode *);
    void finish_add(WNode *, int32_t, WNode *stack[], int);

    uint32_t node_ok(WNode *, int, ErrorHandler *) const;
    WNode *pick_random_nonzero_node(WNode *stack[], int *) const;

    uint32_t node_count(WNode *) const;

    friend class AggregateTree;
    
};

inline AggregateWTree::WNode *
AggregateWTree::new_node()
{
    if (_free) {
	WNode *n = _free;
	_free = (WNode *)n->child[0];
	return n;
    } else
	return new_node_block();
}

inline void
AggregateWTree::free_node(WNode *n)
{
    n->child[0] = _free;
    _free = n;
}

inline uint32_t
AggregateWTree::node_count(WNode *n) const
{
    if (_count_type == COUNT_HOSTS)
	return n->child_count[0] + n->child_count[1] + (n->count ? 1 : 0);
    else
	return n->child_count[0] + n->child_count[1] + n->count;
}

#endif
