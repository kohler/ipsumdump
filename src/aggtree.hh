#ifndef AGGTREE_HH
#define AGGTREE_HH
#include <click/vector.hh>

class AggregateTree {

    AggregateTree();
    AggregateTree(const AggregateTree &);
    ~AggregateTree();

    bool ok(ErrorHandler * = 0) const;
    
    uint32_t num_nonzero() const		{ return _num_nonzero; }
    
    void add(uint32_t aggregate, uint32_t count = 1);
    
    void prefixize(int prefix_len);

    int read_file(FILE *, ErrorHandler *);
    int write_file(FILE *, bool, ErrorHandler *) const;

    AggregateTree &operator=(const AggregateTree &);
    
  public:
    
    struct Node {
	uint32_t aggregate;
	uint32_t count;
	Node *child[2];
    };

    Node *_root;
    Node *_free;
    Vector<Node *> _blocks;

    uint32_t _num_nonzero;

    Node *new_node();
    Node *new_node_block();
    void free_node(Node *);
    void initialize_root();
    void kill_all_nodes();

    Node *make_peer(uint32_t, Node *);
    Node *find_node(uint32_t);

    static uint32_t write_nodes(Node *, FILE *, bool, uint32_t *, int &, int, ErrorHandler *);
    static int write_file_handler(const String &, Element *, void *, ErrorHandler *);
    
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

#endif
