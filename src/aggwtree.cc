#include <click/config.h>
#include "aggwtree.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_BYTEORDER_H
#include <byteorder.h>
#else
static inline uint32_t bswap_32(uint32_t u) {
    return ((u >> 24) | ((u & 0xff0000) >> 8) | ((u & 0xff00) << 8) | ((u & 0xff) << 24));
}
#endif


void
AggregateWTree::initialize_root()
{
    if (!(_root = new_node())) {
	fprintf(stderr, "out of memory!\n");
	abort();
    }
    _root->aggregate = 0;
    _root->count = 0;
    _root->child_count[0] = _root->child_count[1] = 0;
    _root->child[0] = _root->child[1] = 0;
    _num_nonzero = 0;
}

void
AggregateWTree::copy_nodes(Node *n, uint32_t mask)
{
    if (n->count)
	add(n->aggregate & mask, n->count);
    if (n->child[0]) {
	copy_nodes(n->child[0], mask);
	copy_nodes(n->child[1], mask);
    }
}

AggregateWTree::AggregateWTree(int count_what)
    : _free(0), _count_type(count_what)
{
    initialize_root();
}

AggregateWTree::AggregateWTree(const AggregateTree &o, int count_what)
    : _free(0), _count_type(count_what)
{
    initialize_root();
    copy_nodes(o._root);
}

AggregateWTree::AggregateWTree(const AggregateWTree &o)
    : _free(0), _count_type(o._count_type)
{
    initialize_root();
    copy_nodes(o._root);
}

AggregateWTree::~AggregateWTree()
{
    kill_all_nodes();
}

AggregateWTree &
AggregateWTree::operator=(const AggregateWTree &o)
{
    if (&o != this) {
	kill_all_nodes();
	initialize_root();
	_count_type = o._count_type;
	copy_nodes(o._root);
    }
    return *this;
}

AggregateWTree::WNode *
AggregateWTree::new_node_block()
{
    assert(!_free);
    int block_size = 1024;
    WNode *block = new WNode[block_size];
    if (!block)
	return 0;
    _blocks.push_back(block);
    for (int i = 1; i < block_size - 1; i++)
	block[i].child[0] = &block[i+1];
    block[block_size - 1].child[0] = 0;
    _free = &block[1];
    return &block[0];
}

void
AggregateWTree::kill_all_nodes()
{
    for (int i = 0; i < _blocks.size(); i++)
	delete _blocks[i];
    _blocks.clear();
    _root = _free = 0;
}

//
// check to see tree is OK
//

uint32_t
AggregateWTree::node_ok(WNode *n, int last_swivel, ErrorHandler *errh) const
{
    //fprintf(stderr, "%*s%08x: <%u %u %u>\n", (last_swivel < 0 ? 0 : last_swivel), "", n->aggregate, n->child_count[0], n->count, n->child_count[1]);
    
    if (n->child[0] && n->child[1]) {
	int swivel = bi_ffs(n->child[0]->aggregate ^ n->child[1]->aggregate);
	if (swivel <= last_swivel)
	    return errh->error("%x: bad swivel %d <= %d (%x-%x)", n->aggregate, swivel, last_swivel, n->child[0]->aggregate, n->child[1]->aggregate);
	
	uint32_t mask = (swivel == 1 ? 0 : 0xFFFFFFFFU << (33 - swivel));
	if ((n->child[0]->aggregate & mask) != (n->aggregate & mask))
	    return errh->error("%x: left child doesn't match upper bits (swivel %d)", n->aggregate, swivel);
	if ((n->child[1]->aggregate & mask) != (n->aggregate & mask))
	    return errh->error("%x: right child doesn't match upper bits (swivel %d)", n->aggregate, swivel);

	mask = (1 << (32 - swivel));
	if ((n->child[0]->aggregate & mask) != 0)
	    return errh->error("%x: left child swivel bit one (swivel %d)", n->aggregate, swivel);
	if ((n->child[1]->aggregate & mask) == 0)
	    return errh->error("%x: right child swivel bit zero (swivel %d)", n->aggregate, swivel);

	mask = (swivel == 1 ? 0xFFFFFFFFU : (1 << (32 - swivel)) - 1);
	if (n->aggregate & mask)
	    return errh->error("%x: lower bits nonzero (swivel %d)", n->aggregate, swivel);

	// check child counts
	if (n->child_count[0] != node_count((WNode *) n->child[0]))
	    return errh->error("%x: child 0 count (%d) bad", n->aggregate, n->child_count[0]);
	if (n->child_count[1] != node_count((WNode *) n->child[1]))
	    return errh->error("%x: child 1 count (%d) bad", n->aggregate, n->child_count[1]);
		
	int ok1 = node_ok((WNode *) n->child[0], swivel, errh);
	int ok2 = node_ok((WNode *) n->child[1], swivel, errh);
	int local_nnz = (n->count ? 1 : 0);
	return ok1 + ok2 + local_nnz;
	
    } else if (n->child[0] || n->child[1])
	return errh->error("%x: only one live child", n->aggregate);
    else {
	if (n->child_count[0] || n->child_count[1])
	    return errh->error("%x: child counts nonzero", n->aggregate);
	return (n->count ? 1 : 0);
    }
}

bool
AggregateWTree::ok(ErrorHandler *errh) const
{
    if (!errh)
	errh = ErrorHandler::default_handler();

    int before = errh->nerrors();
    uint32_t nnz = node_ok(_root, -1, errh);
    if (errh->nerrors() == before && nnz != _num_nonzero)
	errh->error("bad num_nonzero: nominally %u, calculated %u", _num_nonzero, nnz);
    
    return (errh->nerrors() == before ? 0 : -1);
}


//
// TREE CONSTRUCTION
//

AggregateWTree::WNode *
AggregateWTree::make_peer(uint32_t a, WNode *n)
{
    /*
     * become a peer
     * algo: create two nodes, the two peers.  leave orig node as
     * the parent of the two new ones.
     */

    WNode *down[2];
    if (!(down[0] = new_node()))
	return 0;
    if (!(down[1] = new_node())) {
	free_node(down[0]);
	return 0;
    }

    // swivel is first bit 'a' and 'old->input' differ
    int swivel = bi_ffs(a ^ n->aggregate);
    // bitvalue is the value of that bit of 'a'
    int bitvalue = (a >> (32 - swivel)) & 1;
    // mask masks off all bits before swivel
    uint32_t mask = (swivel == 1 ? 0 : (0xFFFFFFFFU << (33 - swivel)));

    down[bitvalue]->aggregate = a;
    down[bitvalue]->count = 0;
    down[bitvalue]->child[0] = down[bitvalue]->child[1] = 0;
    down[bitvalue]->child_count[0] = down[bitvalue]->child_count[1] = 0;

    *down[1 - bitvalue] = *n;	/* copy orig node down one level */

    n->aggregate = (down[0]->aggregate & mask);
    if (down[0]->aggregate == n->aggregate) {
	n->count = down[0]->count;
	down[0]->count = 0;
    } else
	n->count = 0;
    n->child[0] = down[0];	/* point to children */
    n->child[1] = down[1];
    n->child_count[bitvalue] = 0;
    n->child_count[1 - bitvalue] = node_count(down[1 - bitvalue]);

    return (n->aggregate == a ? n : down[bitvalue]);
}

void
AggregateWTree::finish_add(WNode *n, int32_t delta, WNode *stack[], int pos)
{
    uint32_t old_count = n->count;
    n->count += delta;
    int32_t nnz_delta = (n->count != 0) - (old_count != 0);
    _num_nonzero += nnz_delta;
    if (_count_type == COUNT_HOSTS)
	delta = nnz_delta;
    while (pos > 0) {
	WNode *x = stack[--pos];
	if (x != n) {
	    int bitvalue = (x->child[1] == n);
	    assert(x->child[bitvalue] == n);
	    x->child_count[bitvalue] += delta;
	}
	n = x;
    }
}

void
AggregateWTree::add(uint32_t a, int32_t delta)
{
    WNode *stack[32];
    int pos = 0;
    
    // straight outta tcpdpriv
    WNode *n = _root;
    while (n) {
	
	if (n->aggregate == a) {
	    finish_add(n, delta, stack, pos);
	    return;
	}

	stack[pos++] = n;
	
	if (!n->child[0])
	    n = make_peer(a, n);
	else {
	    // swivel is the first bit in which the two children differ
	    int swivel = bi_ffs(n->child[0]->aggregate ^ n->child[1]->aggregate);
	    if (bi_ffs(a ^ n->aggregate) < swivel) // input differs earlier
		n = make_peer(a, n);
	    else if (a & (1 << (32 - swivel)))
		n = (WNode *)n->child[1];
	    else
		n = (WNode *)n->child[0];
	}
    }
    
    fprintf(stderr, "AggregateWTree: out of memory!\n");
}



//
// SAMPLING
//

AggregateWTree::WNode *
AggregateWTree::pick_random_nonzero_node(WNode *stack[], int *store_pos) const
{
    int pos = 0;
    WNode *n = _root;
    int ct = _count_type;

    while (n) {
	uint32_t self_count = (ct == COUNT_HOSTS ? n->count != 0 : n->count);
	uint32_t left_count = n->child_count[0];
	uint32_t nc = left_count + self_count + n->child_count[1];
	uint32_t v = ((uint32_t)random()) % nc;
	if (v < left_count) {
	    stack[pos++] = n;
	    n = (WNode *) n->child[0];
	} else if (v < left_count + self_count) {
	    *store_pos = pos;
	    return n;
	} else {
	    stack[pos++] = n;
	    n = (WNode *) n->child[1];
	}
    }

    // no nonzero nodes!
    assert(_num_nonzero == 0);
    return 0;
}

void
AggregateWTree::cull_hosts(uint32_t max_nnz)
{
    WNode *stack[32];
    int pos;
    assert(_count_type == COUNT_HOSTS);
    while (_num_nonzero > max_nnz) {
	WNode *n = pick_random_nonzero_node(stack, &pos);
	finish_add(n, -n->count, stack, pos);
    }
}

void
AggregateWTree::cull_hosts_by_packets(uint32_t max_nnz)
{
    WNode *stack[32];
    int pos;
    assert(_count_type == COUNT_PACKETS);
    while (_num_nonzero > max_nnz) {
	WNode *n = pick_random_nonzero_node(stack, &pos);
	finish_add(n, -1, stack, pos);
    }
}

void
AggregateWTree::cull_packets(uint32_t max_np)
{
    WNode *stack[32];
    int pos;
    assert(_count_type == COUNT_PACKETS);
    for (uint32_t np = node_count(_root); np > max_np; np--) {
	WNode *n = pick_random_nonzero_node(stack, &pos);
	finish_add(n, -1, stack, pos);
    }
}


//
// PREFIXES
//


//
// READING AND WRITING
//

static void
read_packed_file(FILE *f, AggregateWTree *tree, int file_byte_order)
{
    uint32_t ubuf[BUFSIZ];
    if (file_byte_order == CLICK_BYTE_ORDER) {
	while (!feof(f) && !ferror(f)) {
	    size_t howmany = fread(ubuf, 8, BUFSIZ / 2, f);
	    for (size_t i = 0; i < howmany; i++)
		tree->add(ubuf[2*i], ubuf[2*i + 1]);
	}
    } else {
	while (!feof(f) && !ferror(f)) {
	    size_t howmany = fread(ubuf, 8, BUFSIZ / 2, f);
	    for (size_t i = 0; i < howmany; i++)
		tree->add(bswap_32(ubuf[2*i]), bswap_32(ubuf[2*i + 1]));
	}
    }
}

int
AggregateWTree::read_file(FILE *f, ErrorHandler *errh)
{
    char s[BUFSIZ];
    uint32_t agg, value;
    while (fgets(s, BUFSIZ, f)) {
	if (strlen(s) == BUFSIZ - 1 && s[BUFSIZ - 2] != '\n')
	    return errh->error("line too long");
	if (s[0] == '$') {
	    if (strcmp(s, "$packed\n") == 0)
		read_packed_file(f, this, CLICK_BYTE_ORDER);
	    else if (strcmp(s, "$packed_le\n") == 0)
		read_packed_file(f, this, CLICK_LITTLE_ENDIAN);
	    else if (strcmp(s, "$packed_be\n") == 0)
		read_packed_file(f, this, CLICK_BIG_ENDIAN);
	} else if (sscanf(s, "%u %u", &agg, &value) == 2)
	    add(agg, value);
    }
    if (ferror(f))
	return errh->error("file error");
    return 0;
}

int
AggregateWTree::write_file(FILE *f, bool binary, ErrorHandler *errh) const
{
    fprintf(f, "$num_nonzero %u\n", _num_nonzero);
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
    if (binary)
	fprintf(f, "$packed_be\n");
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
    if (binary)
	fprintf(f, "$packed_le\n");
#else
    binary = false;
#endif
    
    uint32_t buf[1024];
    int pos = 0;
    AggregateTree::write_nodes(_root, f, binary, buf, pos, 1024, errh);
    if (pos)
	AggregateTree::write_batch(f, binary, buf, pos, errh);

    if (ferror(f))
	return errh->error("file error");
    else
	return 0;
}
