#include <click/config.h>
#include "aggwtree.hh"
#include <click/glue.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/integers.hh>
#include <cstdlib>
#include <cstring>

#ifdef HAVE_BYTEORDER_H
#include <byteorder.h>
#else
static inline uint32_t bswap_32(uint32_t u) {
    return ((u >> 24) | ((u & 0xff0000) >> 8) | ((u & 0xff00) << 8) | ((u & 0xff) << 24));
}
#endif

typedef AggregateWTree::WNode WNode;


// AggregateTree methods

AggregateTree::AggregateTree(const AggregateWTree &o)
    : _free(0), _read_format(o._read_format)
{
    initialize_root();
    copy_nodes(o._root);
}

AggregateTree &
AggregateTree::operator=(const AggregateWTree &o)
{
    kill_all_nodes();
    initialize_root();
    copy_nodes(o._root);
    _read_format = o._read_format;
    return *this;
}


// AggregateWTree

void
AggregateWTree::initialize_root()
{
    if (!(_root = new_node())) {
	fprintf(stderr, "out of memory!\n");
	abort();
    }
    _root->aggregate = 0;
    _root->count = _root->full_count = 0;
    _root->wchild[0] = _root->wchild[1] = 0;
    _root->depth = 0;
    _num_nonzero = 0;
}

void
AggregateWTree::copy_nodes(const Node* n, uint32_t mask)
{
    if (n->count)
	add(n->aggregate & mask, n->count);
    if (n->child[0]) {
	copy_nodes(n->child[0], mask);
	copy_nodes(n->child[1], mask);
    }
}

void
AggregateWTree::set_count_type(int count_what)
{
    _topheavy = ((count_what & LEAF) == 0);
    _count_type = (count_what & ~LEAF);
}

AggregateWTree::AggregateWTree(int count_what)
    : _free(0), _read_format(AggregateTree::WR_UNKNOWN)
{
    set_count_type(count_what);
    initialize_root();
}

AggregateWTree::AggregateWTree(const AggregateTree &o, int count_what)
    : _free(0), _read_format(o._read_format)
{
    set_count_type(count_what);
    initialize_root();
    copy_nodes(o._root);
}

AggregateWTree::AggregateWTree(const AggregateWTree &o)
    : _free(0), _count_type(o._count_type), _topheavy(o._topheavy),
      _read_format(o._read_format)
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
	_read_format = o._read_format;
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
	block[i].wchild[0] = &block[i+1];
    block[block_size - 1].wchild[0] = 0;
    _free = &block[1];
    return &block[0];
}

void
AggregateWTree::kill_all_nodes()
{
    for (int i = 0; i < _blocks.size(); i++)
	delete[] _blocks[i];
    _blocks.clear();
    _root = _free = 0;
}

//
// check to see tree is OK
//

static uint32_t NODE_OK_ERROR = (uint32_t) ErrorHandler::error_result;

uint32_t
AggregateWTree::node_ok(WNode *n, int last_swivel, uint32_t *nnz_ptr,
			ErrorHandler *errh) const
{
    //fprintf(stderr, "%*s%08x: <%u %u %u>\n", (last_swivel < 0 ? 0 : last_swivel), "", n->aggregate, n->child_count[0], n->count, n->child_count[1]);

    if (n->count && nnz_ptr)
	(*nnz_ptr)++;
    uint32_t local_count = node_local_count(n);
    if (n->depth != last_swivel)
	errh->error("%x: bad depth %d <= %d", n->aggregate, n->depth, last_swivel);

    if (n->wchild[0] && n->wchild[1]) {
	int swivel = ffs_msb(n->wchild[0]->aggregate ^ n->wchild[1]->aggregate);
	if (swivel <= last_swivel)
	    return errh->error("%x: bad swivel %d <= %d (%x-%x)", n->aggregate, swivel, last_swivel, n->wchild[0]->aggregate, n->wchild[1]->aggregate);

	uint32_t mask = (swivel == 1 ? 0 : 0xFFFFFFFFU << (33 - swivel));
	if ((n->wchild[0]->aggregate & mask) != (n->aggregate & mask))
	    return errh->error("%x: left child doesn't match upper bits (swivel %d)", n->aggregate, swivel);
	if ((n->wchild[1]->aggregate & mask) != (n->aggregate & mask))
	    return errh->error("%x: right child doesn't match upper bits (swivel %d)", n->aggregate, swivel);

	mask = (1 << (32 - swivel));
	if ((n->wchild[0]->aggregate & mask) != 0)
	    return errh->error("%x: left child swivel bit one (swivel %d)", n->aggregate, swivel);
	if ((n->wchild[1]->aggregate & mask) == 0)
	    return errh->error("%x: right child swivel bit zero (swivel %d)", n->aggregate, swivel);

	mask = (swivel == 1 ? 0xFFFFFFFFU : (1 << (32 - swivel)) - 1);
	if (n->aggregate & mask)
	    return errh->error("%x: lower bits nonzero (swivel %d)", n->aggregate, swivel);

	// check topheaviness
	if (_topheavy && n->aggregate == n->wchild[0]->aggregate && n->wchild[0]->count)
	    return errh->error("%x: packets present in copied left child", n->aggregate);
	else if (!_topheavy && n->count)
	    return errh->error("%x: packets present in middle of tree", n->aggregate);

	// check child counts
	uint32_t left_count = node_ok(n->wchild[0], swivel, nnz_ptr, errh);
	uint32_t right_count = node_ok(n->wchild[1], swivel, nnz_ptr, errh);
	if (left_count + right_count + local_count != n->full_count
	    && left_count != NODE_OK_ERROR && right_count != NODE_OK_ERROR)
	    return errh->error("%x: bad full count: nominally %u, calculated %u", n->aggregate, n->full_count, left_count + right_count + local_count);

	return left_count + right_count + local_count;

    } else if (n->wchild[0] || n->wchild[1])
	return errh->error("%x: only one live child", n->aggregate);

    else if (local_count != n->full_count)
	return errh->error("%x: bad full count for leaf: nominally %u, calculated %u", n->aggregate, n->full_count, local_count);

    else
	return local_count;
}

bool
AggregateWTree::ok(ErrorHandler *errh) const
{
    if (!errh)
	errh = ErrorHandler::default_handler();

    int before = errh->nerrors();
    uint32_t nnz = 0;
    (void) node_ok(_root, 0, &nnz, errh);
    if (errh->nerrors() == before && nnz != _num_nonzero)
	errh->error("bad num_nonzero: nominally %u, calculated %u", _num_nonzero, nnz);

    return (errh->nerrors() == before);
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
    int swivel = ffs_msb(a ^ n->aggregate);
    // bitvalue is the value of that bit of 'a'
    int bitvalue = (a >> (32 - swivel)) & 1;
    // mask masks off all bits before swivel
    uint32_t mask = (swivel == 1 ? 0 : (0xFFFFFFFFU << (33 - swivel)));

    down[bitvalue]->aggregate = a;
    down[bitvalue]->count = down[bitvalue]->full_count = 0;
    down[bitvalue]->wchild[0] = down[bitvalue]->wchild[1] = 0;

    *down[1 - bitvalue] = *n;	/* copy orig node down one level */

    down[0]->depth = down[1]->depth = swivel;

    n->aggregate = (down[0]->aggregate & mask);
    if (down[0]->aggregate == n->aggregate && _topheavy) {
	n->count = down[0]->count;
	down[0]->full_count -= node_local_count(down[0]);
	down[0]->count = 0;
    } else
	n->count = 0;
    n->wchild[0] = down[0];	/* point to children */
    n->wchild[1] = down[1];

    return (n->aggregate == a && _topheavy ? n : down[bitvalue]);
}

void
AggregateWTree::finish_add(WNode *n, int32_t delta, WNode *stack[], int pos)
{
    assert(pos > 0 && stack[pos - 1] == n);
    uint32_t old_count = n->count;
    n->count += delta;
    int32_t nnz_delta = (n->count != 0) - (old_count != 0);
    _num_nonzero += nnz_delta;
    if (_count_type == COUNT_ADDRS)
	delta = nnz_delta;
    while (pos > 0) {
	WNode *x = stack[--pos];
	x->full_count += delta;
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

	stack[pos++] = n;

	if (n->aggregate == a) {
	    if (!_topheavy && n->wchild[0]) { // take left child by definition
		n = n->wchild[0];
		continue;
	    }
	    finish_add(n, delta, stack, pos);
	    return;
	}

	if (!n->wchild[0])
	    n = make_peer(a, n);
	else {
	    // swivel is the first bit in which the two children differ
	    int swivel = ffs_msb(n->wchild[0]->aggregate ^ n->wchild[1]->aggregate);
	    if (ffs_msb(a ^ n->aggregate) < swivel) // input differs earlier
		n = make_peer(a, n);
	    else if (a & (1 << (32 - swivel)))
		n = n->wchild[1];
	    else
		n = n->wchild[0];
	}
    }

    fprintf(stderr, "AggregateWTree: out of memory!\n");
}

static void
check_stack(AggregateWTree::WNode *stack[], int pos)
{
    for (int i = 0; i < pos - 1; i++) {
	int bitvalue = (stack[i]->wchild[1] == stack[i+1]);
	assert(stack[i]->wchild[bitvalue] == stack[i+1]);
    }
}

void
AggregateWTree::adjust_num_nonzero(int32_t delta, WNode *stack[], int pos)
{
    check_stack(stack, pos);
    _num_nonzero += delta;
    if (_count_type == COUNT_ADDRS && delta)
	for (int i = 0; i < pos; i++)
	    stack[i]->full_count += delta;
}

void
AggregateWTree::free_subtree_x(WNode *n, uint32_t &nnz, uint32_t &count)
{
    if (n->count)
	nnz++;
    count += n->count;
    if (n->wchild[0]) {
	free_subtree_x(n->wchild[0], nnz, count);
	free_subtree_x(n->wchild[1], nnz, count);
    }
    free_node(n);
}

void
AggregateWTree::collapse_subtree(WNode *n, WNode *stack[], int pos)
{
    assert(pos > 0 && stack[pos - 1] == n);
    if (n->wchild[0]) {
	uint32_t nnz = (n->count != 0), count = 0;
	free_subtree_x(n->wchild[0], nnz, count);
	free_subtree_x(n->wchild[1], nnz, count);
	n->wchild[0] = n->wchild[1] = 0;
	n->count += count;
	adjust_num_nonzero((n->count != 0) - nnz, stack, pos);
	assert(n->full_count == node_local_count(n));
    }
}

void
AggregateWTree::delete_subtree(WNode *n, WNode *stack[], int pos)
{
    collapse_subtree(n, stack, pos);
    finish_add(n, -n->count, stack, pos);
}


//
// SAMPLING
//

AggregateWTree::WNode *
AggregateWTree::pick_random_active_node(WNode *stack[], int *store_pos) const
{
    // return early if no nodes whatsoever in tree
    if (_num_nonzero == 0)
	return 0;

    int pos = 0;
    WNode *n = _root;
    uint32_t v = ((uint32_t)random()) % (_root->full_count);

    while (n) {
	uint32_t left_count = node_full_count(n->wchild[0]);
	uint32_t self_count = node_local_count(n);
	assert(v < left_count + self_count + node_full_count(n->wchild[1]));
	stack[pos++] = n;
	if (v < left_count)
	    n = n->wchild[0];
	else if (v < left_count + self_count) {
	    *store_pos = pos;
	    return n;
	} else {
	    v -= left_count + self_count;
	    n = n->wchild[1];
	}
    }

    // cannot happen
    assert(0);
    return 0;
}

void
AggregateWTree::cull_addresses(uint32_t max_nnz)
{
    WNode *stack[32];
    int pos;
    assert(_count_type == COUNT_ADDRS);
    while (_num_nonzero > max_nnz) {
	WNode *n = pick_random_active_node(stack, &pos);
	finish_add(n, -n->count, stack, pos);
    }
}

void
AggregateWTree::cull_addresses_by_packets(uint32_t max_nnz)
{
    WNode *stack[32];
    int pos;
    assert(_count_type == COUNT_PACKETS);
    while (_num_nonzero > max_nnz) {
	WNode *n = pick_random_active_node(stack, &pos);
	finish_add(n, -1, stack, pos);
    }
}

void
AggregateWTree::cull_packets(uint32_t max_np)
{
    WNode *stack[32];
    int pos;
    assert(_count_type == COUNT_PACKETS);
    for (uint32_t np = _root->full_count; np > max_np; np--) {
	WNode *n = pick_random_active_node(stack, &pos);
	finish_add(n, -1, stack, pos);
    }
}


//
// PREFIXES
//

void
AggregateWTree::node_prefixize(WNode *n, int prefix, WNode *stack[], int pos)
{
    assert(!n->wchild[0] || n->wchild[0]->depth == n->wchild[1]->depth);
    n->aggregate &= prefix_to_mask(prefix);
    stack[pos++] = n;

    if (!n->wchild[0])
	/* do nothing */;
    else if (n->wchild[0]->depth > prefix)
	collapse_subtree(n, stack, pos);
    else {
	node_prefixize(n->wchild[0], prefix, stack, pos);
	node_prefixize(n->wchild[1], prefix, stack, pos);
	if (n->wchild[0]->depth == prefix && _topheavy) {
	    WNode *left = n->wchild[0];
	    assert(left->aggregate == n->aggregate && !left->wchild[0]);
	    int nnz_change = (left->count && n->count ? -1 : 0);
	    n->count += left->count;
	    left->count = left->full_count = 0;
	    adjust_num_nonzero(nnz_change, stack, pos);
	}
    }
}

void
AggregateWTree::prefixize(int prefix_len)
{
    assert(prefix_len >= 0 && prefix_len <= 32);
    WNode *stack[32];
    if (prefix_len < 32)
	node_prefixize(_root, prefix_len, stack, 0);
}

void
AggregateWTree::make_prefix(int prefix_len, AggregateWTree &t) const
{
    assert(prefix_len >= 0 && prefix_len <= 32);
    t.copy_nodes(_root, prefix_to_mask(prefix_len));
}

void
AggregateWTree::num_active_prefixes(Vector<uint32_t> &out) const
{
    AggregateTree copy(*this);
    out.assign(33, 0);
    out[32] = nnz();
    for (int i = 31; i >= 0; i--) {
	copy.prefixize(i);
	out[i] = copy.nnz();
    }
}


//
// DISCRIMINATING PREFIXES
//

static uint32_t
node_discriminated_by(WNode *n, uint32_t *ndp)
{
    if (n->wchild[0]) {
	assert(!n->count);
	WNode *left = n->wchild[0], *right = n->wchild[1];
	assert(left && right);
	uint32_t nnondiscrim = node_discriminated_by(left, ndp)
	    + node_discriminated_by(right, ndp);
	if (nnondiscrim && left->full_count && right->full_count) {
	    int swivel = ffs_msb(left->aggregate ^ right->aggregate);
	    assert(swivel >= 0 && swivel <= 32);
	    ndp[swivel] += nnondiscrim;
	    nnondiscrim = 0;
	}
	return nnondiscrim;
    } else
	return (n->count != 0);
}

void
AggregateWTree::num_discriminated_by_prefix(uint32_t ndp[33]) const
{
    assert(!_topheavy && _root);
    for (int i = 0; i <= 32; i++)
	ndp[i] = 0;
    uint32_t any = node_discriminated_by(_root, ndp);
    assert(any == 0 || any == 1);
    ndp[0] += any;
}

void
AggregateWTree::num_discriminated_by_prefix(Vector<uint32_t> &ndp) const
{
    ndp.resize(33);
    num_discriminated_by_prefix(&ndp[0]);
}


//
// COLLECT ACTIVE NODES
//

static void
node_collect_active(WNode *n, Vector<WNode *> &v)
{
    if (n->count)
	v.push_back(n);
    if (n->wchild[0]) {
	node_collect_active(n->wchild[0], v);
	node_collect_active(n->wchild[1], v);
    }
}

void
AggregateWTree::collect_active(Vector<WNode *> &v) const
{
    v.reserve(v.size() + _num_nonzero);
    node_collect_active(_root, v);
}

static void
node_collect_active_depth(WNode *n, int d, Vector<WNode *> &v)
{
    if (n->count && n->depth == d)
	v.push_back(n);
    if (n->wchild[0]) {
	node_collect_active_depth(n->wchild[0], d, v);
	node_collect_active_depth(n->wchild[1], d, v);
    }
}

void
AggregateWTree::collect_active_depth(int d, Vector<WNode *> &v) const
{
    v.reserve(v.size() + _num_nonzero);
    node_collect_active_depth(_root, d, v);
}


//
// FAKING BASED ON DISCRIMINATING PREFIX
//

void
AggregateWTree::fake_by_discriminating_prefix(int q, const uint32_t dp[33][33],
					      double randomness)
{
    assert(q >= 0 && q <= 32 && !_topheavy && randomness >= 0 && randomness <= 1);

    if (q == 0) {
	assert(_root->count == 0 && !_root->wchild[0]);
	assert(dp[0][0] == 0 || dp[0][0] == 1);
	if (dp[0][0])
	    add(0, 1);
    }

    // collect nonzero nodes with correct depth
    Vector<WNode *> s;
    collect_active_depth(q, s);

    //
    for (int p = q + 1; p <= 32; p++) {
	assert((uint32_t) s.size() == dp[p-1][q]);

#if 1
	uint32_t first_random = dp[p-1][q] - (uint32_t)(randomness * (dp[p-1][q] - dp[p][q]));
	if (randomness >= 1)
	    first_random = dp[p][q];
#else
	uint32_t random_delta = (uint32_t) (dp[p][q] * (1 - randomness));
#endif

	for (uint32_t i = dp[p][q]; i < dp[p-1][q]; i++) {
	    // pick random element of s
#if 1
	    int which = (i >= first_random ? ((uint32_t)random()) % s.size() : s.size() - 1);
#else
	    int which = (random_delta >= dp[p][q] ? s.size() - 1 : (((uint32_t)random()) % (s.size() - random_delta)) + random_delta);
#endif
	    WNode *n = s[which];
	    assert(n->depth == p - 1 && n->count == 1 && n->full_count == 1);
	    add(n->aggregate | (1 << (32 - p)), 1);
	    s[which] = s.back();
	    s.pop_back();
	}

	for (uint32_t i = 0; i < dp[p][q]; i++) {
	    WNode *n = s[i];
	    assert(n->depth == p - 1 && n->count == 1 && n->full_count == 1);
	    (void) make_peer(n->aggregate | (1 << (32 - p)), n);
	    if (random() % 1) {	// swap left and right
		n->wchild[1]->count = n->wchild[1]->full_count = 1;
		n->wchild[0]->count = n->wchild[0]->full_count = 0;
		s[i] = n->wchild[1];
	    } else
		s[i] = n->wchild[0];
	}
    }

#if !NDEBUG
    if (q < 32)
	assert((uint32_t) s.size() == dp[32][q]);
    else {
	uint32_t nnz = 0;
	for (int p = 0; p <= 32; p++)
	    nnz += dp[32][p];
	assert((uint32_t) s.size() == nnz);
    }
#endif
}


static uint32_t branchcount_0[] = { 1, 1 };
static uint32_t branchcount_1[] = { 1, 2, 1 };
static uint32_t branchcount_2[] = { 1, 4, 6, 4, 1 };
static uint32_t branchcount_3[] = { 1, 8, 28, 56, 70, 56, 28, 8, 1 };
static uint32_t branchcount_4[] = { 1, 16, 120, 560, 1820, 4368, 8008, 11440, 12870, 11440, 8008, 4368, 1820, 560, 120, 16, 1 };

static struct Branch {
    uint32_t *val, *count, *off;
} branches[] = {
    { 0, branchcount_0, 0 },
    { 0, branchcount_1, 0 },
    { 0, branchcount_2, 0 },
    { 0, branchcount_3, 0 },
    { 0, branchcount_4, 0 },
};

static uint32_t nbits_set_5[] = {
    0, 1, 1, 2, 1, 2, 2, 3,
    1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5
};

static inline int
nbits_set(uint32_t val)
{
    int n = 0;
    while (val) {
	n += nbits_set_5[val & 037];
	val >>= 5;
    }
    return n;
}

static void
construct_branch(int depth)
{
    assert(depth >= 1 && depth <= 4);
    if (branches[depth].val)
	return;
    int n = (1 << depth);
    uint32_t *val = branches[depth].val = new uint32_t[1 << n];
    branches[depth].off = new uint32_t[n + 1];

    int k = 0;
    for (int i = 0; i <= n; i++) {
	branches[depth].off[i] = k;
	k +=  branches[depth].count[i];
    }

    uint32_t *off = new uint32_t[n + 1];
    memcpy(off, branches[depth].off, sizeof(uint32_t) * (n + 1));

    uint32_t max = (depth == 5 ? 0xFFFFFFFFU : (1 << n) - 1);
    for (uint32_t i = 0; i <= max; i++) {
	int nb = nbits_set(i);
	val[off[nb]++] = i;
    }

    for (int i = 0; i < n; i++)
	assert(off[i] == branches[depth].off[i + 1]);
    assert(off[n] == off[n-1] + 1);

    delete[] off;
}

void
AggregateWTree::fake_by_branching_counts(int p, int depth,
					 const Vector<uint32_t> &v, bool randomized)
{
    assert(p >= 0 && p <= 32 && depth > 0 && p + depth <= 32);
    assert(v.size() == ((1 << depth) + 1) && depth <= 4);

    if (!branches[depth].val)
	construct_branch(depth);

    uint32_t nnz_v = 0;
    for (int i = 1; i < v.size(); i++)
	nnz_v += v[i];

    if (p == 0) {
	assert(_root->count == 0 && !_root->wchild[0]);
	assert(nnz_v == 0 || nnz_v == 1);
	if (nnz_v)
	    add(0, 1);
    }

    assert(nnz_v == _num_nonzero);

    // collect nonzero nodes with correct depth
    Vector<WNode *> s;
    collect_active(s);

    //
    uint32_t mask_delta = (1 << (32 - p - depth));
    for (int count = 0; count < v.size(); count++) {
	assert((uint32_t) s.size() >= v[count]);
	const uint32_t *brval = branches[depth].val + branches[depth].off[count];
	const uint32_t brcount = branches[depth].count[count];

	for (uint32_t k = 0; k < v[count]; k++) {
	    // pick random element of s
	    int which = (randomized ? ((uint32_t)random()) % s.size() : s.size() - 1);
	    WNode *n = s[which];
	    assert(n->count == 1 && n->full_count == 1);

	    // split into count subaggregates in a random manner
	    uint32_t value = brval[((uint32_t)random()) % brcount];
	    for (int i = 0; i < (1 << depth); i++, value >>= 1)
		if (value & 1)
		    add(n->aggregate + (i * mask_delta), 1);
	    add(n->aggregate, -1);

	    s[which] = s.back();
	    s.pop_back();
	}
    }

    assert(s.size() == 0);
}


//
// FAKING BASED ON DIRICHLET
//

void
AggregateWTree::node_fake_dirichlet(WNode *n, WNode *stack[], int stack_pos,
				    uint32_t randval)
{
    if (stack_pos == 32) {
	assert(n->count == 0 && n->depth == 32 && !n->wchild[0]);
	n->count = n->full_count = 1;
	_num_nonzero++;
	for (int i = 0; i < stack_pos; i++)
	    stack[i]->full_count++;
	return;
    }

    if (!n->wchild[0]) {
	assert((n->aggregate & ~prefix_to_mask(n->depth)) == 0);
	(void) make_peer(n->aggregate | (1 << (31 - n->depth)), n);
	if (!n->wchild[0])
	    return;
    }

    WNode *a = n->wchild[0], *b = n->wchild[1];
    assert(a->depth == b->depth);
    uint32_t full_subtree = (1U << (32 - a->depth));
    assert(a->full_count <= full_subtree && b->full_count <= full_subtree);

    int which;
    if ((!a->full_count && !b->full_count) || b->full_count == full_subtree)
	which = 0;
    else if (a->full_count == full_subtree)
	which = 1;
    else if (b->full_count == 0)
	which = ((randval % 5) >= 1);
    else
	which = ((randval % (a->full_count + b->full_count)) >= a->full_count);

    WNode *c = (which ? b : a);
    assert(c->full_count < full_subtree);
    stack[stack_pos++] = n;
    node_fake_dirichlet(c, stack, stack_pos, randval);
}

void
AggregateWTree::fake_by_dirichlet(uint32_t nnz)
{
    assert(_num_nonzero == 0 && !_topheavy);
    WNode *stack[32];
    for (uint32_t i = 0; i < nnz; i++)
	node_fake_dirichlet(_root, stack, 0, random());
}


//
// READING AND WRITING
//

void
AggregateWTree::read_packed_file(FILE *f, int file_byte_order)
{
    uint32_t ubuf[BUFSIZ];
    _read_format = AggregateTree::WR_BINARY;
    if (file_byte_order == CLICK_BYTE_ORDER) {
	while (!feof(f) && !ferror(f)) {
	    size_t howmany = fread(ubuf, 8, BUFSIZ / 2, f);
	    for (size_t i = 0; i < howmany; i++)
		add(ubuf[2*i], ubuf[2*i + 1]);
	}
    } else {
	while (!feof(f) && !ferror(f)) {
	    size_t howmany = fread(ubuf, 8, BUFSIZ / 2, f);
	    for (size_t i = 0; i < howmany; i++)
		add(bswap_32(ubuf[2*i]), bswap_32(ubuf[2*i + 1]));
	}
    }
}

int
AggregateWTree::read_file(FILE *f, ErrorHandler *errh)
{
    char s[BUFSIZ];
    uint32_t agg, value, b[4];
    _read_format = AggregateTree::WR_ASCII;
    while (fgets(s, BUFSIZ, f)) {
	if (strlen(s) == BUFSIZ - 1 && s[BUFSIZ - 2] != '\n')
	    return errh->error("line too long");
	if (s[0] == '$' || s[0] == '!') {
	    if (strcmp(s + 1, "packed\n") == 0)
		read_packed_file(f, CLICK_BYTE_ORDER);
	    else if (strcmp(s + 1, "packed_le\n") == 0)
		read_packed_file(f, CLICK_LITTLE_ENDIAN);
	    else if (strcmp(s + 1, "packed_be\n") == 0)
		read_packed_file(f, CLICK_BIG_ENDIAN);
	} else if (sscanf(s, "%u %u", &agg, &value) == 2)
	    add(agg, value);
	else if (sscanf(s, "%u.%u.%u.%u %u", &b[0], &b[1], &b[2], &b[3], &value) == 5
		 && b[0] < 256 && b[1] < 256 && b[2] < 256 && b[3] < 256) {
	    add((b[0]<<24) | (b[1]<<16) | (b[2]<<8) | b[3], value);
	    _read_format = AggregateTree::WR_ASCII_IP;
	}
    }
    if (ferror(f))
	return errh->error("file error");
    return 0;
}

int
AggregateWTree::write_file(FILE *f, AggregateTree::WriteFormat format, ErrorHandler *errh) const
{
    fprintf(f, "!num_nonzero %u\n", _num_nonzero);
    if (format == AggregateTree::WR_BINARY) {
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
	fprintf(f, "!packed_be\n");
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
	fprintf(f, "!packed_le\n");
#else
	format = AggregateTree::WR_ASCII;
#endif
    } else if (format == AggregateTree::WR_ASCII_IP)
	fprintf(f, "!ip\n");

    uint32_t buf[1024];
    int pos = 0;
    AggregateTree::write_nodes(_root, f, format, buf, pos, 1024, errh);
    if (pos)
	AggregateTree::write_batch(f, format, buf, pos, errh);

    if (ferror(f))
	return errh->error("file error");
    else
	return 0;
}

int
AggregateWTree::write_hex_file(FILE *f, ErrorHandler *errh) const
{
    fprintf(f, "!num_nonzero %u\n", _num_nonzero);

    AggregateTree::write_hex_nodes(_root, f, errh);

    if (ferror(f))
	return errh->error("file error");
    else
	return 0;
}
