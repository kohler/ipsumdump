#include <click/config.h>
#include "aggtree.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <packet_anno.hh>

void
AggregateTree::initialize_root()
{
    if (!(_root = new_node())) {
	fprintf(stderr, "out of memory!\n");
	abort();
    }
    _root->aggregate = 0;
    _root->count = 0;
    _root->child[0] = _root->child[1] = 0;
    _num_nonzero = 0;
}

void
AggregateTree::copy_nodes(Node *n)
{
    if (n->count)
	add(n->aggregate, n->count);
    if (n->child[0])
	copy_nodes(n->child[0]);
    if (n->child[1])
	copy_nodes(n->child[1]);
}

AggregateTree::AggregateTree()
    : _free(0)
{
    initialize_root();
}

AggregateTree::AggregateTree(const AggregateTree &o)
    : _free(0)
{
    initialize_root();
    copy_nodes(o._root);
}

AggregateTree::~AggregateTree()
{
    kill_all_nodes();
}

AggregateTree &
AggregateTree::operator=(const AggregateTree &o)
{
    if (&o != this) {
	kill_all_nodes();
	initialize_root();
	copy_nodes(o._root);
    }
    return *this;
}

AggregateTree::Node *
AggregateTree::new_node_block()
{
    assert(!_free);
    int block_size = 1024;
    Node *block = new Node[block_size];
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
AggregateTree::kill_all_nodes()
{
    for (int i = 0; i < _blocks.size(); i++)
	delete _blocks[i];
    _blocks.clear();
    _root = _free = 0;
}

// from tcpdpriv
int
bi_ffs(uint32_t value)
{
    int add = 0;
    static uint8_t bvals[] = { 0, 4, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1 };

    if ((value & 0xFFFF0000) == 0) {
	if (value == 0) {	/* zero input ==> zero output */
	    return 0;
	}
	add += 16;
    } else {
	value >>= 16;
    }
    if ((value & 0xFF00) == 0) {
	add += 8;
    } else {
	value >>= 8;
    }
    if ((value & 0xF0) == 0) {
	add += 4;
    } else {
	value >>= 4;
    }
    return add + bvals[value & 0xf];
}

//
// check to see tree is OK
//

static int
node_ok(Node *n, int last_swivel, ErrorHandler *errh)
{
    if (n->child[0] && n->child[1]) {
	int swivel = bi_ffs(n->child[0]->aggregate ^ n->child[1]->aggregate);
	if (swivel <= last_swivel)
	    return errh->error("%u: bad swivel %d <= %d", n->aggregate, swivel, last_swivel);
	
	uint32_t mask = (swivel == 1 ? 0 : 0xFFFFFFFFU << (33 - swivel));
	if ((n->child[0]->aggregate & mask) != (n->aggregate & mask))
	    return errh->error("%u: left child doesn't match upper bits (swivel %d)", n->aggregate, swivel);
	if ((n->child[1]->aggregate & mask) != (n->aggregate & mask))
	    return errh->error("%u: right child doesn't match upper bits (swivel %d)", n->aggregate, swivel);

	mask = (1 << (32 - swivel));
	if ((n->child[0]->aggregate & mask) != 0)
	    return errh->error("%u: left child swivel bit one (swivel %d)", n->aggregate, swivel);
	if ((n->child[1]->aggregate & mask) == 0)
	    return errh->error("%u: right child swivel bit zero (swivel %d)", n->aggregate, swivel);

	int ok1 = node_ok(n->child[0], swivel, errh);
	int ok2 = node_ok(n->child[1], swivel, errh);
	return (ok1 >= 0 && ok2 >= 0 ? 0 : -1);
	
    } else if (n->child[0] || n->child[1])
	return errh->error("%u: only one live child", n->aggregate);
    else
	return 0;
}

bool
AggregateTree::ok(ErrorHandler *errh) const
{
    if (!errh)
	errh = ErrorHandler::silent_handler();
    return (node_ok(_root, -1, errh) >= 0);
}

AggregateTree::Node *
AggregateTree::make_peer(uint32_t a, Node *n)
{
    if (n->count == 0) {
	n->aggregate = a;
	return n;
    }
    
    /*
     * become a peer
     * algo: create two nodes, the two peers.  leave orig node as
     * the parent of the two new ones.
     */

    Node *down[2];
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

    down[bitvalue]->aggregate = a;
    down[bitvalue]->count = 0;
    down[bitvalue]->child[0] = down[bitvalue]->child[1] = 0;

    *down[1 - bitvalue] = *n;	/* copy orig node down one level */

    n->aggregate = down[0]->aggregate;
    n->count = down[0]->count;
    n->child[0] = down[0];	/* point to children */
    n->child[1] = down[1];

    down[0]->count = 0;

    return (n->aggregate == a ? n : down[bitvalue]);
}

AggregateTree::Node *
AggregateTree::find_node(uint32_t a)
{
    // straight outta tcpdpriv
    Node *n = _root;
    while (n) {
	if (n->aggregate == a)
	    return n;
	if (!n->child[0])
	    n = make_peer(a, n);
	else {
	    // swivel is the first bit in which the two children differ
	    int swivel = bi_ffs(n->child[0]->aggregate ^ n->child[1]->aggregate);
	    if (bi_ffs(a ^ n->aggregate) < swivel) // input differs earlier
		n = make_peer(a, n);
	    else if (a & (1 << (32 - swivel)))
		n = n->child[1];
	    else
		n = n->child[0];
	}
    }
    
    click_chatter("AggregateTree: out of memory!");
    return 0;
}


int
AggregateTree::read_file(FILE *f, ErrorHandler *errh)
{
    char buf[BUFSIZ];
    uint32_t agg, value;
    while (fgets(s, BUFSIZ, f)) {
	if (strlen(s) == BUFSIZ - 1 && s[BUFSIZ - 2] != '\n')
	    return errh->error("line too long");
	if (strcmp(s, "$packed\n") == 0) {
	    // read packed file
	    uint32_t ubuf[BUFSIZ];
	    while (!feof(f) && !ferror(f)) {
		size_t howmany = fread(ubuf, 8, BUFSIZ / 2, f);
		for (size_t i = 0; i < howmany; i++)
		    add(ubuf[2*i], ubuf[2*i + 1]);
	    }
	    break;
	} else if (sscanf(s, "%u %u", &agg, &value) == 2)
	    add(agg, value);
    }
    if (ferror(f))
	return errh->error("file error");
    return 0;
}

static void
write_batch(FILE *f, bool binary, uint32_t *buffer, int pos,
	    ErrorHandler *)
{
    if (binary)
	fwrite(buffer, sizeof(uint32_t), pos, f);
    else
	for (int i = 0; i < pos; i += 2)
	    fprintf(f, "%u %u\n", buffer[i], buffer[i+1]);
}

uint32_t
AggregateTree::write_nodes(Node *n, FILE *f, bool binary,
			   uint32_t *buffer, int &pos, int len,
			   ErrorHandler *errh)
{
    uint32_t nnz;
    
    if (n->count > 0) {
	buffer[pos++] = n->aggregate;
	buffer[pos++] = n->count;
	if (pos == len) {
	    write_batch(f, binary, buffer, pos, errh);
	    pos = 0;
	}
	nnz = 1;
    } else
	nnz = 0;

    if (n->child[0])
	nnz += write_nodes(n->child[0], f, binary, buffer, pos, len, errh);
    if (n->child[1])
	nnz += write_nodes(n->child[1], f, binary, buffer, pos, len, errh);

    return nnz;
}

int
AggregateTree::write_file(FILE *f, bool binary, ErrorHandler *errh) const
{
    bool seekable = (fseek(f, 0, SEEK_SET) >= 0);
    if (seekable)
	fprintf(f, "$num_nonzero            \n");
    if (binary)
	fprintf(f, "$packed\n");
    
    uint32_t buf[1024];
    int pos = 0;
    uint32_t nnz = write_nodes(_root, f, binary, buf, pos, 1024, errh);
    if (pos)
	write_batch(f, binary, buf, pos, errh);

    if (seekable) {
	fseek(f, 0, SEEK_SET);
	fprintf(f, "$num_nonzero %u", nnz);
    }

    if (ferror(f))
	return errh->error("%s: file error", where.cc());
    else
	return 0;
}

ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(AggregateTree)
