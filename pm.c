/** Pattern Matcher Implementation
 *
 */

#include "fw_common.h"
#include "pm.h"

/* Reallocation step for pm_node_t. (matched_patterns)	*/
#define REALLOC_CHUNK_MATCHSTR 1

/* Reallocation step for pm_node_t. (outgoing array)	*/
#define REALLOC_CHUNK_OUTGOING 1

/* Allocation step for automata.all_nodes		*/
#define REALLOC_CHUNK_ALLNODES 200

/** Initialize node
 *  Parameters:
 *	this  - The node to perform on.
 *  Returns: TRUE if succeed, FALSE if out of memory.
 */
static boolean
pm_node_init(pm_node_t* this);

/** Comparison function for qsort. see man qsort.
 *  Parameters:
 *	first  - The first edge to compare.
 *	second - The second edge to compare.
 *  Returns: 1 if greater or equal, -1 if not.
 */
static int
pm_node_edge_compare(const void* first, const void* second);

/** Determine if a final node contains a pattern in its accepted pattern list
 *	or not.
 *  Parameters:
 *	this   - The node to perform on.
 *	newstr - The new string to check.
 *  Returns: TRUE if it has, else FALSE
 */
static boolean
pm_node_has_matchstr(pm_node_t* this, pm_string_t* newstr);

/** Adds the node pointer to all_nodes.
 *  Parameters:
 *	this   - The automata to work on.
 *	node   - The node to add.
 *  Returns: TRUE if succeed, FALSE if out of memory.
 */
static boolean
pm_automata_register_nodeptr(pm_automata_t* this, pm_node_t* node);

/** Collect accepted patterns of the node. the accepted patterns consist of the
 *   node's own accepted pattern plus accepted patterns of its failure node.
 *  Parameters:
 *	node   - The node.
 *  Returns: TRUE if succeed, FALSE if out of memory.
 */
static boolean
pm_automata_union_matchstrs(pm_node_t* node);

/** Find failure node for the given node.
 *  Parameters:
 *   this   - The automata to work on.
 *   node   - The node to traverse.
 *   alphas - The alphabetics.
 */
static void
pm_automata_set_failure(pm_automata_t* this, pm_node_t* node, char* alphas);

/** Traverse all automata nodes using DFS (Depth First Search), meanwhile it set
 *	the failure node for every node it passes through. this function must be
 *	called after adding last pattern to automata. i.e. after calling this you
 *	can not add further pattern to automata.
 *  Parameters:
 *	this   - The automata to work on.
 *	node   - The node to traverse.
 *	alphas - The alphabetics.
 */
static void
pm_automata_traverse_setfailure(pm_automata_t* this, pm_node_t* node, char* alphas);

/** Reset the automata and make it ready for doing new search on a new text.
 *	when you finished with the input text, you must reset automata state for
 *	new input, otherwise it will not work.
 *  Parameters:
 *	this - The automata to work on.
 */
static void
pm_automata_reset (pm_automata_t* this);

/** Create the node
 *  Returns: The new allocated node or NULL if out of memory.
 */
pm_node_t*
pm_node_create(void)
{
	const static char	fname[]	= "pm_node_create";
	pm_node_t* 			this;

	this = (pm_node_t *)fw_malloc(sizeof(pm_node_t));
	if(!this) {
		error("%s: out of memory.\n", fname);
		goto CLEANUP;
	}
	if(!pm_node_init(this)) {
		error("%s: pm_node_init() failed.\n", fname);
		goto CLEANUP;
	}
	pm_node_assign_id(this);
CLEANUP:
	return this;
}

/** Initialize node
 *  Parameters:
 *	this  - The node to perform on.
 *  Returns: TRUE if succeed, FALSE if out of memory.
 */
boolean
pm_node_init(pm_node_t* this)
{
	boolean				rv		= TRUE;
	const static char	fname[]	= "pm_node_init";

	memset(this, 0, sizeof(pm_node_t));
	this->outgoing_max	 = REALLOC_CHUNK_OUTGOING;
	this->outgoing		 = (struct edge *)fw_malloc(this->outgoing_max*sizeof(struct edge));
	if(!this->outgoing) {
		error("%s: out of memory.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	memset(this->outgoing, 0, sizeof(struct edge));
	this->matched_patterns_max	= REALLOC_CHUNK_MATCHSTR;
	this->matched_patterns		= (pm_string_t *)fw_malloc(this->matched_patterns_max * sizeof(pm_string_t));
	if(!this->matched_patterns) {
		error("%s: out of memory.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	memset(this->matched_patterns, 0, this->matched_patterns_max * sizeof(pm_string_t));
CLEANUP:
	if(!this->outgoing) {
		fw_free(this->matched_patterns);
	}
	return rv;
}

/** Release node.
 *  Parameters:
 *	this  - The node to perform on.
 *
 */
void
pm_node_release(pm_node_t* this)
{
	if(this) {
		fw_free(this->matched_patterns);
		fw_free(this->outgoing);
		fw_free(this);
	}
}

/** Find out the next node for a given Alpha to move. this function is used in
 *	the pre-processing stage in which edge array is not sorted. so it uses
 *	linear search.
 *  Parameters:
 *	this  - The node to perform on.
 *	alpha - The alphabetic to find.
 *  Returns: The node to find or NULL if non found.
 *
 */
pm_node_t*
pm_node_find_next(pm_node_t* this, char alpha)
{
	const static char	fname[] = "pm_node_find_next";
	pm_node_t* 			rv	= NULL;
	int 				i;

	if(!this || !alpha) {
		error("%s: this or alpha are null.\n", fname);
		goto CLEANUP;
	}
	for (i = 0; i < this->outgoing_degree; ++i) {
		if(this->outgoing[i].alpha == alpha) {
			rv = (this->outgoing[i].next);
			goto CLEANUP;
		}
	}
 CLEANUP:
	return rv;
}

/** Find out the next node for a given Alpha. this function is used after the
 *   pre-processing stage in which we sort edges. so it uses Binary Search.
 *  Parameters:
 *	this - The node to perform on.
 *	alph - The alphabetic to find.
 *  Returns: The node to find or NULL if non found.
 */
pm_node_t*
pm_node_findbs_next (pm_node_t * this, char alpha)
{
	pm_node_t* 	rv	= NULL;
	int			min;
	int			max;
	int			mid;
	char 		amid;

	min = 0;
	max = this->outgoing_degree - 1;
	while(min <= max) {
		mid = (min + max) >> 1;
		amid = this->outgoing[mid].alpha;
		if(alpha > amid) {
			min = mid + 1;
		} else if(alpha < amid) {
			max = mid - 1;
		} else {
			rv = (this->outgoing[mid].next);
			goto CLEANUP;
		}
	}
CLEANUP:
	return rv;
}

/** Determine if a final node contains a pattern in its accepted pattern list
 *	or not.
 *  Parameters:
 *	this   - The node to perform on.
 *	newstr - The new string to check.
 *  Returns: TRUE if it has, else FALSE
 */
boolean
pm_node_has_matchstr(pm_node_t* this, pm_string_t* newstr)
{
	boolean 		rv = FALSE;
	int 			i;
	int 			j;
	pm_string_t* 	str;

	for(i = 0; i < this->matched_patterns_num; ++i) {
		str = &this->matched_patterns[i];
		if(str->length != newstr->length) {
			continue;
		}

		for(j = 0; j < str->length; ++j) {
			if(str->str[j] != newstr->str[j]) {
				continue;
			}
		}

		if(j == str->length) {
			rv = TRUE;
			goto CLEANUP;
		}
	}
CLEANUP:
	return rv;
}

/** Create the next node for the given alpha.
 *  Parameters:
 *	this  - The node to perform on.
 *	alpha - The alpha to add.
 *  Returns the new node or NULL if already exist.
 */
pm_node_t*
pm_node_create_next(pm_node_t* this, char alpha)
{
	const static char	fname[]	= "pm_node_create_next";
	pm_node_t* 			rv		= NULL;
	pm_node_t* 			next;

	next = pm_node_find_next(this, alpha);
	if(next) {
		goto CLEANUP;
	}
	next = pm_node_create();
	if(!next) {
		error("%s: pm_node_create() failed.\n", fname);
		goto CLEANUP;
	}
	if(!pm_node_register_outgoing(this, next, alpha)) {
		error("%s: pm_node_register_outgoing() failed.\n", fname);
		goto CLEANUP;
	}
	rv = next;
CLEANUP:
	return rv;
}

/** Adds the pattern to the list of accepted pattern.
 *  Parameters:
 *	this  - The node to perform on.
 *	str   - The string to add.
 *  Returns: TRUE if success, FALSE if out of memory.
 */
boolean
pm_node_register_matchstr(pm_node_t* this, pm_string_t* str)
{
	const static char	fname[]	= "pm_node_register_matchstr";
	boolean				rv		= TRUE;
	void*				new_mem = NULL; /* Used for reallocation. */
	short int			pre_patterns_max;
	/* Check if the new pattern already exists in the node list */
	if(pm_node_has_matchstr(this, str)) {
		goto CLEANUP;
	}

	/* Manage memory */
	if(this->matched_patterns_num >= this->matched_patterns_max) {
		pre_patterns_max = this->matched_patterns_max;
		this->matched_patterns_max += REALLOC_CHUNK_MATCHSTR;
		new_mem = fw_malloc(this->matched_patterns_max * sizeof(pm_string_t));
		if(!new_mem) {
			error("%s: out of memory.\n", fname);
			rv = FALSE;
			goto CLEANUP;
		}
		memset(new_mem, 0, this->matched_patterns_max * sizeof(pm_string_t));
		memcpy(new_mem, (void*)this->matched_patterns, pre_patterns_max * sizeof(pm_string_t));
		this->matched_patterns = (pm_string_t *)new_mem;
	}
	this->matched_patterns[this->matched_patterns_num].str = str->str;
	this->matched_patterns[this->matched_patterns_num].length = str->length;
	++(this->matched_patterns_num);
CLEANUP:
	return rv;
}

/** Establish an edge between two nodes
 *  Parameters:
 *	this  - The node to perform on.
 *	next  - The next node.
 *	alpha - The alphabetic to assign.
 *  Returns: TRUE if success, FALSE if out of memory.
 */
boolean
pm_node_register_outgoing(pm_node_t* this, pm_node_t* next, char alpha)
{
	const static char	fname[]	= "pm_node_register_outgoing";
	boolean				rv		= TRUE;
	unsigned short		pre_outgoing_max;
	void* 				new_mem = NULL; /* Used for reallocation. */

	if(this->outgoing_degree >= this->outgoing_max) {
		pre_outgoing_max = this->outgoing_max;
		this->outgoing_max += REALLOC_CHUNK_OUTGOING;
		new_mem = fw_malloc(this->outgoing_max * sizeof(struct edge));
		if(!new_mem) {
			error("%s: out of memory.\n", fname);
			rv = FALSE;
			goto CLEANUP;
		}
		memset(new_mem, 0, this->outgoing_max * sizeof(struct edge));
		memcpy(new_mem, (void*)this->outgoing, pre_outgoing_max * sizeof(struct edge));
		this->outgoing = (struct edge *)new_mem;
	}
	this->outgoing[this->outgoing_degree].alpha  = alpha;
	this->outgoing[this->outgoing_degree++].next = next;
CLEANUP:
	return rv;
}

/** Assign a unique ID to the node (used for debugging purpose).
 *  Parameters:
 *	this - The node to perform on.
 */
void
pm_node_assign_id(pm_node_t* this)
{
	static int unique_id = 1;
	this->id = unique_id++;
}

/** Comparison function for qsort. see man qsort.
 *  Parameters:
 *	first  - The first edge to compare.
 *	second - The second edge to compare.
 *  Returns: 1 if greater or equal, -1 if not.
 */
int
pm_node_edge_compare(const void* first, const void* second)
{
	return((((struct edge *)first)->alpha >= ((struct edge *)second)->alpha)?(1):(-1));
}

/** Sorts edges alphabets.
 *  Parameters:
 *	this - The node to perform on.
 */
void
pm_node_sort_edges(pm_node_t* this)
{
	sort((void *)this->outgoing, this->outgoing_degree, sizeof(struct edge),
			pm_node_edge_compare, 0);
}

/** Initialize automata; allocate memories and set initial values.
 *  Returns: The new allocated automata.
 */
pm_automata_t*
pm_automata_init(void)
{
	const static char	fname[]	= "pm_automata_init";
	pm_automata_t*		this	= (pm_automata_t *)fw_malloc(sizeof(pm_automata_t));

	if(!this) {
		error("%s: out of memory.\n", fname);
		goto CLEANUP;
	}
	memset (this, 0, sizeof(pm_automata_t));
	this->root = pm_node_create();
	this->all_nodes_max = REALLOC_CHUNK_ALLNODES;
	this->all_nodes = (pm_node_t**)fw_malloc(this->all_nodes_max * sizeof(pm_node_t*));
	if(!this->all_nodes) {
		error("%s: out of memory.\n", fname);
		goto CLEANUP;
	}
	pm_automata_register_nodeptr(this, this->root);
	pm_automata_reset(this);
	this->total_patterns = 0;
	this->automata_open  = 1;
CLEANUP:
	if(this && !this->all_nodes) {
		fw_free(this);
	}
	return this;
}

/** Adds pattern to the automata.
 *  Parameters:
 *   this - The automata to work on.
 *   str  - The string to add.
 * Returns: The success of failure status.
 */
pm_status_t
pm_automata_add(pm_automata_t* this, pm_string_t* patt)
{
	const static char	fname[]		= "pm_automata_add";
	pm_status_t			rv			= PM_SUCCESS;
	unsigned int		i;
	pm_node_t*			n 			= this->root;
	pm_node_t*			next;
	char				alpha;

	if(!this->automata_open) {
		rv = PM_AUTOMATA_CLOSED;
		goto CLEANUP;
	}
	if(!patt->length) {
		rv = PM_ZERO_PATTERN;
		goto CLEANUP;
	}
	if(patt->length > PM_MAX_PATTRN_LENGTH) {
		rv = PM_LONG_PATTERN;
		goto CLEANUP;
	}
	for(i = 0; i < patt->length; ++i) {
		alpha = patt->str[i];
		if ((next = pm_node_find_next(n, alpha))) {
			n = next;
			continue;
		} else {
			next = pm_node_create_next(n, alpha);
			if(!next) {
				error("%s: pm_node_create_next() failed.\n", fname);
				rv = PM_OUT_OF_MEMORY;
				goto CLEANUP;
			}
			next->depth = n->depth + 1;
			n = next;

			if(!pm_automata_register_nodeptr(this, n)) {
				error("%s: pm_automata_register_nodeptr() failed.\n", fname);
				rv = PM_OUT_OF_MEMORY;
				goto CLEANUP;
			}
		}
	}
	if(n->final) {
		rv = PM_DUPLICATE_PATTERN;
		goto CLEANUP;
	}
	n->final = 1;
	if(!pm_node_register_matchstr(n, patt)) {
		error("%s: pm_node_register_matchstr() failed.\n", fname);
		rv = PM_OUT_OF_MEMORY;
		goto CLEANUP;
	}
	++(this->total_patterns);
CLEANUP:
	return rv;
}

/** Locate the failure node for all nodes and collect all matched pattern for
 *		every node. it also sorts outgoing edges of node, so binary search could be
 *		performed on them. after calling this function the automate literally will
 *		be finalized and you can not add new patterns to the automate.
 *  Parameters:
 *		this - The automata to work on.
 *	Returns: TRUE if succeed, FALSE if out of memory.
 */
boolean
pm_automata_finalize(pm_automata_t* this)
{
	boolean				rv		= TRUE;
	const static char	fname[]	= "pm_automata_finalize";
	unsigned int		i;
	char				alphas[PM_MAX_PATTRN_LENGTH];
	pm_node_t*			node;

	pm_automata_traverse_setfailure(this, this->root, alphas);
	for(i = 0; i < this->all_nodes_num; ++i) {
		node = this->all_nodes[i];
		if(!pm_automata_union_matchstrs(node)) {
			error("%s: pm_automata_union_matchstrs().\n", fname);
			rv = FALSE;
			goto CLEANUP;
		}
		pm_node_sort_edges(node);
	}
	this->automata_open = 0; /* do not accept patterns any more */
CLEANUP:
	return rv;
}

/** Search in the input text using the given automata. on match event it will
 *   call the call-back function. and the call-back function in turn after doing
 *   its job, will return an integer value to ac_automata_search(). 0 value means
 *   continue search, and non-0 value means stop search and return to the caller.
 * Parameters:
 *	this	 - The automata to work on.
 *	text	 - The text to search for.
 *	keep	 - keep the current automata state.
 *	callback - match callback function.
 *	param	- param to be returned with the callback on match.
 * Returns:
 * -1: failed; automata is not finalized
 *  0: success; input text was searched to the end
 *  1: success; input text was searched partially. (callback broke the loop)
 */
int
pm_automata_search(pm_automata_t* this, pm_string_t* text, int keep,
		pm_match_cb callback, void* param)
{
	const static char	fname[]		= "pm_automata_search";
	int					rv	 		= -1;
	unsigned long		position;
	pm_node_t*			curr;
	pm_node_t*			next;
	pm_match_t			match;

	if(this->automata_open) {
		error("%s: you must call ac_automata_locate_failure() first.\n", fname);
		goto CLEANUP;
	}
	this->text = 0;
	if(!keep) {
		pm_automata_reset(this);
	}
	position = 0;
	curr  = this->current_node;
	while(position < text->length) {
		if(!(next = pm_node_findbs_next(curr, text->str[position]))) {
			if(curr->failure_node) {
				curr = curr->failure_node;
			}
			else {
				++position;
			}
		} else {
			curr = next;
			++position;
		}

		if(curr->final && next) {
			match.position = position + this->base_position;
			match.match_num = curr->matched_patterns_num;
			match.patterns = curr->matched_patterns;
			if(callback(&match, param)) {
				rv = 1;
				goto CLEANUP;
			}
		}
	}
	this->current_node		=  curr;
	this->base_position		+= position;
	rv						=  0;
CLEANUP:
	return rv;
}

/** Set the search string.
 *  Parameters:
 *   this - The automata to work on.
 *   text - The new text.
 *   keep - keep or not the current automata state.
 */
void
pm_automata_settext(pm_automata_t* this, pm_string_t* text, int keep)
{
	this->text = text;
	if(!keep) {
		pm_automata_reset(this);
	}
	this->position = 0;
}

/** Find the next match.
 *  Parameters:
 *   this - The automata to work on.
 *  Returns: The next match or NULL, if none found.
 */
pm_match_t*
pm_automata_findnext(pm_automata_t* this)
{
	pm_match_t*			rv		= NULL;
	unsigned long		position;
	pm_node_t*			curr;
	pm_node_t*			next;
	static pm_match_t 	match;

	if(this->automata_open) {
		goto CLEANUP;
	}
	if(!this->text) {
		goto CLEANUP;
	}
	position		= this->position;
	curr			= this->current_node;
	match.match_num = 0;
	while(position < this->text->length) {
		if(!(next = pm_node_findbs_next(curr, this->text->str[position]))) {
			if(curr->failure_node /* we are not in the root node */) {
				curr = curr->failure_node;
			} else {
				++position;
			}
		}
		else {
			curr = next;
			++position;
		}
		/* We check 'next' to find out if we came here after a alphabet
		 * transition or due to a fail. in second case we should not report
		 * matching because it was reported in previous node */
		if(curr->final && next) {
			match.position	= position + this->base_position;
			match.match_num = curr->matched_patterns_num;
			match.patterns	= curr->matched_patterns;
			break;
		}
	}
	/* Save status variables. */
	this->current_node	= curr;
	this->position		= position;
	if(!match.match_num) {
		this->base_position += position;
	}
	rv = match.match_num? &match: 0;
CLEANUP:
	return rv;
}

/** Reset the automata and make it ready for doing new search on a new text.
 *	when you finished with the input text, you must reset automata state for
 *	new input, otherwise it will not work.
 *  Parameters:
 *   this - The automata to work on.
 */
void
pm_automata_reset(pm_automata_t* this)
{
	this->current_node 	= this->root;
	this->base_position	= 0;
}

/** Release all allocated memories to the automata
 *  Parameters:
 *   this - The automata to work on.
 */
void
pm_automata_release(pm_automata_t* this)
{
	unsigned int	i;
	pm_node_t*		n;

	for(i = 0; i < this->all_nodes_num; ++i) {
		n = this->all_nodes[i];
		pm_node_release(n);
	}
	fw_free(this->all_nodes);
	fw_free(this);
}

/** Prints the automata to output in human readable form.
 *  Parameters:
 *   this	  - The automata to work on.
 */
void
pm_automata_display(pm_automata_t* this)
{
	unsigned int 	i;
	unsigned int 	j;
	pm_node_t*		n;
	struct edge* 	e;
	pm_string_t 	sid;

	print("---------------------------------\n");

	for(i = 0; i < this->all_nodes_num; ++i)
	{
		n = this->all_nodes[i];
		print("NODE(%3d)/----fail----> NODE(%3d)\n",
				n->id, (n->failure_node)?n->failure_node->id:1);
		for(j = 0; j < n->outgoing_degree; ++j)
		{
			e = &n->outgoing[j];
			print("		 |----(");
			if(isgraph(e->alpha)) {
				print("%c)---", e->alpha);
			}
			else {
				print("0x%x)", e->alpha);
			}
			print("--> NODE(%3d)\n", e->next->id);
		}
		if(n->matched_patterns_num) {
			print("Accepted patterns: {");
			for(j = 0; j < n->matched_patterns_num; j++)
			{
				sid = n->matched_patterns[j];
				if(j) {
					print(", ");
				}
				print("%s", sid.str);
			}
			print("}\n");
		}
		print("---------------------------------\n");
	}
}

/** Adds the node pointer to all_nodes.
 *  Parameters:
 *	this   - The automata to work on.
 *	node   - The node to add.
 *  Returns: TRUE if succeed, FALSE if out of memory.
 */
boolean
pm_automata_register_nodeptr(pm_automata_t* this, pm_node_t* node)
{
	const static char	fname[]			= "pm_automata_register_nodeptr";
	boolean				rv				= TRUE;
	unsigned short		pre_node_max;
	void*				new_mem 		= NULL; /* Used for reallocation. */

	if(this->all_nodes_num >= this->all_nodes_max) {
		pre_node_max = this->all_nodes_max;
		this->all_nodes_max += REALLOC_CHUNK_ALLNODES;
		new_mem = fw_malloc(this->all_nodes_max * sizeof(pm_node_t*));
		if(!new_mem) {
			error("%s: out of memory.\n", fname);
			rv = FALSE;
			goto CLEANUP;
		}
		memset(new_mem, 0, this->all_nodes_max * sizeof(pm_node_t*));
		memcpy(new_mem, (void*)this->all_nodes, pre_node_max * sizeof(pm_node_t*));
		this->all_nodes = (pm_node_t **)new_mem;
	}
	this->all_nodes[this->all_nodes_num++] = node;
CLEANUP:
	return rv;
}

/** Collect accepted patterns of the node. the accepted patterns consist of the
 *   node's own accepted pattern plus accepted patterns of its failure node.
 *  Parameters:
 *	node   - The node.
 *  Returns: TRUE if succeed, FALSE if out of memory.
 */
boolean
pm_automata_union_matchstrs(pm_node_t* node)
{
	boolean				rv		= TRUE;
	const static char	fname[]	= "pm_automata_union_matchstrs";
	unsigned int 		i;
	pm_node_t*			m		= node;

	while((m = m->failure_node)) {
		for(i = 0; i < m->matched_patterns_num; ++i) {
			if(!pm_node_register_matchstr(node, &(m->matched_patterns[i]))) {
				error("%s: out of memory.\n", fname);
				rv = FALSE;
				goto CLEANUP;
			}
		}

		if(m->final) {
			node->final = 1;
		}
	}
CLEANUP:
	return rv;
}

/** Find failure node for the given node.
 *  Parameters:
 *   this   - The automata to work on.
 *   node   - The node to traverse.
 *   alphas - The alphabetics.
 */
void
pm_automata_set_failure(pm_automata_t* this, pm_node_t* node, char* alphas)
{
	unsigned int 	i;
	unsigned int 	j;
	pm_node_t*		m;

	for(i = 1; i < node->depth; ++i) {
		m = this->root;
		for(j = i; j < node->depth && m; ++j) {
			m = pm_node_find_next(m, alphas[j]);
		}
		if(m) {
			node->failure_node = m;
			break;
		}
	}
	if(!node->failure_node) {
		node->failure_node = this->root;
	}
}

/** Traverse all automata nodes using DFS (Depth First Search), meanwhile it set
 * the failure node for every node it passes through. this function must be
 * called after adding last pattern to automata. i.e. after calling this you
 * can not add further pattern to automata.
 *  Parameters:
 *   this   - The automata to work on.
 *   node   - The node to traverse.
 *   alphas - The alphabetics.
 */
void
pm_automata_traverse_setfailure(pm_automata_t* this, pm_node_t* node, char* alphas)
{
	unsigned int	i;
	pm_node_t*		next;

	for(i = 0; i < node->outgoing_degree; ++i) {
		alphas[node->depth] = node->outgoing[i].alpha;
		next = node->outgoing[i].next;
		pm_automata_set_failure(this, next, alphas);
		pm_automata_traverse_setfailure(this, next, alphas);
	}
}
