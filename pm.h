/**
 * Pattern Matcher implementation.
 */

#ifndef _PM_H_
#define _PM_H_

/**
 * The maximum pattern length.
 */
#define PM_MAX_PATTRN_LENGTH 20

/**
 * The pattern matcher use a non null terminated string.
 */
typedef struct
{
	const char*		str;	/* The string value.			*/
	unsigned int	length; /* The length of the string.	*/
} pm_string_t;

typedef struct
{
	pm_string_t* 	patterns;	/* Array of matched pattern								*/
	long 			position;	/* The end position of matching pattern(s) in the text	*/
	unsigned int 	match_num;	/* Number of matched patterns							*/
} pm_match_t;

/* The return values from pm_search
**/
typedef enum
{
	PM_SUCCESS				= 0, /* No error occurred									*/
	PM_DUPLICATE_PATTERN	= 1, /* Duplicate patterns									*/
	PM_LONG_PATTERN			= 2, /* Pattern length is longer than AC_PATTRN_MAX_LENGTH 	*/
	PM_ZERO_PATTERN			= 3, /* Empty pattern (zero length)							*/
	PM_AUTOMATA_CLOSED		= 4, /* Automata is closed. after calling					*
	 	 	 	 	 	 	 	  *  ac_automata_finalize() you can not add new			*
	 	 	 	 	 	 	 	  *  patterns to the automata.							*/
	PM_OUT_OF_MEMORY	 	= 5  /* Out of memory.										*/
} pm_status_t;

typedef enum
{
	PM_RET_CONTINUE		= 0, /* Continue the search for the next match pattern. 	*/
	PM_RET_STOP			= 1  /* Stop The search and return to caller.		 	  	*/
} pm_cb_ret_t;

/** Callback to be called when a match found.
 *  Parameters:
 *	match - The match opaque.
 *	data  - General used parameter passed to the callback.
 *  Returns:
 */
typedef pm_cb_ret_t (*pm_match_cb)(pm_match_t*, void*);

/* Forward declaration for edge and node mutual know each other. */
struct edge;


typedef struct pm_node
{
	int 				id;						/* to identify the node.									*/
	boolean 			final;					/* Indicate if it's the final node.							*/
	struct pm_node*		failure_node; 			/* The failure node of this node.							*/
	unsigned short 		depth; 					/* Distance between this node and the root.					*/
	pm_string_t*		matched_patterns;	 	/* Array of matched patterns.								*/
	unsigned short		matched_patterns_num; 	/* Number of matched patterns at this node. 				*/
	unsigned short		matched_patterns_max; 	/* Max capacity of allocated memory for matched_patterns. 	*/
	struct edge*		outgoing; 				/* Array of outgoing edges									*/
	unsigned short		outgoing_degree; 		/* Number of outgoing edges 								*/
	unsigned short		outgoing_max; 			/* Max capacity of allocated memory for outgoing 			*/
} pm_node_t;

/* The Edge of the Node */
struct edge
{
	char		alpha;	/* Edge alpha 			*/
	pm_node_t*	next;	/* Target of the edge 	*/
};

typedef struct pm_automata
{
	struct pm_node*		root;			/* The root of the Aho-Corasick tree.				*/
	struct pm_node**	all_nodes;		/* maintain all nodes pointers.						*/
	unsigned int		all_nodes_num;	/* Number of all nodes in the automata. 			*/
	unsigned int		all_nodes_max;	/* Current max allocated memory for *all_nodes.		*/
	boolean 			automata_open;  /* Indicate if the automata is finalized.			*/
	struct pm_node* 	current_node; 	/* Pointer to current node while searching.			*/
	unsigned long 		base_position; 	/* Represents the position of current chunk			*
				  	  	 	 	 	 	 * related to whole input text.						*/
	pm_string_t* 		text;			/* The input text. (for settext/findnext mode)		*/
	unsigned long 		position;		/* Last search position (for settext/findnext mode)	*/
	unsigned long 		total_patterns; /* Total patterns in the automata 					*/
} pm_automata_t;

/** Create the node
 *  Returns: The new allocated node or NULL if out of memory.
 */
pm_node_t*
pm_node_create(void);

/** Create the next node for the given alpha.
 *  Parameters:
 *	this  - The node to perform on.
 *	alpha - The alpha to add.
 *  Returns the new node or NULL if already exist.
 */
pm_node_t*
pm_node_create_next(pm_node_t* this, char alpha);

/** Adds the pattern to the list of accepted pattern.
 *  Parameters:
 *	this  - The node to perform on.
 *	str   - The string to add.
 *  Returns: TRUE if success, FALSE if out of memory.
 */
boolean
pm_node_register_matchstr(pm_node_t* this, pm_string_t* str);

/** Establish an edge between two nodes
 *  Parameters:
 *	this  - The node to perform on.
 *	next  - The next node.
 *	alpha - The alphabetic to assign.
 *  Returns: TRUE if success, FALSE if out of memory.
 */
boolean
pm_node_register_outgoing(pm_node_t* this, pm_node_t* next, char alpha);

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
pm_node_find_next(pm_node_t* this, char alpha);


/** Find out the next node for a given Alpha. this function is used after the
 *   pre-processing stage in which we sort edges. so it uses Binary Search.
 *  Parameters:
 *	this - The node to perform on.
 *	alph - The alphabetic to find.
 *  Returns: The node to find or NULL if non found.
 */
pm_node_t*
pm_node_findbs_next (pm_node_t * this, char alpha);

/** Release node.
 *  Parameters:
 *	this  - The node to perform on.
 *
 */
void
pm_node_release(pm_node_t* this);

/** Assign a unique ID to the node (used for debugging purpose).
 *  Parameters:
 *	this - The node to perform on.
 */
void
pm_node_assign_id(pm_node_t* this);

/** Sorts edges alphabets.
 *  Parameters:
 *	this - The node to perform on.
 */
void
pm_node_sort_edges(pm_node_t* this);

/** Initialize automata; allocate memories and set initial values.
 *  Returns: The new allocated automata.
 */
pm_automata_t*
pm_automata_init(void);

/** Adds pattern to the automata.
 *  Parameters:
 *	this - The automata to work on.
 *	str  - The string to add.
 * Returns: The success of failure status.
 */
pm_status_t
pm_automata_add(pm_automata_t* this, pm_string_t* str);

/** Locate the failure node for all nodes and collect all matched pattern for
 *   every node. it also sorts outgoing edges of node, so binary search could be
 *   performed on them. after calling this function the automate literally will
 *   be finalized and you can not add new patterns to the automate.
 *  Parameters:
 *	this - The automata to work on.
 *  Returns: TRUE if succeed, FALSE if out of memory.
 */
boolean
pm_automata_finalize(pm_automata_t* this);

/** Search in the input text using the given automata. on match event it will
 *   call the call-back function. and the call-back function in turn after doing
 *   its job, will return an integer value to ac_automata_search(). 0 value means
 *   continue search, and non-0 value means stop search and return to the caller.
 * Parameters:
 *	this		- The automata to work on.
 *	text		- The text to search for.
 *	keep		- keep the current automata state.
 *	callback	- match callback function.
 *	param		- param to be returned with the callback on match.
 * Returns:
 * -1: failed; automata is not finalized
 *  0: success; input text was searched to the end
 *  1: success; input text was searched partially. (callback broke the loop)
 */
int
pm_automata_search(pm_automata_t* this, pm_string_t* text, int keep,
		pm_match_cb callback, void* param);

/** Set the search string.
 *  Parameters:
 *	this - The automata to work on.
 *	text - The new text.
 *	keep - keep or not the current automata state.
 */
void
pm_automata_settext(pm_automata_t* this, pm_string_t* text, int keep);

/** Find the next match.
 *  Parameters:
 *	this - The automata to work on.
 *  Returns: The next match or NULL, if none found.
 */
pm_match_t*
pm_automata_findnext(pm_automata_t* this);

/** Release all allocated memories to the automata
 *  Parameters:
 *	this - The automata to work on.
 */
void
pm_automata_release(pm_automata_t* this);

/** Prints the automata to output in human readable form.
 *  Parameters:
 *	this - The automata to work on.
 */
void
pm_automata_display(pm_automata_t* this);

#endif /*_PM_H_*/
