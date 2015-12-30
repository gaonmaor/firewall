#include "fw_common.h"
#include "tcp_conn_handler.h"
#include "connection_table.h"
#define fw_malloc_atomic(size) kmalloc(size, GFP_ATOMIC)

/** Creates new connection key.
 *  Parameters:
 *    src_port - The source port.
 *    dst_port - The destination port.
 *    src_ip   - The source IP.
 *    dst_ip   - The destination IP.
 *  Returns: the new allocated connection key.
 */
conn_key_t*
conn_key_create(__be16 src_port, __be16 dst_port,
	__be32	src_ip,	__be32 dst_ip)
{
	conn_key_t* new_key = 0;
	new_key = (conn_key_t*)fw_malloc_atomic(sizeof(conn_key_t));
	conn_key_fill(new_key, src_port, dst_port, src_ip, dst_ip);
	return new_key;
}

/** Destroy allocated connection key.
 *  Parameters:
 *    conn_key - the key to destroy.
 */
void
conn_key_destroy(conn_key_t* conn_key)
{
	fw_free(conn_key);
}

/** Initiate the connection key.
 *  Parameters:
 *    src_port - The source port.
 *    dst_port - The destination port.
 *    src_ip   - The source IP.
 *    dst_ip   - The destination IP.
 */
void
conn_key_fill(conn_key_t* conn_key,  unsigned short src_port, 
	unsigned short dst_port, __be32	src_ip,	__be32 dst_ip)
{
	if(conn_key) {
		conn_key->src_port = src_port;
		conn_key->dst_port = dst_port;
		conn_key->src_ip   = src_ip;
		conn_key->dst_ip   = dst_ip;
	}
}

/** Copy the content of one key to another.
 *  Parameters:
 *    dst - The destination key.
 *    src - The source key.
 *    Returns: TRUE for success, FALSE for failure.
 */
static boolean
conn_key_copy(conn_key_t* dst, conn_key_t* src)
{
	boolean           rv       = TRUE;
	const static char fname[]  = "conn_key_copy";
	if(!src || !dst) {
		error("%s: ", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	dst->src_port = src->src_port;
	dst->dst_port = src->dst_port;
	dst->src_ip   = src->src_ip;
	dst->dst_ip   = src->dst_ip;
CLEANUP:
	return rv;
}

/** Check if two connection keys are equal.
 *  Parameters:
 *    conn_key1 - The first connection key.
 *    conn_key2 - The second connection key.
 *  Returns: TRUE if equal, FALSE if not.
 */
int
conn_key_equal(const conn_key_t* conn_key1, const conn_key_t* conn_key2)
{
	boolean rv = FALSE;
	/*const static char fname[]  = "conn_key_equal";*/
	boolean chk_dir;
	boolean chk_reverse;

	if(unlikely(!conn_key1 || !conn_key2)) {
		error("conn_key1 or conn_key2 are null.\n");
		goto CLEANUP;
	}
	chk_dir = (conn_key1->src_port == conn_key2->src_port) &&
		  (conn_key1->dst_port == conn_key2->dst_port) &&
		  (conn_key1->src_ip   == conn_key2->src_ip  ) &&
		  (conn_key1->dst_ip   == conn_key2->dst_ip  );
	chk_reverse = (conn_key1->src_port == conn_key2->dst_port) &&
		      (conn_key1->dst_port == conn_key2->src_port) &&
 	 	      (conn_key1->src_ip   == conn_key2->dst_ip  ) &&
		      (conn_key1->dst_ip   == conn_key2->src_ip  );
	rv = chk_dir || chk_reverse;
CLEANUP:
	return  rv;
}

/** Returns the conn key hash code.
 *  Parameters:
 *    conn_key - The connection key to hash.
 */
int
conn_key_hash(const conn_key_t* conn_key)
{
	/*const static char fname[]  = "conn_key_hash";*/
	int               hash = 0;
	if(conn_key) {
		hash = (conn_key->src_port + conn_key->dst_port +
			conn_key->src_ip + conn_key->dst_ip) % 
			MAX_HASH_ELEMENTS;
	}
	return hash;
}

/** Creates a new connection node.
 *  Parameters:
 *    pkt    - The first packet of that connection.
 *    sport  - Source port if any or 0 if not used.
 *    dport  - Destination port if any or 0 if not used.
 *  Returns: the new allocated node or NULL if failed.
 */
conn_node_t*
conn_node_create(struct iphdr* pkt, unsigned short sport,
		unsigned short dport)
{
	conn_node_t*     new_node = 0;
	struct timeval    cur_time;

	new_node = (conn_node_t *)fw_malloc_atomic(sizeof(conn_node_t));
	if(new_node) {
		do_gettimeofday(&cur_time);
		new_node->chain.pkt           = pkt;
		new_node->protocol            = PROTOCOL_UNCHECKED;
		new_node->connection.cli_ip   = pkt->saddr;
		new_node->connection.ser_ip   = pkt->daddr;
		new_node->connection.cli_port = sport;
		new_node->connection.ser_port = dport;
		new_node->connection.expires  = cur_time.tv_sec + 5;
		new_node->connection.state    = TCP_CONN_SYN_SENT;
	}
	return new_node;
}

/** Create a new connection_table.
 *  Returns: The instance of the new connection table or null on failure.
 */
conn_table_t*
connection_table_create(void)
{
	conn_table_t* new_conn;
	const static char fname[]  = "connection_table_create";
	new_conn = (conn_table_t *)fw_malloc_atomic(sizeof(conn_table_t));
	if(new_conn) {
		new_conn->hash = hash_table_create();
		if(!new_conn->hash) {
			fw_free(new_conn);
			new_conn = 0;
		}
		else {
			new_conn->available = CONNECTION_TABLE_ENTRIES;
			debug(DESEC_CONN_TAB, DEBUG_INFO, "%s: Connection created for %lu.\n",
				fname, new_conn->available);
		}
	}
	return new_conn;
}

/** Destroy the connection table.
 *  Parameters:
 *    conn_tab - The conneciton to destroy.
 */
void
connection_table_destroy(conn_table_t* conn_tab)
{
	if(conn_tab->hash) {
		hash_table_destroy_free(conn_tab->hash, conn_node_free);
	}
	fw_free(conn_tab);
}

/** Destroy the connection node content.
 *  Parameters:
 *    key  - The key to free.
 *    node - The node to free.
 */
void
conn_node_free(conn_key_t* key, conn_node_t* node)
{
	const static char fname[]  = "conn_node_free";

	debug(DESEC_CONN_TAB, DEBUG_INFO, "%s: key: %p\n", fname, key);
	if(key) {
		fw_free(key);
	}
	if(node) {
		fw_free(node);
	}
}

/** Clear the connection table.
 *  Parameters:
 *    conn_key - the key to destroy.
 */
void
connection_table_clear(conn_table_t* conn_tab)
{
	if(conn_tab->hash) {
		hash_table_clear_free(conn_tab->hash, conn_node_free);
		conn_tab->available = CONNECTION_TABLE_ENTRIES;
	}
}


/** This function checks if there is a packet connected to that key.
 * Parameters:
 *   conn_tab - The conn_table.
 *   key      - The key for locating the data.
 */
int
connection_table_contains(conn_table_t* conn_tab, const conn_key_t* key)
{

	return (!conn_tab->hash)?0:hash_table_contains(conn_tab->hash, key);
}

/** Get the packet located by the given key.
 * Parameters:
 *   conn_tab - The conn_table.
 *   key      - The key to locate by.
 * Returns: the iphdr struct if found else NULL.
 */
conn_node_t*
connection_table_get(conn_table_t* conn_tab, const conn_key_t* key)
{
	return (!conn_tab->hash)?0:hash_table_get(conn_tab->hash, key);
}

/** Go over the connection table and free all the expired connections.
 *  Parameters:
 *    conn_tab - The connection table to free from.
 *  Returns: The amount of freed connections.
 */
static int
free_expired(conn_table_t* conn_tab)
{
	int                 rv        = 0;
	const static char   fname[]   = "free_expired";
	unsigned int        hash_code = 0;
	struct hash_node_t* cur_hash  = 0;
	struct hash_node_t* next_hash = 0;
	struct timeval      cur_time;

	debug(DESEC_CONN_TAB, DEBUG_INFO, "%s: called.\n", fname);
	if(unlikely(!conn_tab)) {
		error("%s: conn_tab is null.\n", fname);
		goto CLEANUP;
	}
	if(unlikely(!conn_tab->hash)) {
		error("%s: conn_tab->hash is null.\n", fname);
		goto CLEANUP;
	}
	do_gettimeofday(&cur_time);
	for(hash_code = 0; hash_code < MAX_HASH_ELEMENTS; ++hash_code) {
		for(cur_hash = conn_tab->hash[hash_code]; cur_hash; 
			cur_hash = next_hash) {
			if(cur_hash->data) {
				conn_node_t* node = 
					(conn_node_t *)cur_hash->data;
				conn_key_t*  key  = 
					(conn_key_t *)cur_hash->key;
				next_hash = cur_hash->next;
				if(unlikely(!key || !node)) {
					error("%s: key or nude are null.\n", 
						fname);
					rv = 0;
					goto CLEANUP;
				}
				if(node->connection.expires <= 
					cur_time.tv_sec) {
					rv += connection_table_remove(conn_tab,
						node);
					debug(DESEC_CONN_TAB, DEBUG_INFO,
						"%s: node "
						"(%pI4 :%d -> %pI4 :%d) freed."
						"\n", 
						fname, &key->src_ip, 
						ntohs(key->src_port), 
			       			&key->dst_ip, 
						ntohs(key->dst_port));
				}
			}
		}
	}
	debug(DESEC_CONN_TAB, DEBUG_INFO, "%s: %d freed.\n", fname, rv);
	
CLEANUP:
	return rv;
}

/** Add pkt to the connection table.
 * Parameters:
 *   conn_tab   - The connection table.
 *   conn_node  - The connection node.
 *   conn_key   - The connection key
 * Returns: TRUE for success, FALSE for failure - out of memory.
 */
boolean
connection_table_add(conn_table_t* conn_tab, conn_node_t* conn_node, 
	conn_key_t* conn_key)
{
	boolean           rv       = TRUE;
	const static char fname[]  = "connection_table_add";
	conn_key_t*       new_key  = 0;
	if(unlikely(!conn_tab->hash || !conn_node)) {
		error("%s: conn_tab->hash or conn_node are null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	debug(DESEC_CONN_TAB, DEBUG_INFO, "%s: Called available %lu", fname,
		conn_tab->available);
	if(unlikely(!conn_tab->available && !free_expired(conn_tab))) {
		error("%s: No more nodes available.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	new_key = (conn_key_t *)fw_malloc_atomic(sizeof(conn_key_t));
	if(unlikely(!new_key)) {
		error("%s: Not enough memory.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	if(unlikely(!conn_key_copy(new_key, conn_key))) {
		error("%s: conn_key_copy() failed.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	--conn_tab->available;
	rv = hash_table_set(conn_tab->hash, new_key, conn_node);
CLEANUP:
	return rv;
}

/** This function remove the packet located by the given key.
 * Parameters:
 *   conn_tab  - The connection table.
 *   conn_node - The connection node.
 * Returns: 1 if removed else 0.
 */
int
connection_table_remove(conn_table_t* conn_tab, conn_node_t* conn_node)
{
	const static char fname[]  = "connection_table_remove";
	int               rv       = 1;
	conn_key_t        conn_key;
	if(unlikely(conn_tab->available == CONNECTION_TABLE_ENTRIES)) {
		error("%s: Removed more item than was stores.\n", fname);
		rv = 0;
		goto CLEANUP;
	}
	conn_key_fill(&conn_key, conn_node->connection.cli_port,
			conn_node->connection.ser_port, 
			conn_node->connection.cli_ip,
			conn_node->connection.ser_ip);
	rv = (!conn_tab->hash)?0:hash_table_remove_destroy(conn_tab->hash, 
						&conn_key, conn_node_free);
	if(rv) {
		++conn_tab->available;
	}
CLEANUP:
	return rv;
}
