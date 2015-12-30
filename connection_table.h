/**
 * connection_table.h
 * Handles tcp connections.
 * Made by:        Maor Gaon 301308821
 * Created:        20/4/2014
 */

#ifndef _connection_table
#define _connection_table

/* The size of history buffer. */
#define HISTORY_PACKET_BUFF 4096

/** Connection unique key.
 */
typedef struct {
	__be16	src_port;
	__be16	dst_port;
	__be32	src_ip;
	__be32	dst_ip;
} conn_key_t;

/** Connection node.
 */
typedef struct {
	/* Holds the connection data. */
	connection_t connection;
	/* Contains the tcp packet chain. */
	tcp_chain_t chain;
	/* The reason given for the first packet.*/
	reason_t reason;
	/* The TCP connection protocol */
	app_protocol_t protocol;
	/* Contains the last packets from the previous packets. */
	char           history_buff[HISTORY_PACKET_BUFF];
	/* Contains the HTTP request data. */
	struct http_request_t req;
} conn_node_t;

#define hash_malloc   fw_malloc_atomic
#define hash_free     fw_free
#define hash_key_t    conn_key_t*
#define hash_data_t   conn_node_t*
#define get_hash_code conn_key_hash
#define hash_cmp      conn_key_equal
#include "hash_table.h"

/** Contains all the connections.
 */
typedef struct {
	/* The inner hash*/
	hash_table_t hash;
	/* The amount of available connections starts as
		 CONNECTION_TABLE_ENTRIES*/
	unsigned long available;
} conn_table_t;

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
	__be32	src_ip,	__be32 dst_ip);

/** Destroy allocated connection key.
 *  Parameters:
 *    conn_key - the key to destroy.
 */
void
conn_key_destroy(conn_key_t* conn_key);

/** Initiate the connection key.
 *  Parameters:
 *    src_port - The source port.
 *    dst_port - The destination port.
 *    src_ip   - The source IP.
 *    dst_ip   - The destination IP.
 */
void
conn_key_fill(conn_key_t* conn_key,  unsigned short src_port, 
	unsigned short dst_port, __be32	src_ip,	__be32 dst_ip);

/** Check if two connection keys are equal.
 *  Parameters:
 *    conn_key1 - The first connection key.
 *    conn_key2 - The second connection key.
 */
int
conn_key_equal(const conn_key_t* conn_key1, const conn_key_t* conn_key2);

/** Returns the conn key hash code.
 *  Parameters:
 *    conn_key - The connection key to hash.
 */
int
conn_key_hash(const conn_key_t* conn_key);



/** Creates a new connection node.
 *  Parameters:
 *    pkt    - The first packet of that connection.
 *    sport  - source port if any or 0 if not used.
 *    dport  - destination port if any or 0 if not used.
 *  Returns: the new allocated node or NULL if failed.
 */
conn_node_t*
conn_node_create(struct iphdr* pkt, unsigned short sport,
		unsigned short dport);

/** Destroy the connection node content.
 *  Parameters:
 *    key  - The key to free.
 *    node - The node to free.
 */
void
conn_node_free(conn_key_t* key, conn_node_t* node);

/** Create a new connection_table.
 *  Returns: The instance of the new connection table or null on failure.
 */
conn_table_t*
connection_table_create(void);

/** destroy the connection table.
 * Parameters:
 *   conn_tab - The conneciton to destroy.
 */
void
connection_table_destroy(conn_table_t* conn_tab);

/** Clear the connection table.
 *  Parameters:
 *    conn_key - the key to destroy.
 */
void
connection_table_clear(conn_table_t* conn_tab);

/** This function checks if there is a packet connected to that key.
 * Parameters:
 *   conn_tab - The conn_table.
 *   key      - The key for locating the data.
 */
int
connection_table_contains(conn_table_t* conn_tab, const conn_key_t* key);

/** Get the packet located by the given key.
 * Parameters:
 *   conn_tab - The conn_table.
 *   key      - The key to locate by.
 * Returns: the iphdr struct if found else NULL.
 */
conn_node_t*
connection_table_get(conn_table_t* conn_tab, const conn_key_t* key);

/** Add pkt to the connection table.
 * Parameters:
 *   conn_tab   - The connection table.
 *   conn_node  - The connection node.
 *   conn_key   - The connection key
 * Returns: TRUE for success, FALSE for failure - out of memory.
 */
boolean
connection_table_add(conn_table_t* conn_tab, conn_node_t* conn_node, 
	conn_key_t* conn_key);

/** This function remove the packet located by the given key.
 * Parameters:
 *   conn_tab  - The connection table.
 *   conn_node - The connection node.
 * Returns: 1 if removed else 0.
 */
int
connection_table_remove(conn_table_t* conn_tab, conn_node_t* conn_node);

#endif /* _connection_table*/
