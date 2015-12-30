/*
 * tcp_chain_handler.c
 * This module handle the creation and operation on tcp chains.
 */

#include "fw_common.h"
#include "tcp_conn_handler.h"
#include "connection_table.h"
#include "http_protections.h"

/** Returns the connection state as string.
 *  Parameters:
 *    state - The state to convert.
 *  Returns: The state string.
 */
const char*
state_to_string(tcp_conn_t state)
{
	const static char* state_str[] = {
			"",
			"syn sent",
			"syn ack",
			"established",
			"closing",
		};
	return state_str[state];
}

/** Validate the next state corresponding to the current state,
 *  Parameters:
 *    conn     - The connection.
 *    pkt      - The new packet.
 *    decision - The reason and action to set.
 *  Returns: TRUE for success, FALSE for failure.
 */
static boolean
validate_conn_state(conn_node_t* conn, struct iphdr* pkt,
		decision_t* decision) {
	const static char fname[] = "validate_conn_state";
	boolean           rv      = TRUE;
	struct tcphdr*    tcp     = 0;
	struct timeval    cur_time;

	if(unlikely(!conn || !pkt || !decision)) {
		error("%s: conn, pkt or decision are null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	do_gettimeofday(&cur_time);
	tcp = get_tcp(pkt);
	if(unlikely(tcp->rst)) {
		debug(DESEC_TCP, DEBUG_INFO, "%s: called: syn = %d ack = %d fin = %d "
			"reset connection.\n", 
			fname, tcp->syn, tcp->ack, tcp->fin);
		conn->connection.state = TCP_CONN_CLOSING;
		conn->connection.expires = 0;
		goto CLEANUP;
	}
	if(conn->connection.state != TCP_CONN_CLOSING && tcp->fin) {
		conn->connection.state = TCP_CONN_CLOSING;
		conn->connection.expires = cur_time.tv_sec + 5;
	}
	/* If the connection expired, but not deleted yet.*/
	if(conn->connection.expires <= cur_time.tv_sec) {
		if(unlikely(tcp->ack || !tcp->syn)) {
			decision->reason = REASON_OUT_OF_STATE;
			decision->action = NF_DROP;
			goto CLEANUP;
		}
		debug(DESEC_TCP, DEBUG_INFO, "%s: expired connection was reused.\n",
			fname);
		conn->connection.state = TCP_CONN_SYN_SENT;
		conn->connection.expires = cur_time.tv_sec + 5;
		goto CLEANUP;
	}
	switch(conn->connection.state) {
		case TCP_CONN_SYN_SENT:
			debug(DESEC_TCP, DEBUG_INFO, "%s: called: syn = %d ack = %d "
			"fin = %d state: syn sent.\n", 
			fname, tcp->syn, tcp->ack, tcp->fin);
			if(unlikely(!(tcp->syn && tcp->ack))) {
				decision->reason = REASON_OUT_OF_STATE;
				decision->action = NF_DROP;
				goto CLEANUP;
			}
			if(unlikely(pkt->saddr != conn->connection.ser_ip)) {
				decision->reason = REASON_OUT_OF_STATE;
				decision->action = NF_DROP;
				goto CLEANUP;
			}
			conn->connection.state = TCP_CONN_SYN_ACK;
			conn->connection.expires = cur_time.tv_sec + 5;
			break;
		case TCP_CONN_SYN_ACK:
			debug(DESEC_TCP, DEBUG_INFO, "%s: called: syn = %d ack = %d "
			"fin = %d state: syn ack.\n", 
			fname, tcp->syn, tcp->ack, tcp->fin);
			if(unlikely(tcp->syn)) {
				decision->reason = REASON_OUT_OF_STATE;
				decision->action = NF_DROP;
				goto CLEANUP;
			}
			conn->connection.state = TCP_CONN_ESTAB;
			conn->connection.expires = cur_time.tv_sec + 3*60;
			break;
		case TCP_CONN_ESTAB:
			debug(DESEC_TCP, DEBUG_INFO, "%s: called: syn = %d ack = %d "
			"fin = %d state: conn established.\n", 
			fname, tcp->syn, tcp->ack, tcp->fin);
			if(unlikely(tcp->syn)) {
				decision->reason = REASON_OUT_OF_STATE;
				decision->action = NF_DROP;
				goto CLEANUP;
			}
			conn->connection.expires = cur_time.tv_sec + 3*60;
			break;
		case TCP_CONN_CLOSING:
			debug(DESEC_TCP, DEBUG_INFO, "%s: called: syn = %d ack = %d "
			"fin = %d state: conn closing.\n", 
			fname, tcp->syn, tcp->ack, tcp->fin);
			if(unlikely(!(tcp->ack) && !(tcp->fin))) {
				decision->reason = REASON_OUT_OF_STATE;
				decision->action = NF_DROP;
				goto CLEANUP;
			}
			break;
	}
CLEANUP:
	return rv;
}

/** Adds the packet to the chain of the given connection.
 * Parameters:
 *   conn      - The chain to add to.
 *   pkt       - The packet to add.
 *   Returns: True for success else false.
 */
static boolean
add_to_tcp_chain(conn_node_t* conn, struct iphdr* pkt)
{
	const static char fname[]          = "add_to_tcp_chain";
	boolean           rv               = TRUE;

	debug(DESEC_TCP, DEBUG_INFO, "%s: called\n", fname);
	if(unlikely(!conn || !pkt)) {
		error("%s: connection or pkt are null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	conn->chain.pkt = pkt;
CLEANUP:
	return rv;
}

/** Get the application layer protocol out of TCP connection
 *  Protocols:
 *    sock_buff - The received packet.
 *    rule_base - The currently rule base.
 *    decision  - The result decision
 *    tcp       - The TCP structure.
 *    conn_node - The connection node.
 *    Returns The protocol or PROTOCOL_UNKNOWN if non found or unhandled.
 */
static app_protocol_t
get_tcp_protocol(struct sk_buff* sock_buff, rule_base_t* rule_base,
		decision_t* decision, struct tcphdr* tcp, conn_node_t* conn_node)
{
	const static char fname[]          = "get_tcp_protocol";
	app_protocol_t    rv               = PROTOCOL_UNCHECKED;

	debug(DESEC_TCP, DEBUG_INFO, "%s: called\n", fname);
	if(parse_http_protocol(sock_buff, rule_base, decision, tcp,
			conn_node)) {
		rv = PROTOCOL_HTTP;
	}
	return rv;
}

/** Enforce the relevant TCP protection for this connection.
 *  Parameters:
 *    sock_buff - The received packet.
 *    rule_base - The currently rule base.
 *    decision  - The result decision
 *    tcp       - The TCP structure.
 *    conn_node - The connection node.
 *  Returns: TRUE for success, FALSE for failure.
 */
static boolean
enforce_tcp_protections(struct sk_buff* sock_buff, rule_base_t* rule_base,
		decision_t* decision, struct tcphdr* tcp, conn_node_t* conn_node)
{
	const static char 	fname[]	= "enforce_tcp_protections";
	boolean  	     	rv		= TRUE;

	if(unlikely(!tcp || !conn_node)) {
		error("%s: tcp or conn_node are null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	debug(DESEC_TCP, DEBUG_INFO, "%s: called protocol: %d\n", fname, conn_node->protocol);
	if(conn_node->protocol == PROTOCOL_UNCHECKED) {
		conn_node->protocol = get_tcp_protocol(sock_buff, rule_base,
				decision, tcp, conn_node);
	}
	/* Check for static protection based on the protocol. */
	switch(conn_node->protocol) {
		case PROTOCOL_HTTP:
			enforce_http_protections(sock_buff, rule_base, decision, tcp, conn_node);
			conn_node->protocol = PROTOCOL_HANDLED;
			break;
		default:
			break;
	}

	CLEANUP:
		return rv;
}

/** Handle TCP connection pakcets.
 *  Parameters:
 *    sock_buff - The received packet.
 *    rule_base - The currently rule base.
 *    decision  - The result decision
 *  Returns: should be always TRUE, FALSE for significant error.
 */
boolean
handle_tcp_conn_chain(struct sk_buff* sock_buff, rule_base_t* rule_base,
		decision_t* decision)
{
	const static char fname[]   = "handle_tcp_conn_chain";
	boolean           rv        = TRUE;
	unsigned int      sport     = 0;
	unsigned int      dport     = 0;
	struct tcphdr*    tcp       = 0;
	struct iphdr*     ip_header = 0;
	conn_table_t*     conn_tab  = 0;
	conn_node_t*      conn_node = 0;
	conn_key_t        conn_key;

	debug(DESEC_TCP, DEBUG_INPUT, "%s: Called.\n", fname);
	if(unlikely(!rule_base)) {
		error("%s: connection_table is null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	ip_header = (struct iphdr*)(sock_buff->data);
	tcp       = get_tcp(sock_buff->data);
	sport     = tcp->source;
	dport     = tcp->dest;
	conn_tab  = (conn_table_t*)rule_base->connection_table;
	if(unlikely(!conn_tab)) {
		error("%s: connection_table is null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	conn_key_fill(&conn_key, sport, dport, ip_header->saddr, 
		ip_header->daddr);
	if(connection_table_contains(conn_tab, &conn_key)) {
		conn_node = connection_table_get(conn_tab, &conn_key);
		debug(DESEC_TCP, DEBUG_INPUT, "%s: conn_node found: %p.\n", fname,
			conn_node);
		if(!conn_node) {
			error("%s: conn_node is null while it shouldn't.\n", 
				fname);
			rv = FALSE;
			goto CLEANUP;
		}
		/* Validate the correction of the new packet before
			 adding to the chain.*/
		if(!validate_conn_state(conn_node, ip_header, decision)) {
			debug(DESEC_TCP, DEBUG_WARNING,	"%s: validate_conn_state() failed.\n", fname);
			rv = FALSE;
			goto CLEANUP;
		}
		if(!add_to_tcp_chain(conn_node, ip_header)) {
			debug(DESEC_TCP, DEBUG_WARNING,
				"%s: failed to add packet to chain.\n", fname);
			goto CLEANUP;
		}
		if(decision->reason == REASON_FW_INACTIVE) {
			decision->reason = conn_node->reason;
		}
	}
	else {
		if(!tcp->syn || tcp->ack) {
			debug(DESEC_TCP, DEBUG_INFO, "%s: not a syn! ack packet.\n",
				fname);
			decision->reason = REASON_OUT_OF_STATE;
			decision->action = NF_DROP;
			goto CLEANUP;
		}
		conn_node = conn_node_create(ip_header, sport, dport);
		if(unlikely(!connection_table_add(rule_base->connection_table, 
			conn_node, &conn_key))) {
			error("%s: failed to set the chain to the connection "
				"table.\n",
				fname);
			rv = FALSE;
			goto CLEANUP;
		}
		conn_node->reason = decision->reason;
		debug(DESEC_TCP, DEBUG_INPUT, "%s: conn_node created and stored: %p.\n",
			fname, conn_node);
	}
	if(!enforce_tcp_protections(sock_buff, rule_base, decision, tcp, conn_node)) {
		error("%s: enforce_tcp_protections() failed.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
CLEANUP:
	return rv;
}

