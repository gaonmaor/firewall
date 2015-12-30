/*
 * tcp_chain_handler.h
 * This module handles and validate tcp streams.
 * Made By: Maor Gaon 301308821
 */

#ifndef TCP_CHAIN_HANDLER_H_
#define TCP_CHAIN_HANDLER_H_

/**
 * Holds the tcp packet chain.
 */
typedef struct
{
	/* For now we only need to store the last packet of each tcp chain,
	    later we could replace pkt with a real list of packets. */
	struct iphdr*    pkt;
} tcp_chain_t;

/**
 * The layer 5: Application protocols, handled by this firewall.
 */
typedef enum
{
	PROTOCOL_UNCHECKED = 0,
	PROTOCOL_HTTP,
	PROTOCOL_UNKNOWN,
	PROTOCOL_HANDLED
} app_protocol_t;

/** Returns the connection state as string.
 *  Parameters:
 *    state - The state to convert.
 *  Returns: The state string.
 */
const char*
state_to_string(tcp_conn_t state);

/** Handle TCP connection pakcets.
 *  Parameters:
 *    sock_buff - The received packet.
 *    rule_base - The currently rule base.
 *    decision  - The result decision.
 *  Returns: should be always TRUE, FALSE for significant error.
 */
boolean
handle_tcp_conn_chain(struct sk_buff* sock_buff, rule_base_t* rule_base,
		decision_t* decision);

#endif /* TCP_CHAIN_HANDLER_H_ */
