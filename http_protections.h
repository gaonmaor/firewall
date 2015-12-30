/*
 * http_protections.h
 * This module handles and validate HTTP protocol.
 * Made By: Maor Gaon 301308821
 */

#ifndef HTTP_PROTECTIONS_H_
#define HTTP_PROTECTIONS_H_

/** Enforce the relevant HTTP protection for this connection.
 *  Parameters:
 *    sock_buff - The received packet.
 *    rule_base - The currently rule base.
 *    decision  - The result decision
 *    tcp       - The TCP structure.
 *    conn_node - The connection node.
 *  Returns: TRUE for success, FALSE for failure.
 */
boolean
enforce_http_protections(struct sk_buff* sock_buff, rule_base_t* rule_base,
		decision_t* decision, struct tcphdr* tcp, conn_node_t* conn_node);

/** Parse the HTTP protocol.
 *  Parameters:
 *    sock_buff - The received packet.
 *    rule_base - The currently rule base.
 *    decision  - The result decision
 *    tcp       - The TCP structure.
 *    conn_node - The connection node.
 *  Returns: TRUE for success, FALSE for failure.
 */
boolean
parse_http_protocol(struct sk_buff* sock_buff, rule_base_t* rule_base,
		decision_t* decision, struct tcphdr* tcp, conn_node_t* conn_node);

/** Allocate resources for HTTP protections.
 *  Parameters:
 *    sqli_loaded	- Returned value to indicate if sqli was loaded.
 *    zabbix_loaded	- Returned value to indicate if Zabbix was loaded.
 */
void
http_protection_allocate(boolean* sqli_loaded, boolean* zabbix_loaded);

/** Release any allocate resources.
 */
void
http_protection_release(void);

#endif /* HTTP_PROTECTIONS_H_ */
