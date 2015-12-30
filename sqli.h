/** SQL Injection protection.
 */

#ifndef _SQLI_H_
#define _SQLI_H_

/** Prepare the automata for SQL Injection key worlds.
 *	Returns: TRUE if succeed, FALSE for failure.
 */
boolean
sqli_prepare_automata(void);

/** Release SQL Injection allocated resources.
 *
 */
void
sqli_release_automata(void);

/** SQL Injection protection.
 *    decision  - The verdict decision.
 *    conn_node - The connection node.
 *    prot_data - The protection data.
 *  Returns: TRUE for success, FALSE for failure.
 */
boolean
sqli_protection(decision_t* decision, conn_node_t* conn_node,
	sqli_protection_t* sqli_prot_data);

#endif /* _SQLI_H_*/
