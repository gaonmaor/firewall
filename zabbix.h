/** Zabbix protection.
 */

#ifndef _ZABBIX_H_
#define _ZABBIX_H_

/** Prepare the automata for Zabbix key worlds.
 *	Returns: TRUE if succeed, FALSE for failure.
 */
boolean
zabbix_prepare_automata(void);

/** Release SQL Injection allocated resources.
 *
 */
void
zabbix_release_automata(void);

/** Enforce zabbix protections
 *  Parameters:
 *    decision  - The result decision
 *    conn_node - The connection node.
 *  Notes: The attack to sign (example): 2 and (select 1 from (select count(*),concat((select(select concat(cast(concat(alias,0x7e,passwd,0x7e) as char),0x7e)) from zabbix.users LIMIT 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)
 *  Our smoking gun would be:
 *  	uri is - /zabbix/httpmon.php
 *  	applications attribute contains: 'select' 'from' and 'from information_schema.tables'
 *  	those conditions should be specific enough to catch the attack if a false positive close to none (application should not normally contains all those worlds.)
 *  	to speed-up the search, all the patterns will be checked all together with the pm.
 *  Returns: TRUE for success, FALSE for failure.
 */
boolean
zabbix_protection(decision_t* decision, conn_node_t* conn_node);

#endif /* _ZABBIX_H_*/
