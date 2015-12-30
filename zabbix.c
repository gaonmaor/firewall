#include "fw_common.h"
#include "tcp_conn_handler.h"
#include "connection_table.h"
#include "http_protections.h"
#include "zabbix.h"
#include "pm.h"

/**
 * Contains the suspicious words to identify Zabbix attack.
 */
#define ZABBIX_SUSP_WORDS 4
static const char* zabbix_susp_words[] =
{
		"and",
		"select",
		"from",
		"information_schema."
};

/**
 * The Zabbix internal automata.
 */
static pm_automata_t*	zabbix_pm_atm;

/** Prepare the automata for Zabbix key worlds.
 *	Returns: TRUE if succeed, FALSE for failure.
 */
boolean
zabbix_prepare_automata(void)
{
	const static char 	fname[] 	= "zabbix_prepare_automata";
	boolean				rv 			= TRUE;
	unsigned int 		i;
	pm_string_t			cur_pattern;
	pm_status_t    	 	rc;

	/* Initiate the automata. */
	zabbix_pm_atm = pm_automata_init();
	if(!zabbix_pm_atm) {
		error("%s: pm_automata_init() failed.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	/* Add the patterns. */
	for (i = 0; i < (sizeof(zabbix_susp_words) / sizeof(char*)); ++i) {
		cur_pattern.str		= zabbix_susp_words[i];
		cur_pattern.length	= strlen(cur_pattern.str);
		rc = pm_automata_add(zabbix_pm_atm, &cur_pattern);
		switch(rc) {
			case PM_SUCCESS:
				break;
			case PM_DUPLICATE_PATTERN:
				break;
			case PM_LONG_PATTERN:
				break;
			case PM_ZERO_PATTERN:
				break;
			case PM_AUTOMATA_CLOSED:
				error("%s: pm_automata_add() automata is closed!.\n", fname);
				rv = FALSE;
				goto CLEANUP;
				break;
			case PM_OUT_OF_MEMORY:
				error("%s: pm_automata_add() failed.\n", fname);
				rv = FALSE;
				goto CLEANUP;
				break;
		}
	}
	/* Finalize the automata - now it ready to be search.*/
	pm_automata_finalize(zabbix_pm_atm);
CLEANUP:
	if(!rv) {
		if(zabbix_pm_atm) {
			pm_automata_release(zabbix_pm_atm);
		}
	}
	return rv;
}

/** Release SQL Injection allocated resources.
 *
 */
void
zabbix_release_automata(void)
{
	pm_automata_release(zabbix_pm_atm);
}

/** Search the buffer for SQL Injection pattern.
 *  Parameters:
 *    buff 			- The buffer to scan.
 *    match_array	- The match array.
 *    match_count	- The match count.
 *  Returns: TRUE for success, FALSE for failure.
 */
static boolean
zabbix_search(char* buff, char** match_array, unsigned int* match_count)
{
	boolean				rv		= TRUE;
	const static char 	fname[] = "zabbix_search";
	unsigned int		i;
	unsigned int		j;
	pm_string_t			search_text;
	pm_match_t*			matchp;

	if(!zabbix_pm_atm) {
		error("%s: zabbix_pm_atm is null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}

	debug(DESEC_SQLI, DEBUG_INFO, "%s: called\n", fname);
	search_text.str		= buff;
	search_text.length	= strlen(search_text.str);
	pm_automata_settext(zabbix_pm_atm, &search_text, 0);

	while((matchp = pm_automata_findnext(zabbix_pm_atm))) {
		debug(DESEC_SQLI, DEBUG_INFO, "%s: match at offset %lu: ", fname, matchp->position);
		for (i = 0; i < matchp->match_num; ++i) {
			debug(DESEC_SQLI, DEBUG_INFO, "%s: match[%d] (%s), ",fname,
					i, matchp->patterns[i].str);
			for(j = 0; j < *match_count; ++j) {
				if(!strcmp(matchp->patterns[i].str, match_array[j])) {
					break;
				}
			}
			if(j == *match_count) {
				match_array[(*match_count)++] = (char *)matchp->patterns[i].str;
			}
		}
		++rv;
	}
	debug(DESEC_SQLI, DEBUG_INFO, "%s: match count %u: ", fname, *match_count);
CLEANUP:
	return rv;
}

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
zabbix_protection(decision_t* decision, conn_node_t* conn_node) {
	const static char	fname[]							= "zabbix_protection";
	boolean				rv								= TRUE;
	int					i;
	int					j;
	unsigned int		match_count						= 0;
	char*				match_array[ZABBIX_SUSP_WORDS] 	= {0};
	boolean				mid_spaces;

	debug(DESEC_HTTP, DEBUG_INFO, "%s: called\n", fname);
	/** Check if the uri path is zabbix/httpmon.php
	 */
	if(strcmp(conn_node->req.uri, "/zabbix/httpmon.php")) {
		debug(DESEC_HTTP, DEBUG_INFO, "%s: cmp failed uri %s.\n", fname, conn_node->req.uri);
		goto CLEANUP;
	}
	debug(DESEC_HTTP, DEBUG_INFO, "%s: uri matched\n", fname);
	for(i = 0; i < conn_node->req.query_count; ++i) {
		if(conn_node->req.queries[i].name && !strcmp(conn_node->req.queries[i].name, "applications")) {
			debug(DESEC_HTTP, DEBUG_INFO, "%s: attribute: applications found\n", fname);
			/* Skip initial spaces. */
			for(j = 0; conn_node->req.queries[i].value[j] && j < MAX_HTTP_VALUE_SIZE &&
					   conn_node->req.queries[i].value[j] != ' ' &&
					   conn_node->req.queries[i].value[j] != '\t'; ++j);
			if(!conn_node->req.queries[i].value[j] || j >= MAX_HTTP_VALUE_SIZE) {
				debug(DESEC_HTTP, DEBUG_INFO,
					"%s: attribute value is null.\n", fname);
					goto CLEANUP;
			}
			mid_spaces = FALSE;
			/* Check if application variable contains spaces - in the middle. */
			for(; conn_node->req.queries[i].value[j] && j < MAX_HTTP_VALUE_SIZE; ++j) {
				if(conn_node->req.queries[i].value[j] == ' ' ||
				   conn_node->req.queries[i].value[j] == '\t') {
					mid_spaces = TRUE;
				}
				if(mid_spaces && conn_node->req.queries[i].value[j] != ' ' &&
						   conn_node->req.queries[i].value[j] != '\t') {
					debug(DESEC_HTTP, DEBUG_INFO,
						"%s: zabbix value with spaces to application - dropping.\n", fname);
						decision->action = NF_DROP;
						decision->reason = REASON_ZABBIX;
						conn_node->connection.expires = 0;
						goto CLEANUP;
				}
				if(conn_node->req.queries[i].value[j] >= 'A' &&
						conn_node->req.queries[i].value[j] <= 'Z') {
					conn_node->req.queries[i].value[j] = conn_node->req.queries[i].value[j] - 'A' + 'a';
				}
			}
			if(!zabbix_search(conn_node->req.queries[i].value, match_array, &match_count)) {
				error("%s: zabbix_search() failed.\n", fname);
				rv = FALSE;
				goto CLEANUP;
			}
			if(match_count == ZABBIX_SUSP_WORDS) {
				debug(DESEC_HTTP, DEBUG_INFO, "%s: zabbix attack was found!\n", fname);
				decision->action = NF_DROP;
				decision->reason = REASON_ZABBIX;
				conn_node->connection.expires = 0;
			}
			break;
		}
	}
CLEANUP:
	return rv;
}
