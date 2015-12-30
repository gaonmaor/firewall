/** SQL Injection protection code implementation.
 *
 */

#include "fw_common.h"
#include "tcp_conn_handler.h"
#include "connection_table.h"
#include "http_protections.h"
#include "sqli.h"
#include "pm.h"

/**
 * The suspicious array.
 */
#define SQLI_SUSP_WORDS_COUNT 33
static const char* sqli_susp_words[] =
{
	"--",
	";--",
	";",
	"/*",
	"*/",
	"@@",
	"@",
	"char",
	"nchar",
	"varchar",
	"nvarchar",
	"alter",
	"begin",
	"cast",
	"create",
	"cursor",
	"count",
	"declare",
	"delete",
	"drop",
	"end",
	"exec",
	"execute",
	"fetch",
	"insert",
	"kill",
	"open",
	"select",
	"sys",
	"sysobjects",
	"syscolumns",
	"table",
	"update"
};

/**
 * The SQL Injection internal automata.
 */
static pm_automata_t*	sqli_pm_atm;

/** Prepare the automata for SQL Injection key worlds.
 *	Returns: TRUE if succeed, FALSE for failure.
 */
boolean
sqli_prepare_automata(void)
{
	const static char 	fname[] 	= "sqli_prepare_automata";
	boolean				rv 			= TRUE;
	unsigned int 		i;
	pm_string_t			cur_pattern;
	pm_status_t    	 	rc;

	/* Initiate the automata. */
	sqli_pm_atm = pm_automata_init();
	if(!sqli_pm_atm) {
		error("%s: pm_automata_init() failed.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	/* Add the patterns. */
	for (i = 0; i < (sizeof(sqli_susp_words) / sizeof(char*)); ++i) {
		cur_pattern.str		= sqli_susp_words[i];
		cur_pattern.length	= strlen(cur_pattern.str);
		rc = pm_automata_add(sqli_pm_atm, &cur_pattern);
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
	pm_automata_finalize(sqli_pm_atm);
CLEANUP:
	if(!rv) {
		if(sqli_pm_atm) {
			pm_automata_release(sqli_pm_atm);
		}
	}
	return rv;
}

/** Release SQL Injection allocated resources.
 *
 */
void
sqli_release_automata(void)
{
	pm_automata_release(sqli_pm_atm);
}

/** Search the buffer for SQL Injection pattern.
 *  Parameters:
 *    buff			- The buffer to scan.
 *    match_array	- The match array.
 *    match_count	- The match count.
 *  Returns: TRUE for success, FALSE for failure.
 */
static unsigned int
sqli_search(char* buff, char** match_array, unsigned int* match_count)
{
	boolean				rv		= TRUE;
	const static char 	fname[] = "sqli_search";
	unsigned int		i;
	unsigned int		j;
	pm_string_t			search_text;
	pm_match_t*			matchp;

	if(!sqli_pm_atm) {
		error("%s: sqli_pm_atm is null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}

	debug(DESEC_SQLI, DEBUG_INFO, "%s: called\n", fname);
	search_text.str	= buff;
	search_text.length	= strlen(search_text.str);
	pm_automata_settext(sqli_pm_atm, &search_text, 0);

	while((matchp = pm_automata_findnext(sqli_pm_atm))) {
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

/** Check if the string is suspicious.
 *  Parameters:
 *    str         - The string to protect and modify.
 *    mysql_comma - mysql comma indicator.
 *  Returns: TRUE if unbalanced, FALSE if not.
 *
 */
static boolean
sqli_is_suspicious(char* str) {
	boolean 			rv					= FALSE;
	const static char	fname[] 			= "sqli_is_suspicious";
	int					c_comma_count 		= 0;
	boolean             single_comma	 	= FALSE;
	boolean				mysql_comma			= FALSE;
	int					i;
	int					j;

	debug(DESEC_SQLI, DEBUG_INFO, "%s: called for %s.\n", fname, str);

	for(i = 0, j = 0; str && i < MAX_HTTP_VALUE_SIZE; ++i) {
		if(str[i] == '/' && str[i+1] == '*') {
			++c_comma_count;
		}
		if(str[i] == '*' && str[i+1] == '/') {
			--c_comma_count;
		}
		/* Check for my-sql c-comma*/
		if(str[i] == '/' && str[i+1] == '*' && str[i+2] == '!') {
			mysql_comma = TRUE;
		}
		if(str[i] == '\'') {
			single_comma = TRUE;
		}
		if(!c_comma_count) {
			str[j] = str[i];
			if(str[j] >= 'A' && str[j] <= 'Z') {
				str[j] = str[j] - 'A' + 'a';
			}
			++j;
		}
	}
	str[j] = 0;
	debug(DESEC_SQLI, DEBUG_INFO, "%s: buff: %s. single_comma: %s mysql_comma: %s\n",
			fname, str, boolean_to_string(single_comma), boolean_to_string(mysql_comma));
	rv = single_comma || mysql_comma;
	return rv;
}

/** SQL Injection protection.
 *    decision  - The verdict decision.
 *    conn_node - The connection node.
 *    prot_data - The protection data.
 *  Returns: TRUE for success, FALSE for failure.
 */
boolean
sqli_protection(decision_t* decision, conn_node_t* conn_node,
		sqli_protection_t*	sqli_prot_data)
{
	const static char		fname[] 	= "sqli_protection";
	boolean					rv      	= TRUE;
	boolean                 suspicious	= FALSE;
	unsigned int            match_count	= 0;
	char*					match_array[SQLI_SUSP_WORDS_COUNT] = {0};
	struct http_request_t*	req;
	int						i;

	debug(DESEC_SQLI, DEBUG_INFO, "%s: called prot_mode: %d.\n", fname, sqli_prot_data->prot_mode);
	req = &conn_node->req;
	for(i = 0; i < req->query_count; ++i) {
		if(sqli_is_suspicious(req->queries[i].value)) {
			debug(DESEC_SQLI, DEBUG_INFO, "%s: suspicious string was detected. (%s)\n",
					fname, req->queries[i].value);
			suspicious = TRUE;
		}
	}
	for(i = 0; i < req->query_count; ++i) {
		if(!sqli_search(req->queries[i].value, match_array, &match_count)) {
			error("%s: sqli_search() failed", fname);
			rv = FALSE;
			goto CLEANUP;
		}
	}
	switch(sqli_prot_data->prot_mode) {
		case SQLI_NO_PROT:
				break;
		case SQLI_LOW:
				if((suspicious && match_count > 3) || match_count > 5) {
					debug(DESEC_SQLI, DEBUG_INFO, "%s: SQLI_MEDIUM enforced. suspicious: %s\n",
							fname, suspicious?"TRUE":"FALSE");
					decision->action = NF_DROP;
					decision->reason = REASON_SQLI;
					conn_node->connection.expires = 0;
				}
				break;
		case SQLI_MEDIUM:
			if((suspicious && match_count > 1) || match_count > 4) {
				debug(DESEC_SQLI, DEBUG_INFO, "%s: SQLI_MEDIUM enforced. suspicious: %s\n",
						fname, suspicious?"TRUE":"FALSE");
				decision->action = NF_DROP;
				decision->reason = REASON_SQLI;
				conn_node->connection.expires = 0;
			}
			break;
		case SQLI_HIGH:
			if((suspicious && match_count > 0) || match_count > 2) {
				debug(DESEC_SQLI, DEBUG_INFO, "%s: SQLI_HIGH enforced. suspicious: %s\n",
										fname, suspicious?"TRUE":"FALSE");
				decision->action = NF_DROP;
				decision->reason = REASON_SQLI;
				conn_node->connection.expires = 0;
			}
			break;
	}
CLEANUP:
	return rv;
}
