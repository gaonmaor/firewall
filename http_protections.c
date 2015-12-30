/*
 * tcp_chain_handler.c
 * This module implements the http protections.
 */

#include "fw_common.h"
#include "tcp_conn_handler.h"
#include "connection_table.h"
#include "http_protections.h"
#include "sqli.h"
#include "zabbix.h"

/** Check if the HTTP request method is valid.
 *  Parameters:
 *    method_str - The method string to validate.
 *  Returns: TRUE if valid, FALSE if not.
 */
static boolean inline
is_valid_http_method(const char* method_str) {
	return !strcmp(method_str, "GET"     ) ||
		   !strcmp(method_str, "POST"    ) ||
		   !strcmp(method_str, "HEAD"    ) ||
		   !strcmp(method_str, "CONNECT" ) ||
		   !strcmp(method_str, "PUT"     ) ||
		   !strcmp(method_str, "DELETE"  ) ||
		   !strcmp(method_str, "OPTIONS" ) ||
		   !strcmp(method_str, "PROPFIND") ||
		   !strcmp(method_str, "MKCOL"   );
}

/** Decode the URL.
 *  Parameters:
 *    src     - The source string from the HTTP request buffer.
 *    src_len - The length to decode.
 *    dst     - The destination decoded URL.
 *    dst_len - The destination buffer length.
 *    is_form_url_encoded - Indicate if the URL is encoded as form.
 *  Returns: The destination length or -1 if the length overflow.
 */
static int
http_url_decode(const char* src, int src_len, char* dst,
                  int dst_len, int is_form_url_encoded) {
	int i;
	int j;
	int a;
	int b;
	#define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')

	for (i = 0, j = 0; i < src_len && j < dst_len - 1; i++, j++) {
		if (src[i] == '%' && i < src_len - 2 &&
			isxdigit(* (const unsigned char *) (src + i + 1)) &&
			isxdigit(* (const unsigned char *) (src + i + 2))) {
		a = tolower(* (const unsigned char *) (src + i + 1));
		b = tolower(* (const unsigned char *) (src + i + 2));
		dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
		i += 2;
		} else if (is_form_url_encoded && src[i] == '+') {
			dst[j] = ' ';
		} else {
			dst[j] = src[i];
		}
	}
	dst[j] = 0;
	return i >= src_len ? j : -1;
}

/** Protect against directory disclosure attack by removing '..',
 *    excessive '/' and '\' characters
 *  Parameters:
 *    url
 */

static void
remove_double_dots_and_double_slashes(char* url_str) {
	char* p = url_str;

	while (*url_str) {
		*p++ = *url_str++;
		if (url_str[-1] == '/' || url_str[-1] == '\\') {
			/* Skip all slashes, backslashes and double-dots. */
			while (url_str[0]) {
				if (url_str[0] == '/' || url_str[0] == '\\') {
					++url_str;
				}
				else if (url_str[0] == '.' && url_str[1] == '.') {
					url_str += 2;
				}
				else {
					break;
				}
			}
		}
	}
	*p = '\0';
}

/** Progress the buffer to point to the next character after the given
 *    delimeters.
 *  Parameters:
 *    buff       - The buffer to modify.
 *    len		 - The buffer length.
 *    delimiters - The delimiters to skip.
 *  Returns: The beginning of the next word, or NUll if no more words.
 */
static char*
skip_to_next(char** buff, int len, const char* delimiters) {
	char*		p;
	int			i;
	const char*	cur_delim;
	char*		begin_word;
	char*		end_word;
	char*		end_delimiters;

	begin_word = *buff;
	for(end_word = begin_word, cur_delim = delimiters, i = 0;
			*end_word && i < (len - 2);
			++i, ++end_word) {
		for(cur_delim = delimiters; *cur_delim && *cur_delim != *end_word; ++cur_delim);
		if(*cur_delim == *end_word) {
			break;
		}
	}
	if(i == (len - 2) || !(*end_word)) {
		begin_word = 0;
		goto CLEANUP;
	}
	*(end_word++) = 0;
	for(end_delimiters = end_word, cur_delim = delimiters;
			*end_delimiters && i < (len - 2);
			++i, ++end_delimiters) {
		for(cur_delim = delimiters; *cur_delim && *cur_delim != *end_delimiters; ++cur_delim);
		if(!(*cur_delim)) {
			break;
		}
	}
	if(i == (len - 2)) {
		begin_word = 0;
		goto CLEANUP;
	}
	for (p = end_word; p < end_delimiters && i < len; ++p, ++i) {
		*p = '\0';
	}
	*buff = end_delimiters;
CLEANUP:
	return begin_word;
}

/** Parset HTTP headers.
 *  Parameters:
 *    buff - The buffer to modify.
 *    len  - The buffer length.
 *    req  - The http request struct to fill.
 *  Returns: TRUE if parsed, FALSE if not.
 */
static boolean
parse_http_headers(char** buff, int len, struct http_request_t* req) {
	boolean				rv		= TRUE;
	const static char	fname[]	= "parse_http_headers";
	size_t				i;
	char*				name;
	char*				value;

	req->num_headers = 0;
	name  = skip_to_next(buff, len, ": ");
	if(!name) {
		rv = FALSE;
		goto CLEANUP;
	}
	value = skip_to_next(buff, len, "\r\n");
	if(!value) {
		rv = FALSE;
		goto CLEANUP;
	}
	for (i = 0; name && *name && value && *value && i < MAX_HTTP_HEADER_COUNT;) {
		if(*name && *value) {
			req->http_headers[i].name  = name;
			req->http_headers[i].value = value;
			debug(DESEC_HTTP, DEBUG_INFO, "%s: name: %s value: %s \n", fname,
						req->http_headers[i].name, req->http_headers[i].value);
			++i;
			req->num_headers = i;
		}
		name  = skip_to_next(buff, len, ": ");
		if(name) {
			value = skip_to_next(buff, len, "\r\n");
		}
	}
CLEANUP:
	return rv;
}

/** Parse a single attribute from the query string.
 *  Parameters:
 *    attr - The attribute string.
 *    req  - The request structure.
 *    Returns: TRUE for success, FALSE for failure.
 *
 */
static boolean
parse_attrib(char* attr, struct http_request_t* req)
{
	boolean				rv			= TRUE;
	const static char	fname[]		= "parse_attrib";
	char*				name;
	char*				value;
	int				value_len	= 0;
	int					c;
	char				hex_buff[3];

	if(!attr) {
		debug(DESEC_HTTP, DEBUG_INFO, "%s: attr is null\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	name = attr;
	while(*attr && (*attr != '=')) ++attr;
	if(!*attr) {
		debug(DESEC_HTTP, DEBUG_INFO, "%s: *attr\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	*(attr++) = '\0';
	if(req->query_count > MAX_HTTP_HEADER_COUNT) {
		debug(DESEC_HTTP, DEBUG_INFO, "%s: *attr\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	req->queries[req->query_count].name = name;
	value = req->queries[req->query_count].value;
	for(; *attr; ++attr) {
		switch(*attr) {
			case '%':
				hex_buff[0] = *(++attr);
				hex_buff[1] = *(++attr);
				hex_buff[2] = '\0';
				sscanf(hex_buff, "%2x", &c);
				break;
			case '+':
				c = ' ';
				break;
			default:
				c = *attr;
		}
		*(value++) = c;
		++value_len;
	}
	*value = 0;
	if(value_len) {
		debug(DESEC_HTTP, DEBUG_INFO, "%s: name: %s, value: %s, value_len: %d\n", fname,
					req->queries[req->query_count].name,
					req->queries[req->query_count].value,
					value_len);
			++(req->query_count);
	}
CLEANUP:
	return rv;
}

/** Parse HTTP request query sting.
 *  Parameters:
 *    req - The request structure.
 *    Returns: TRUE for success, FALSE for failure.
 */
static boolean
parse_query_string(struct http_request_t* req) {
	boolean           rv          = TRUE;
	const static char fname[]     = "parse_query_string";
	char*             query_string;
	char*             attr;

	debug(DESEC_HTTP, DEBUG_INFO, "%s: called\n", fname);
	query_string = (char*)req->query_string;
	attr         = strsep(&query_string, "&");
	while(rv && attr) {
		rv = parse_attrib(attr, req);
		if(!rv) {
			debug(DESEC_HTTP, DEBUG_INFO, "%s: invalid data was parsed.\n", fname);
		}
		attr = strsep(&query_string, "&");
	}
	return rv;
}

/** A temporary local copy for the buffer manipulations.
 *
 */
static char g_buff[MAX_HTTP_VALUE_SIZE];

/** Parse HTTP request.
 *  Parameters:
 *    buff - The buffer to parse.
 *    len  - The length of the HTTP buffer, the last new-line of the http
 *             header.
 *    req  - The HTTP request to be filled.
 *
 *   Returns: TRUE if parsed, FALSE if not.
 */
static boolean
parse_http_request(char* buff, int len, struct http_request_t* req) {
	const static char	fname[]     = "parse_http_request";
	boolean				rv          = TRUE;
	int					uri_len;
	char*				query_string;
	int					i			= 0;

	/* Work with a local copy of the packet. */
	len = min(len, MAX_HTTP_VALUE_SIZE);
	memset(g_buff, 0, len);
	memcpy(g_buff, buff, len);
	g_buff[len-1] = 0;
	buff = g_buff;

	/* Reset fields. */
	memset(req, 0, sizeof(struct http_request_t));
	/* Ignore initial white-spaces. */
	for (i = 0; i < len && *buff && isspace(* (unsigned char *)buff); ++buff, ++i);
	req->request_method = skip_to_next(&buff, len, " ");
	if(!req->request_method) {
		rv = FALSE;
		goto CLEANUP;
	}
	req->uri            = skip_to_next(&buff, len, " ");
	if(!req->uri) {
		rv = FALSE;
		goto CLEANUP;
	}
	req->http_version   = skip_to_next(&buff, len, "\r\n");
	if(!req->http_version) {
		rv = FALSE;
		goto CLEANUP;
	}
	/* Ensure that we have a request and not a response,
		and that we have HTTP version. */
	if(!is_valid_http_method(req->request_method) ||
		memcmp(req->http_version, "HTTP/", 5)) {
		rv = FALSE;
		goto CLEANUP;
	}
	debug(DESEC_HTTP, DEBUG_INFO, "%s: uri: %s\n", fname, req->uri);
	/*debug(DESEC_HTTP, DEBUG_INFO, "%s: method: %s uri: %s ver: %s \n", fname,
				req->request_method, req->uri, req->http_version);*/
	req->http_version += 5;
	if(!parse_http_headers(&buff, len, req)) {
		rv = FALSE;
		goto CLEANUP;
	}
	query_string = (char *)req->uri;
	req->query_string = 0;
	for(i = 0; *query_string && *query_string != '?' &&  i < len; ++i, ++query_string);
	if(*query_string == '?') {
		req->query_string = query_string;
	}
	if(req->query_string) {
		*(char *) req->query_string++ = 0;
		if(!parse_query_string(req)) {
			debug(DESEC_HTTP, DEBUG_INFO,
					"%s: parse_query_string() invalid data.\n", fname);
		}
	}
	uri_len = (int) strlen(req->uri);
	http_url_decode(req->uri, uri_len, (char *)req->uri, uri_len + 1, 0);
	remove_double_dots_and_double_slashes((char *)req->uri);
	debug(DESEC_HTTP, DEBUG_INFO, "%s: decoded uri: %s\n", fname, req->uri);
CLEANUP:
	return rv;
}

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
		decision_t* decision, struct tcphdr* tcp, conn_node_t* conn_node)
{
	const static char	fname[] = "parse_http_protocol";
	boolean				rv      = FALSE;
	boolean				is_client;
	char*				data;
	int					data_len;

	if(!sock_buff || !rule_base || !decision || !tcp || !conn_node || !conn_node->chain.pkt) {
		error("%s: sock_buff<%p> or rule_base<%p> or decision<%p> or tcp<%p> or conn_node<%p> or"
				" conn_node->chain.pkt<%p> are null.\n", fname,
				sock_buff, rule_base, decision, tcp, conn_node, !conn_node?0:conn_node->chain.pkt);
		goto CLEANUP;
	}

	tcp			= get_tcp(sock_buff->data);
	data		= (char *)((unsigned char *)tcp + (tcp->doff * 4));
	data_len	= (char*)sock_buff->end - (char*)data;
	is_client = conn_node->connection.cli_ip == conn_node->chain.pkt->saddr;
	debug(DESEC_HTTP, DEBUG_INFO, "%s: called data len: %u, port: %d, client: %s \n",
			fname, data_len, ntohs(tcp->dest), boolean_to_string(is_client));
	/* For now the firewall support only HTTP request parsing. */
	if(is_client &&
			(parse_http_request(data , data_len, &conn_node->req))) {
		rv = TRUE;
	}
CLEANUP:
	return rv;
}

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
		decision_t* decision, struct tcphdr* tcp, conn_node_t* conn_node)
{
		const static char	fname[]		= "enforce_http_protections";
		boolean				rv			= TRUE;
		boolean				is_active;

		is_active = conn_node->connection.cli_ip == conn_node->chain.pkt->saddr;
		debug(DESEC_HTTP, DEBUG_INFO, "%s: called sql_mode: %d, zabbix_active: %d"
				" is_active: %s\n",
				fname, rule_base->sqli_prot_data.prot_mode, rule_base->zabbix_active,
				boolean_to_string(is_active));
		if(conn_node->connection.expires && rule_base->sqli_prot_data.prot_mode) {
			if(!sqli_protection(decision, conn_node, &rule_base->sqli_prot_data)) {
				error("%s: sqli_protection() failed.\n", fname);
			}
		}

		if(conn_node->connection.expires && rule_base->zabbix_active) {
			if(is_active &&
				!zabbix_protection(decision, conn_node)) {
				error("%s: zabbix_protection() failed.\n", fname);
			}
		}
		return rv;
}

/** Allocate resources for HTTP protections.
 *  Parameters:
 *    sqli_loaded	- Returned value to indicate if sqli was loaded.
 *    zabbix_loaded	- Returned value to indicate if Zabbix was loaded.
 */
void
http_protection_allocate(boolean* sqli_loaded, boolean* zabbix_loaded)
{
	const static char fname[] = "http_protection_allocate";

	if(!(*sqli_loaded = sqli_prepare_automata())) {
		warning("%s: sqli_prepare_automata() failed - SQLI protection will be disabled.\n", fname);
	}
	if(!(*zabbix_loaded = zabbix_prepare_automata())) {
		warning("%s: zabbix_prepare_automata() failed - zabbix protection will be disabled.\n", fname);
	}
}

/** Release any allocate resources.
 */
void
http_protection_release(void)
{
	zabbix_release_automata();
	sqli_release_automata();
}
