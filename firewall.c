/*
 * firewall.c
 * This is the main module for the firewall.
 */

#include "fw_common.h"
#include "tcp_conn_handler.h"
#include "connection_table.h"
#include "http_protections.h"

#define DRIVER_AUTHOR "Maor Gaon <gaonmaor@gmail.com>"
#define DRIVER_DESC   "firewall workshop TAU part 5"
#define MINOR_COUNT 4
#define CLASS_DEVICE_NAME(class, device) class "_" device
const unsigned long MAX_HASH_ELEMENTS = CONNECTION_TABLE_ENTRIES;

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_VERSION("1.0.0");
MODULE_SUPPORTED_DEVICE("fw5");

/** The current rule base. */
static rule_base_t* g_rule_base             = 0;
/** Rules config flag.  */
static unsigned int g_rules_config          = 0;
/** The rule file mapped area. */
static rule_t*       g_rule_file            = 0;
/* We don't work directly with the mmaped rule file,
	 only when the rule base is loaded the new rule file becomes
	 the active rules array.*/
rule_t*              g_rule_file_copy       = 0;
/** The log file mapped area. */
static log_row_t*    g_log_file             = 0;
/** The connection table file mapped area. */
static connection_t* g_conn_tab_file        = 0;
/** The rule file mapped area size. */
static unsigned long g_rule_file_size       = 0;
/** The mmaped file dentry. */
struct dentry*       g_rule_file_dentry     = 0;
/** The size in bytes of the currently used rules table. */
static unsigned long g_rules_size           =
		RULE_BASE_ENTRIES * (sizeof(rule_t));
/** The size in bytes of the log. */
static unsigned long g_log_size             = sizeof(log_row_t);
/** The size in bytes of the connection table. */
static unsigned long g_conn_tab_size        = sizeof(connection_t);
/** The class for the devices /sys/class/fw5. */
static struct class*  fwmod_class           = 0;
/** The device struct for /dev/fw5_log. */
static struct device* fwmod_device_log      = 0;
/** The rules device struct - for /dev/fw5_rules. */
static struct device* fwmod_device_rules    = 0;
/** The rules device struct - for /dev/fw5_rules. */
static struct device* fwmod_device_conn_tab = 0;
/** The allocated Major & Minor numbers.  */
static dev_t          fwmod_dev;
/** The character device struct. */
static struct cdev    fwmod_cdev;
/* fwmof hook function options. */
static struct nf_hook_ops fwmod_nfho;
/* fwmof hook function options. (local) */
static struct nf_hook_ops fwmod_nfho_lo;
/* Check if SQL Injection protection managed to load successfully. */
static boolean sqli_loaded		= FALSE;
/* Check if Zabbix protection managed to load successfully. */
static boolean zabbix_loaded	= FALSE;

/** Get the current rule base hash code.
 *  Parameters:
 *    rules - The rules list to hash.
 *  Returns: The hash code value.
 */
static inline unsigned long
hash_rule_base(rule_t* rules) {
	const static char fname[] = "hash_rule_base";
	unsigned long     rv      = 0;
	int               i       = 0;

	debug(DESEC_FW, DEBUG_INFO, "%s: called\n", fname);

	if(unlikely(!rules)) {
		error("%s: g_rule_base is null.\n", fname);
		goto CLEANUP;
	}
	for(i = 0; i <  RULE_BASE_ENTRIES && rules[i].protocol != PROT_RES; 
		++i) {
		rv +=	rules[i].src_ip   + rules[i].src_mask + 
			rules[i].dst_ip   + rules[i].dst_mask + 
			rules[i].src_port + rules[i].dst_port + 
			rules[i].protocol + rules[i].action;
	}
	debug(DESEC_FW, DEBUG_INFO, "%s: hash: %lu\n", fname, rv);
CLEANUP:
	return rv;
}

/** Reason to string.
 *  Parameters:
 *  	reason - The reason number.
 *  Returns: the string represantation.
 *
 */
const char*
reason_to_string(int reason) {
	switch(reason) {
		case REASON_FW_INACTIVE:
			return " inactive";
			break;
		case REASON_NOT_IPV4:
			return " ipv4";
			break;
		case REASON_PROT_NOT_ENFORCED:
			return " prot not enforced";
			break;
		case REASON_NO_MATCHING_RULE:
			return " no matching rule";
			break;
		case REASON_OUT_OF_STATE:
			return " out of state";
			break;
		case REASON_CONNECTION_TABLE_FULL:
			return " table full";
			break;
		case REASON_XMAS_PACKET:
			return " xmas packet";
			break;
		case REASON_SQLI:
			return " sqli";
			break;
		case REASON_ZABBIX:
			return " zabbix";
			break;
		default:
			return "";
	}
}

/** Print log message for the packet verdict.
 *  Parameters:
 *    pkt      - The packet to log.
 *    decision - The verdict reason and action.
 *    sport    - The source port.
 *    dport    - The destination port.
 *    hooknum - The hook priority number.
 *  Returns: TRUE for success FALSE for failure.
 */
static inline boolean
log_verdict_and_reason(struct iphdr* pkt, decision_t* decision,
		unsigned short sport, unsigned short dport,
		unsigned int hooknum)
{
	const static char fname[]   = "log_verdict_and_reason";
	boolean				rv        = TRUE;
	int					i         = 0;
	int					count     = 1;
	struct timeval		cur_time;

	count = g_log_size / sizeof(log_row_t);

	do_gettimeofday(&cur_time);
	if(unlikely(!pkt || !decision)) {
		error("%s: decision or pkt are null.\n",
			fname);
		rv = FALSE;
		goto CLEANUP;
	}

	if(pkt->saddr == localaddr || pkt->daddr == localaddr) {
		/*debug(DESEC_FW, DEBUG_INFO, "%s: local address skiped.\n", fname);*/
		goto CLEANUP;
	}

	debug(DESEC_FW, DEBUG_INFO, "%s: called log count: %u, <%pI4: %d -> %pI4: %d>"
				" action: %s, reason: %d%s\n",
				fname, count,
				&pkt->saddr, ntohs(sport),
				&pkt->daddr, ntohs(dport),
				decision->action?"allow":"drop",
				decision->reason, reason_to_string(decision->reason));

	for(i = 0; g_log_file[i].protocol && i < count; ++i) {
		if(g_log_file[i].src_ip   == ntohl(pkt->saddr) &&
		   g_log_file[i].src_port == ntohs(sport)      &&
		   g_log_file[i].dst_ip   == ntohl(pkt->daddr) &&
		   g_log_file[i].dst_port == ntohs(dport)      &&
		   g_log_file[i].protocol == pkt->protocol     &&
		   g_log_file[i].hooknum  == hooknum           &&
		   g_log_file[i].action   == decision->action  &&
		   g_log_file[i].reason   == decision->reason
		   ) {
			g_log_file[i].modified = cur_time.tv_sec;
			g_log_file[i].count = 
				((g_log_file[i].count + 1) > UINT_MAX)?
				UINT_MAX:(g_log_file[i].count + 1);
			break;
		}
	}
	if(!g_log_file[i].protocol
		&& (count < LOG_ENTRIES - 1)) {
		g_log_file[i].modified   = cur_time.tv_sec;
		g_log_file[i].protocol   = pkt->protocol;
		g_log_file[i].action     = decision->action;
		g_log_file[i].hooknum    = hooknum;
		g_log_file[i].src_ip     = ntohl(pkt->saddr);
		g_log_file[i].dst_ip     = ntohl(pkt->daddr);
		g_log_file[i].src_port   = ntohs(sport);
		g_log_file[i].dst_port   = ntohs(dport);
		g_log_file[i].reason     = decision->reason;
		g_log_file[i].count      = 1;
		g_log_file[i+1].modified = 0;
		g_log_file[i+1].protocol = 0;
		g_log_file[i+1].action   = 0;
		g_log_file[i+1].hooknum  = 0;
		g_log_file[i+1].src_ip   = 0;
		g_log_file[i+1].dst_ip   = 0;
		g_log_file[i+1].src_port = 0;
		g_log_file[i+1].dst_port = 0;
		g_log_file[i+1].reason   = 0;
		g_log_file[i+1].count    = 0;
		count = (i+2 > count)?i+2:count;
		g_log_size = count * sizeof(log_row_t);
		debug(DESEC_FW, DEBUG_INFO,
			"%s: modified: %lu protocol: %d action: %s hooknum: %d "
			"saddr: %pI4 daddr: %pI4 sport: %d dport: %d "
			"reason: %d%s count: %d\n", fname,
			g_log_file[i].modified,
			g_log_file[i].protocol,
			g_log_file[i].action?"allow":"drop",
			g_log_file[i].hooknum,
			&pkt->daddr,
			&pkt->saddr,
			g_log_file[i].src_port,
			g_log_file[i].dst_port,
			g_log_file[i].reason, reason_to_string(g_log_file[i].reason),
			g_log_file[i].count);
	}
CLEANUP:
	return rv;
}

/** Prepare the new rule base.
 *  Parameters:
 *    new_rule_base - The new rule base to prepare.
 *  Returns: True if prepare stage succeeded else FALSE.
 */
static boolean
prepare_rule_base(rule_base_t* new_rule_base)
{
	const static char fname[] = "prepare_rule_base";
	boolean           rv      = TRUE;

	debug(DESEC_POLICY, DEBUG_INFO, "%s: called\n", fname);
	if(unlikely(!new_rule_base)) {
		error("%s: new_rule_base is null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	memcpy(g_rule_file_copy, g_rule_file, g_rule_file_size);
	new_rule_base->rule_list        = g_rule_file_copy;
	new_rule_base->rule_hash        = 
		hash_rule_base(new_rule_base->rule_list);
	new_rule_base->connection_table = connection_table_create();
	if(unlikely(!new_rule_base->connection_table)){
		error("%s: failed to create the connection table.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	if(sqli_loaded && ((g_rules_config & FW_CONFIG_SQL_PROTECT1) ||
			(g_rules_config & FW_CONFIG_SQL_PROTECT2))) {
		new_rule_base->sqli_prot_data.prot_mode =  ((g_rules_config & FW_CONFIG_SQL_PROTECT1) != 0) +
				(((g_rules_config & FW_CONFIG_SQL_PROTECT2) != 0) * 2);
	}
	if(zabbix_loaded && (g_rules_config & FW_CONFIG_ZABBIX)) {
		new_rule_base->zabbix_active = TRUE;
	} else {
		new_rule_base->zabbix_active = FALSE;
	}

CLEANUP:
	if(unlikely(!rv && new_rule_base && new_rule_base->connection_table)) {
		connection_table_destroy(new_rule_base->connection_table);
		new_rule_base->connection_table = 0;
		debug(DESEC_POLICY, DEBUG_INFO, "%s: connection table destroyed on error.\n",
			fname);
	}
	return rv;
}

/** Commit the new rule base.
 *  Parameters:
 *    new_rule_base - The new rule base ready to be swept.
 */
static void
commit_rule_base(rule_base_t** new_rule_base)
{
	const static char fname[] = "commit_rule_base";
	rule_base_t*      trb;
	unsigned int      reset;
	debug(DESEC_POLICY, DEBUG_INFO, "%s: called\n", fname);
	if(!new_rule_base || !*new_rule_base) {
		error("%s: new_rule_base is null.\n", fname);
	}
	else {
		/* Stop the firewall just for the swapping process. */
		reset            = g_rules_config;
		g_rules_config   = g_rules_config & (~FW_CONFIG_ACTIVE);
		trb              = g_rule_base;
		g_rule_base      = *new_rule_base;
		*new_rule_base   = trb;
		g_rules_config   = reset;
	}
}

/** Prepare the new rule base.
 *  Parameters:
 *    rule_base - The rule_base struct to clear.
 *  Returns: TRUE for success else FALSE.
 */
static boolean
clean_rule_base(rule_base_t* rule_base)
{
	const static char fname[] = "clean_rule_base";
	boolean           rv      = TRUE;

	debug(DESEC_POLICY, DEBUG_INFO, "%s: called\n", fname);
	if(unlikely(!rule_base)) {
		goto CLEANUP;
	}
	if(rule_base->connection_table) {
		debug(DESEC_POLICY, DEBUG_INFO, "%s: freeing connection table.\n", fname);
		connection_table_destroy(rule_base->connection_table);
		rule_base->connection_table = 0;
	}
CLEANUP:
	return rv;
}

/** Get the mmap area.
 *  Parameters:
 *    rule_file - The rule file buffer area.
 *  Returns: TRUE for success, FALSE for failure
 */
static boolean
get_rule_base_mmap(rule_t** rule_file)
{
	const static char fname[] = "get_rule_base_mmap";
	boolean           rv      = TRUE;

	debug(DESEC_POLICY, DEBUG_INFO, "%s: called\n", fname);
	if(unlikely(!rule_file || !g_rule_file)) {
		error("%s: rule_file ptr or g_rule_file are null.\n", fname);
		rv = FALSE;
	}
	*rule_file = g_rule_file;
	return rv;
}

/** Load the setting from the user space.
 *  Parameters:
 *    read_rule_file - Indicate if we need to read the rules from the
 *      mmaped rule file.
 *  Returns: TRUE for success, FALSE for failure.
 */
static boolean
load_rule_base(boolean read_rule_file)
{
	const static char fname[]        = "load_rule_base";
	boolean           rv             = TRUE;
	rule_base_t*      rule_base      = 0;
	rule_t*           rule_file      = 0;
	int               i;

	debug(DESEC_POLICY, DEBUG_INFO, "%s: called\n", fname);
	debug(DESEC_POLICY, DEBUG_INFO, "%s: fw_malloc rule_base.\n", fname);
	rule_base = (rule_base_t*) fw_malloc(sizeof(rule_base_t));
	if (unlikely(!rule_base)) {
		error("%s: out of memory.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	if(read_rule_file) {
		if(!get_rule_base_mmap(&rule_file)) {
			print("Running with no rulebase - "
			      "all packet will be passed.\n");
			rule_file = 0;
		}
	}
	if(read_rule_file && rule_file) {
		for(i = 0; i < RULE_BASE_ENTRIES &&
			rule_file[i].protocol != 255; ++i) {
			debug(DESEC_POLICY, DEBUG_INFO, "%s: reading mmap entry: %d "
				"protocol: %d src_mask: %d dst_mask: %d "
				"action: %d src_port: %d dst_port: %d "
				"src_ip: %pI4 dst_ip: %pI4\n",
				fname, i,
				rule_file[i].protocol,
				rule_file[i].src_mask, rule_file[i].dst_mask,
				rule_file[i].action,
				ntohs(rule_file[i].src_port), 
				ntohs(rule_file[i].dst_port),
				&rule_file[i].src_ip,   &rule_file[i].dst_ip);
		}
	}
	if(!prepare_rule_base(rule_base)) {
		error("%s: prepare_rule_base() failed.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	commit_rule_base(&rule_base);
CLEANUP:
	if(unlikely(rule_base && !clean_rule_base(rule_base))) {
		error("%s: clean_rule_base() failed.\n", fname);
	}
	return rv;
}

/** Enforce packet via the rule base.
 *  Parameters:
 *    pkt         - The packet to enforce.
 *    sport       - The source port or zero if not used.
 *    dport       - The destination port or zero if not used.
 *    decision    - The returned reason and action.
 *  Returns: TRUE for success else for failure.
 */
static boolean
enforce_rule_base(struct iphdr* pkt, unsigned int sport,
		unsigned int dport, decision_t* decision) {
	#define MASK(offset) (!(offset)?0:(0xFFFFFFFF >> (32 - offset)))
	const static char fname[] = "enforce_rule_base";
	boolean           rv      = TRUE;
	rule_t*           rules;
	unsigned int      cli_ip;
	unsigned int      ser_ip;
	int               i       = 0;

	debug(DESEC_FW, DEBUG_INFO, "%s: called\n", fname);
	if(unlikely(!pkt || !decision || !g_rule_base || 
		!g_rule_base->rule_list)) {
		error("%s: pkt, decision or g_rule_base or "
			  "!g_rule_base->rule_list"
			  " are null.\n", fname);
		rv      = FALSE;
		goto CLEANUP;
	}
	cli_ip = pkt->saddr;
	ser_ip = pkt->daddr;
	rules = g_rule_base->rule_list;
	for(i = 0; i <  RULE_BASE_ENTRIES && 
		rules[i].protocol != PROT_RES; ++i) {
		if((rules[i].src_ip & MASK(rules[i].src_mask)) ==
				(cli_ip & MASK(rules[i].src_mask)) &&
		   (rules[i].dst_ip & MASK(rules[i].dst_mask)) ==
				   (ser_ip & MASK(rules[i].dst_mask)) &&
		   ((!rules[i].src_port) || rules[i].src_port == sport) &&
		   ((!rules[i].dst_port) || rules[i].dst_port == dport) &&
		   ((!rules[i].protocol) || 
			rules[i].protocol == pkt->protocol)) {
			if(rules[i].action == NF_DROP) {
				decision->action = NF_DROP;
			}
			decision->reason = i;
			if(i <= RULE_BASE_ENTRIES) {
				debug(DESEC_FW, DEBUG_INFO,
					"%s: Rule %d matched action: %d\n", 
					fname, i, decision->action);
			}
			break;
		}
	}
	if(i == RULE_BASE_ENTRIES || rules[i].protocol == PROT_RES) {
		decision->reason = REASON_NO_MATCHING_RULE;
		if(!(g_rules_config & FW_CONFIG_CLEANUP_ACCEPT)) {
			decision->action = NF_DROP;
		}
	}
CLEANUP:
	return rv;
}

static boolean inline
is_prot_enforced(__u8 protocol)
{
	return  (protocol != PROT_ICMP && protocol != PROT_TCP &&
			 protocol != PROT_UDP) ||
		   ((protocol == PROT_ICMP) && (g_rules_config & FW_CONFIG_ICMP)) ||
	       ((protocol == PROT_UDP) && (g_rules_config & FW_CONFIG_UDP))   ||
	       ((protocol == PROT_TCP) && (g_rules_config & FW_CONFIG_TCP));
}

/** fwmod hook function.
 *  Parameters:
 *    hooknum   - The hook priority number.
 *    sock_buff - Contains the packet content.
 *    in        - The network device interface received from.
 *    out       - The network device interface send from.
 *    okfn      - Function for handling ok packet.
 *  Returns: NF_ACCEPT to pass the packet, NF_DROP to drop the packet.
 */
static unsigned int
firewall_rx(unsigned int hooknum, struct sk_buff* sock_buff,
		const struct net_device* in, const struct net_device* out,
        int (*okfn)(struct sk_buff *))
{
	const static char  fname[]   = "firewall_rx";
	struct iphdr*      ip_header = 0;
	struct icmphdr*    icmp      = 0;
	struct udphdr*     udp       = 0;
	struct tcphdr*     tcp       = 0;
	unsigned int       sport     = 0;
	unsigned int       dport     = 0;
	ktime_t            tstamp;
	decision_t         decision  = {NF_ACCEPT, REASON_FW_INACTIVE};
	int                rv        = NF_ACCEPT;

	/* Add support for new hookfn version on which instead of hooknum, 
		the hook_ops struct is passed. */
	if(((void *)hooknum) == &fwmod_nfho) {
		hooknum = fwmod_nfho.hooknum;
	}
	else if(((void *)hooknum) == &fwmod_nfho_lo) {
		hooknum = fwmod_nfho_lo.hooknum;
	}
	
	/* Store the time to calc the packet perf time. */
	__net_timestamp(sock_buff);
	tstamp = sock_buff->tstamp;
	ip_header = (struct iphdr*)(sock_buff->data);
	/* If the FW is inactive - don't check anything. */
	if(!(g_rules_config & FW_CONFIG_ACTIVE)) {
		goto CLEANUP;
	}

	if(skb_linearize(sock_buff)) {
		error("%s: skb_linearize() failed.\n", fname);
		goto CLEANUP;
	}

	/* This firewall handles only IPV4. */
	if(unlikely(ip_header->version != 4)) {
		debug(DESEC_FW, DEBUG_INFO, "%s: ip version: %d droped",
		fname, ip_header->version);
		decision.reason = REASON_NOT_IPV4;
		decision.action = NF_DROP;
		goto CLEANUP;
	}
	if(ip_header->saddr != localaddr && ip_header->daddr != localaddr) {
		debug(DESEC_FW, DEBUG_INFO, "%s: Received: %pI4 -> %pI4 from dev: %s\n",
			fname, &ip_header->saddr,
				&ip_header->daddr, (char *)sock_buff->dev);
	}
	switch(ip_header->protocol) {
		case PROT_ICMP:
			if(ip_header->saddr != localaddr && ip_header->daddr != localaddr) {
				debug(DESEC_FW, DEBUG_INFO, "%s: ICMP packet received.\n",
					fname);
				icmp = get_icmp(sock_buff->data);
			}
		break;
	case PROT_TCP:
		tcp = get_tcp(sock_buff->data);
		sport = tcp->source;
		dport = tcp->dest;
		if(ip_header->saddr != localaddr && ip_header->daddr != localaddr) {
			debug(DESEC_FW, DEBUG_INFO, "%s: TCP src_port: %u dst_port: "
					  "%u syn: %d ack: %d\n",
						fname, ntohs(sport), ntohs(dport),
					tcp->syn, tcp->ack);
		}
		/* If all of the TCP flags are on - we have a x-mass packet! */
		if(tcp->fin     == 1 && tcp->syn     == 1 &&
		   tcp->rst     == 1 && tcp->psh     == 1 &&
		   tcp->ack     == 1 && tcp->urg     == 1 && 
		   tcp->ece     == 1 && tcp->cwr     == 1) {
			debug(DESEC_FW, DEBUG_INFO,
				"%s: x-mass packet received and droped!\n", 
				fname);
			decision.reason = REASON_XMAS_PACKET;
			decision.action = NF_DROP;
			goto CLEANUP;
		}
		if((DEBUG_SECS & DESEC_DUMP) &&
				(ip_header->saddr != localaddr && ip_header->daddr != localaddr)) {
			char* data;
			int data_len;
			data = (char *)((unsigned char *)tcp + (tcp->doff * 4));
			data_len = (char*)sock_buff->end - (char*)data;
			print("len: %u\n", data_len);
			print("%s: data addrs data: %p sk: %p\n", fname, data, sock_buff);
			print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_NONE,
				16, 1, data, data_len, 1);
		}
		break;
	case PROT_UDP:
		udp = get_udp(sock_buff->data);
		sport = udp->source;
		dport = udp->dest;
		if(ip_header->saddr != localaddr && ip_header->daddr != localaddr) {
			debug(DESEC_FW, DEBUG_INFO, "%s: UDP src_port: %u dst_port: %u\n", fname,
				ntohs(sport), ntohs(dport));
		}
		break;
	default:
		debug(DESEC_FW, DEBUG_INFO, "packet received of protocol %u\n",
			ip_header->protocol);
		break;
	}

	if(is_prot_enforced(ip_header->protocol)) {
		if(unlikely((ip_header->protocol != PROT_TCP || 
			!(g_rules_config & FW_CONFIG_CONN_TRACK) || 
			(tcp->syn && !tcp->ack)) &&
			!enforce_rule_base(ip_header, sport, dport, 
			&decision))) {
			error("%s: enforce_rule_base() failed.\n", fname);
			rv = -ENOBUFS;
			goto CLEANUP;
		}
		if(unlikely((g_rules_config & FW_CONFIG_CONN_TRACK) &&
			ip_header->protocol == PROT_TCP                 &&
			ip_header->saddr    != localaddr                &&
			ip_header->daddr    != localaddr                &&
			!handle_tcp_conn_chain(sock_buff, g_rule_base, &decision))) {
			error("%s: handle_tcp_chain() failed.\n", fname);
			rv = -ENOBUFS;
			goto CLEANUP;
		}
	}
	else {
		decision.reason = REASON_PROT_NOT_ENFORCED;
	}

CLEANUP:
	__net_timestamp(sock_buff);
	if(ip_header->saddr != localaddr && ip_header->daddr != localaddr) {
		debug(DESEC_FW, DEBUG_INFO, "%s: packet process time: %llu nano.\n", fname,
			skb_get_ktime(sock_buff).tv64 - tstamp.tv64);
	}
	if(ip_header) {
		log_verdict_and_reason(ip_header, &decision, sport, dport, 
			hooknum);
	}
	return (rv != -ENOBUFS)?decision.action:rv;
}

/**
 * Module functions implementations.
 */

/** Handle opening of the rule_file.
 *  Parameters:
 *    inode - The inode of the file.
 *    filp  - The new filp struct.
 *  Returns: o for success, else for failure.
 */
static int
fwmod_open(struct inode *inode, struct file *filp)
{
	const static char fname[] = "fwmod_open";
	int               minor;

	minor = iminor(inode);
	debug(DESEC_FW, DEBUG_INFO, "%s: called for %d\n", fname, minor);
	filp->private_data = (void *)minor;
	return 0;
}

/** Release the allocated resources when the file was opened.
 *  Parameters:
 *    inode - The rule file inode.
 *    filp  - The file struct created when the file was opened.
 *  Returns: 0 for success, else for failure.
 */
static int
fwmod_release(struct inode *inode, struct file *filp)
{
	const static char fname[] = "fwmod_release";

	debug(DESEC_POLICY, DEBUG_INFO, "%s: called for %d\n", fname, iminor(inode));
	if(unlikely(!g_rule_base)) {
		error("%s: filp->private_data is null.\n", fname);
		goto CLEANUP;
	}
	switch(iminor(inode)) {
	case MINOR_RULES:
		if(unlikely((g_rule_base->rule_hash != 
			hash_rule_base(g_rule_file)) && 
			!load_rule_base(TRUE))) {
			error("%s: load_rule_base() failed.\n", fname);
		}
		break;
	case MINOR_LOG:
		break;
	case MINOR_CONN_TAB:
		break;
	default:
		break;
	}
CLEANUP:
	filp->private_data = NULL;
	return 0;
}

/** Handle memory faults to return the not yet memory page.
 *  Parameters:
 *    vma - The vma initialised by fwmod_mmap.
 *    vmf - struct for the fault event.
 *  Returns: zero for success else for failure.
 */
static int
fwmod_fault(struct vm_area_struct* vma, struct vm_fault* vmf)
{
	const static char fname[] = "fwmod_fault";
	int               rv      = 0;
	struct page*      page    = 0;

	debug(DESEC_POLICY, DEBUG_INFO, "%s: called offset: %lu\n", fname, vmf->pgoff);
	if (unlikely(vmf->pgoff > vma->vm_end)) {
		error("%s: invalid address\n", fname);
		rv = VM_FAULT_SIGBUS;
		goto CLEANUP;
	}
	if (unlikely(!vma->vm_private_data)) {
		error("%s: no page\n", fname);
	}
	page = virt_to_page(vma->vm_private_data + 
		(vmf->pgoff << PAGE_SHIFT));
	get_page(page);
	vmf->page = page;
CLEANUP:
	return rv;
}

/**
 * Holds the virtual memory operations.
 */
struct vm_operations_struct fwmod_vm_ops = {
	.fault  = fwmod_fault
};

/** 
 * Count the amount of currently active connections.
 */
static boolean
count_cur_conn_tab(void)
{
	const static char   fname[]   = "count_cur_conn_tab";
	boolean             rv        = TRUE;
	conn_table_t*       conn_tab  = 0;
	unsigned int        hash_code = 0;
	int                 i         = 0;
	struct hash_node_t* cur_hash  = 0;
	struct timeval      cur_time;

	debug(DESEC_POLICY, DEBUG_INFO, "%s: called.\n", fname);
	do_gettimeofday(&cur_time);
	if(unlikely(!g_conn_tab_file || !g_rule_base || 
		!g_rule_base->connection_table)) {
		error("%s: g_conn_tab_file or g_rule_base or "
			  "g_rule_base->connection_table are null.\n", 
			fname);
		rv = FALSE;
		goto CLEANUP;
	}
	conn_tab = (conn_table_t *)g_rule_base->connection_table;
	if(unlikely(!conn_tab->hash)) {
		error("%s: conn_tab->hash is null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	for(hash_code = 0; hash_code < MAX_HASH_ELEMENTS; ++hash_code) {
		for(cur_hash = conn_tab->hash[hash_code]; cur_hash;
			cur_hash = cur_hash->next) {
			if(cur_hash->data) {
				conn_node_t* node = 
					(conn_node_t *)cur_hash->data;
				if(unlikely(i >= CONNECTION_TABLE_ENTRIES)) {
					error("%s: too many connections.\n", 
					fname);
					rv = FALSE;
					goto CLEANUP;
				}
				if(node->connection.expires > 
					cur_time.tv_sec) {
					++i;
				}
			}
		}
	}
	g_conn_tab_size = (i + 1) * sizeof(connection_t);
CLEANUP:
	debug(DESEC_POLICY, DEBUG_INFO, "%s: connection size: %lu.\n", fname,
		g_conn_tab_size);
	return rv;
}

/** Copy the current active connection to the connection array.
 *
 */
static boolean
copy_cur_conn_tab(void)
{
	const static char   fname[]   = "copy_cur_conn_tab";
	boolean             rv        = TRUE;
	conn_table_t*       conn_tab  = 0;
	unsigned int        hash_code = 0;
	struct timeval      cur_time;
	int                 i         = 0;
	struct hash_node_t* cur_hash  = 0;

	debug(DESEC_POLICY, DEBUG_INFO, "%s: called.\n", fname);
	do_gettimeofday(&cur_time);
	if(unlikely(!g_conn_tab_file || !g_rule_base || 
		!g_rule_base->connection_table)) {
		error("%s: g_conn_tab_file or g_rule_base or "
			  "g_rule_base->connection_table are null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	conn_tab = (conn_table_t *)g_rule_base->connection_table;
	if(unlikely(!conn_tab->hash)) {
		error("%s: conn_tab->hash is null.\n", fname);
		rv = FALSE;
		goto CLEANUP;
	}
	for(hash_code = 0; hash_code < MAX_HASH_ELEMENTS; ++hash_code) {
		for(cur_hash = conn_tab->hash[hash_code]; cur_hash;
			cur_hash = cur_hash->next) {
			if(cur_hash->data) {
				conn_node_t* node = 
					(conn_node_t *)cur_hash->data;
				if(i >= CONNECTION_TABLE_ENTRIES) {
					error("%s: too many connections.\n", 
					fname);
					rv = FALSE;
					goto CLEANUP;
				}
				if(node->connection.expires > 
					cur_time.tv_sec) {
					g_conn_tab_file[i].cli_ip = ntohl(
						node->connection.cli_ip);
					g_conn_tab_file[i].ser_ip = ntohl(
						node->connection.ser_ip);
					g_conn_tab_file[i].cli_port = 
						ntohs(
						node->connection.cli_port);
					g_conn_tab_file[i].ser_port = 
						ntohs(
						node->connection.ser_port);
					g_conn_tab_file[i].expires = 
						node->connection.expires;
					g_conn_tab_file[i].state = 
						node->connection.state;
					debug(DESEC_POLICY, DEBUG_INFO,
						"%s: conn[%d] <%pI4:%d->%pI4"
						":%d exp: %d state: %s>.\n", 
						fname, i, 
						&node->connection.cli_ip, 
						g_conn_tab_file[i].cli_port,
						&node->connection.ser_ip, 
						g_conn_tab_file[i].ser_port,
						node->connection.expires, 
						state_to_string(
						node->connection.state));
					++i;
				}
			}
		}
	}
CLEANUP:
	g_conn_tab_size = (i + 1) * sizeof(connection_t);
	if(!i) {
		g_conn_tab_file[i].expires = 0;
	}
	debug(DESEC_POLICY, DEBUG_INFO, "%s: connection size: %lu.\n", fname,
		g_conn_tab_size);
	return rv;
}

/** Memory map handler for user request.
 * Parameters:
 *   filp - The file to mmap.
 *   vma  - The virtual memory area struct.
 * Returns: zero for success else for failure.
 */
static int
fwmod_mmap (struct file* filp, struct vm_area_struct* vma)
{
	const static char fname[] = "fwmod_mmap";
	int               rv      = 0;
	int               minor;

	debug(DESEC_POLICY, DEBUG_INFO,
			"%s: called start: %lu pgoff: %lu size: %lu\n",
				fname, vma->vm_start, vma->vm_pgoff, 
				vma->vm_end - vma->vm_start);
	minor = (int)filp->private_data;
	vma->vm_flags |= VM_IO;
	vma->vm_ops = &fwmod_vm_ops;
	switch(minor) {
		case MINOR_RULES:
			vma->vm_private_data = g_rule_file;
			break;
		case MINOR_LOG:
			vma->vm_private_data = g_log_file;
			break;
		case MINOR_CONN_TAB:
			vma->vm_private_data = g_conn_tab_file;
			if(!copy_cur_conn_tab()) {
				error("%s: copy_cur_conn_tab failed\n", fname);
				goto CLEANUP;
			}
			break;
		default:
			error("%s: unknown minor number received: %d\n", 
				fname, minor);
			goto CLEANUP;
	}
CLEANUP:
	return rv;
}

/**
 * Holds the module functions for file operations.
 */
static const struct file_operations fwmod_fops = {
	.owner   = THIS_MODULE,
	.open    = fwmod_open,
	.release = fwmod_release,
	.mmap    = fwmod_mmap,
};

/** Returns the rules config flag.
 * Parameters:
 *   device - The rules config device.
 *   attr   - The device attribute.
 *   buff   - The byte to put the result on.
 */
static ssize_t
fwmod_rules_config_show(struct kobject* device, struct kobj_attribute* attr,
		char* buff)
{
	sprintf(buff, "%u\n", g_rules_config);
	return strlen(buff);
}

/** Returns the rules table size in bytes.
 * Parameters:
 *   device - The rules config device.
 *   attr   - The device attribute.
 *   buff   - The byte to put the result on.
 */
static ssize_t
fwmod_rules_size_show(struct kobject* device, struct kobj_attribute* attr,
		char* buff)
{
	sprintf(buff, "%lu\n", g_rules_size);
	return strlen(buff);
}

/** Returns the log size in bytes.
 * Parameters:
 *   device - The rules config device.
 *   attr   - The device attribute.
 *   buff   - The byte to put the result on.
 */
static ssize_t
fwmod_log_size_show(struct kobject* device, struct kobj_attribute* attr,
		char* buff)
{
	sprintf(buff, "%lu\n", g_log_size);
	return strlen(buff);
}

/** Returns the connection table size in bytes.
 * Parameters:
 *   device - The rules config device.
 *   attr   - The device attribute.
 *   buff   - The byte to put the result on.
 */
static ssize_t
fwmod_conn_tab_size_show(struct kobject* device, struct kobj_attribute* attr,
		char* buff)
{
	const static char fname[]      = "fwmod_conn_tab_size_show";

	count_cur_conn_tab();
	debug(DESEC_POLICY, DEBUG_INFO, "%s: g_conn_tab_size: %lu\n", fname, g_conn_tab_size);
	sprintf(buff, "%lu\n", g_conn_tab_size);
	return strlen(buff);
}

/** Store the rules config flag value.
 * Parameters:
 *   device - The rules config device.
 *   attr   - The device attributes.
 *   buff   - The received buffer.
 *   count  - The amount of bytes received.
 * Returns: The actual read byte.
 */
static ssize_t
fwmod_rules_config_store(struct kobject* device, struct kobj_attribute* attr,
		const char* buff, size_t count)
{
	#define is_active(var, flag) (((var) & (flag))?"active":"inactive")
	const static char fname[]      = "fwmod_rules_config_store";
	unsigned int      rules_config = 0;
	char*             rp           = 0;
	conn_table_t*     conn_tab     = 0;

	if(count <= 0) {
		error("%s: count <= 0.\n",
		      fname);
		goto CLEANUP;
	}
	debug(DESEC_POLICY, DEBUG_INFO, "%s: received config flag: %s\n", fname, buff);
	rules_config = simple_strtoul(buff, &rp, 10);
	if(!rp) {
		error("%s: The received value is not an unsigned "
		      "integer.\n",
		      fname);
		goto CLEANUP;
	}
	g_rules_config = rules_config;
	debug(DESEC_POLICY, DEBUG_INFO, "%s: fw - %s, icmp - %s, tcp - %s, udp - %s,"
			" conn_track - %s, cleanup - %s, sql1 - %s, sql2 - %s, zabbix - %s\n", fname,
			is_active(rules_config, FW_CONFIG_ACTIVE),
			is_active(rules_config, FW_CONFIG_ICMP),
			is_active(rules_config, FW_CONFIG_TCP),
			is_active(rules_config, FW_CONFIG_UDP),
			is_active(rules_config, FW_CONFIG_CONN_TRACK),
			is_active(rules_config, FW_CONFIG_CLEANUP_ACCEPT),
			is_active(rules_config, FW_CONFIG_SQL_PROTECT1),
			is_active(rules_config, FW_CONFIG_SQL_PROTECT2),
			is_active(rules_config, FW_CONFIG_ZABBIX));
	if(g_rules_config & FW_CONFIG_ACTIVE) {
		conn_tab = (conn_table_t*)g_rule_base->connection_table;
		if(conn_tab) {
			connection_table_clear(conn_tab);
		}
		if(unlikely(!load_rule_base(TRUE))) {
			error("%s: load_rule_base() failed.\n", fname);
		}
	}
CLEANUP:
	return rp?strlen(buff):-EIO;
}

/** when character receives - clear the log.
 * Parameters:
 *   device - The log device.
 *   attr   - The device attributes.
 *   buff   - The received buffer.
 *   count  - The amount of bytes received.
 * Returns: The actual read byte.
 */
static ssize_t
fwmod_log_clear(struct kobject* device, struct kobj_attribute* attr,
		const char* buff, size_t count)
{
	const static char fname[]      = "fwmod_log_clear";

	if(count <= 0) {
		error("%s: count <= 0.\n",
		      fname);
		goto CLEANUP;
	}
	memset(g_log_file, 0, LOG_ENTRIES * sizeof(log_row_t));
	g_log_size = sizeof(log_row_t);
	debug(DESEC_POLICY, DEBUG_INFO, "%s: log cleared.\n", fname);
CLEANUP:
	return strlen(buff);
}

/** when character receives - clear the connection table.
 * Parameters:
 *   device - The log device.
 *   attr   - The device attributes.
 *   buff   - The received buffer.
 *   count  - The amount of bytes received.
 * Returns: The actual read byte.
 */
static ssize_t
fwmod_conn_tab_clear(struct kobject* device, struct kobj_attribute* attr,
		const char* buff, size_t count)
{
	const static char fname[]      = "fwmod_conn_tab_clear";	
	conn_table_t*     conn_tab     = 0;

	debug(DESEC_POLICY, DEBUG_INFO, "%s: called.\n", fname);
	if(count <= 0) {
		error("%s: count <= 0.\n",
		      fname);
		goto CLEANUP;
	}
	if(!g_conn_tab_file) {
		error("%s: g_conn_tab_file is null.\n", fname);
		goto CLEANUP;
	}
	if(!g_rule_base) {
		error("%s: g_rule_base is null.\n", fname);
		goto CLEANUP;
	}
	if(!g_rule_base->connection_table) {
		error("%s: g_rule_base->connection_table is null.\n", fname);
		goto CLEANUP;
	}
	conn_tab = (conn_table_t *)g_rule_base->connection_table;
	connection_table_clear(conn_tab);
	g_conn_tab_size = sizeof(connection_t);
	debug(DESEC_POLICY, DEBUG_INFO, "%s: connection table cleared.\n", fname);
CLEANUP:
	return strlen(buff);
}

/** The input and reset attributes.
 */
static int reset __attribute__((__unused__));
static int input __attribute__((__unused__));
static struct kobj_attribute attr_rules_config = __ATTR(
		config, S_IWUSR | S_IRUSR, fwmod_rules_config_show,
		fwmod_rules_config_store);
static struct kobj_attribute attr_rules_size   = __ATTR(
		rules_size, S_IRUSR, fwmod_rules_size_show, NULL);
static struct kobj_attribute attr_log_size = __ATTR(
		log_size, S_IRUSR, fwmod_log_size_show, NULL);
static struct kobj_attribute attr_log_clear = __ATTR(
		log_clear, S_IWUSR, NULL, fwmod_log_clear);
static struct kobj_attribute attr_conn_tab_size = __ATTR(
		conn_tab_size, S_IRUSR, fwmod_conn_tab_size_show, NULL);
static struct kobj_attribute attr_conn_tab_clear = __ATTR(
		conn_tab_clear, S_IWUSR, NULL, fwmod_conn_tab_clear);
static struct attribute* fwmod_attrs_rules[] = {
        &attr_rules_config.attr,
        &attr_rules_size.attr,
        NULL,
};
static struct attribute* fwmod_attrs_log[] = {
        &attr_log_clear.attr,
        &attr_log_size.attr,
        NULL,
};
static struct attribute* fwmod_attrs_conn_tab[] = {
        &attr_conn_tab_clear.attr,
        &attr_conn_tab_size.attr,
        NULL,
};
static const struct attribute_group fwmod_attr_group_rules = {
        .attrs = fwmod_attrs_rules
};
static const struct attribute_group fwmod_attr_group_log = {
        .attrs = fwmod_attrs_log
};
static const struct attribute_group fwmod_attr_group_conn_tab = {
        .attrs = fwmod_attrs_conn_tab
};

/**
 * Register the firewall module to the kernel.
 * Returns: zero for success else for failure.
 */
static int
__init fwmod_init(void)
{
	const static char fname[]                 = "fwmod_init";
	int               rc                      = 0;
	boolean           mod_registered          = FALSE;
	boolean           device_log_created      = FALSE;
	boolean           device_rules_created    = FALSE;
	boolean           device_conn_tab_created = FALSE;
	boolean           rule_base_loaded        = FALSE;

	rc = alloc_chrdev_region(&fwmod_dev, 0, MINOR_COUNT, CLASS_NAME);
	if (rc) {
		error("%s: alloc_chrdev_region() failed\n", fname);
		goto CLEANUP;
	}
	mod_registered = TRUE;
	cdev_init(&fwmod_cdev, &fwmod_fops);
	rc = cdev_add(&fwmod_cdev, fwmod_dev, MINOR_COUNT);
	if (unlikely(rc)) {
		error("%s: cdev_add() failed\n", fname);
		goto CLEANUP;
	}
	fwmod_class = class_create(THIS_MODULE, CLASS_NAME);
	if (unlikely(IS_ERR(fwmod_class))) {
		error("%s: class_create() failed\n", fname);
		rc = PTR_ERR(fwmod_class);
		goto CLEANUP;
	}

	fwmod_device_rules = device_create(fwmod_class, NULL,
			MKDEV(MAJOR(fwmod_dev), MINOR_RULES), "%s",
			CLASS_DEVICE_NAME(CLASS_NAME, DEVICE_NAME_RULES));
	if (unlikely(IS_ERR(&fwmod_device_rules))) {
		error("%s: device_create() for fwmod_device_rules failed\n", 
			fname);
		rc = PTR_ERR(&fwmod_device_rules);
		goto CLEANUP;
	}
	device_rules_created = TRUE;
	fwmod_device_log = device_create(fwmod_class, NULL,
			MKDEV(MAJOR(fwmod_dev), MINOR_LOG), "%s",
			CLASS_DEVICE_NAME(CLASS_NAME, DEVICE_NAME_LOG));
	if (unlikely(IS_ERR(&fwmod_device_log))) {
		error("%s: device_create() for fwmod_device_log failed\n", 
			fname);
		rc = PTR_ERR(&fwmod_device_log);
		goto CLEANUP;
	}
	device_log_created = TRUE;
	fwmod_device_conn_tab = device_create(fwmod_class, NULL,
			MKDEV(MAJOR(fwmod_dev), MINOR_CONN_TAB), "%s",
			CLASS_DEVICE_NAME(CLASS_NAME, DEVICE_NAME_CONN_TAB));
	if (unlikely(IS_ERR(&fwmod_device_conn_tab))) {
		error("%s: device_create() for "
		      "fwmod_device_conn_tab failed\n", fname);
		rc = PTR_ERR(&fwmod_device_conn_tab);
		goto CLEANUP;
	}
	device_conn_tab_created = TRUE;
	rc = sysfs_create_group(&fwmod_device_rules->kobj, 
		&fwmod_attr_group_rules);
	if (unlikely(rc)) {
		error("%s: sysfs_create_group() failed for rules\n", fname);
		goto CLEANUP;
	}
	rc = sysfs_create_group(&fwmod_device_log->kobj, 
		&fwmod_attr_group_log);
	if (unlikely(rc)) {
		error("%s: sysfs_create_group() failed for log\n", fname);
		goto CLEANUP;
	}
	rc = sysfs_create_group(&fwmod_device_conn_tab->kobj, 
		&fwmod_attr_group_conn_tab);
	if (unlikely(rc)) {
		error("%s: sysfs_create_group() failed for conn_tab\n", fname);
		goto CLEANUP;
	}
	/* Allocate mmap areas.*/
	g_rule_file_size = RULE_BASE_ENTRIES * sizeof(rule_t);
	g_rule_file      = fw_malloc(g_rule_file_size);
	if(unlikely(!g_rule_file)) {
		error("%s: out of memory. (g_rule_file)\n", fname);
		rc = FALSE;
		goto CLEANUP;
	}
	memset(g_rule_file, 0, g_rule_file_size);
	/* The default rules. */
	g_rule_file[0].protocol = PROT_ICMP;
	g_rule_file[0].src_ip = localaddr;
	g_rule_file[0].dst_ip = localaddr;
	g_rule_file[0].src_port = 0;
	g_rule_file[0].dst_port = 0;
	g_rule_file[0].src_mask = 32;
	g_rule_file[0].dst_mask = 32;
	g_rule_file[0].action   = NF_ACCEPT;
	g_rule_file[1].protocol = PROT_TCP;
	g_rule_file[1].src_ip = localaddr;
	g_rule_file[1].dst_ip = localaddr;
	g_rule_file[1].src_port = 0;
	g_rule_file[1].dst_port = 0;
	g_rule_file[1].src_mask = 32;
	g_rule_file[1].dst_mask = 32;
	g_rule_file[1].action   = NF_ACCEPT;
	g_rule_file[2].protocol = PROT_UDP;
	g_rule_file[2].src_ip = localaddr;
	g_rule_file[2].dst_ip = localaddr;
	g_rule_file[2].src_port = 0;
	g_rule_file[2].dst_port = 0;
	g_rule_file[2].src_mask = 32;
	g_rule_file[2].dst_mask = 32;
	g_rule_file[2].action   = NF_ACCEPT;
	g_rule_file[3].protocol = PROT_RES;

	g_rule_file_copy = fw_malloc(g_rule_file_size);
	if(unlikely(!g_rule_file_copy)) {
		error("%s: out of memory. (g_rule_file_copy)\n", fname);
		rc = FALSE;
		goto CLEANUP;
	}
	memcpy(g_rule_file_copy, g_rule_file, g_rule_file_size);
	g_log_size = sizeof(log_row_t);
	g_log_file      = fw_malloc(LOG_ENTRIES * sizeof(log_row_t));
	if(unlikely(!g_log_file)) {
		error("%s: out of memory. (g_log_file)\n", fname);
		rc = FALSE;
		goto CLEANUP;
	}
	memset(g_log_file, 0, LOG_ENTRIES * sizeof(log_row_t));
	g_conn_tab_size = sizeof(connection_t);
	g_conn_tab_file      = fw_malloc(CONNECTION_TABLE_ENTRIES * 
		sizeof(connection_t));
	if(unlikely(!g_conn_tab_file)) {
		error("%s: out of memory. (g_conn_tab)\n", fname);
		rc = FALSE;
		goto CLEANUP;
	}
	memset(g_conn_tab_file, 0, CONNECTION_TABLE_ENTRIES * 
		sizeof(connection_t));
	if(unlikely(!load_rule_base(FALSE))) {
		error("%s: load_rule_base() failed.\n", fname);
		rc = FALSE;
		goto CLEANUP;
	}
	rule_base_loaded = TRUE;
	fwmod_nfho.hook = firewall_rx;
	/* Hook at before routing which is just after packet received. */
	fwmod_nfho.hooknum = NF_INET_PRE_ROUTING;
	fwmod_nfho.pf = PF_INET;
	/* Give the firewall module the highest hook priority. */
	fwmod_nfho.priority = NF_IP_PRI_FIRST;
	if(unlikely(nf_register_hook(&fwmod_nfho) < 0)) {
		error("%s: nf_register_hook() failed.\n", fname);
		rc = FALSE;
		goto CLEANUP;
	}
	fwmod_nfho_lo.hook = firewall_rx;
	/* Hook at local machine output. */
	fwmod_nfho_lo.hooknum = NF_INET_LOCAL_OUT;
	fwmod_nfho_lo.pf = PF_INET;
	/* Give the firewall module the highest hook priority. */
	fwmod_nfho_lo.priority = NF_IP_PRI_FIRST;
	if(unlikely(nf_register_hook(&fwmod_nfho_lo) < 0)) {
		error("%s: nf_register_hook() failed. (lo)\n", fname);
		rc = FALSE;
		goto CLEANUP;
	}
	/* Prepare the SQL Injection automata. */
	http_protection_allocate(&sqli_loaded, &zabbix_loaded);
	print("Firewall module loaded.\n");
CLEANUP:
	if(unlikely(rc)) {
		if(rule_base_loaded) {
			clean_rule_base(g_rule_base);
			g_rule_base = 0;
		}
		if(g_conn_tab_file) {
			kfree(g_conn_tab_file);
		}
		if(g_rule_file_copy) {
			kfree(g_rule_file_copy);
		}
		if(g_log_file) {
			kfree(g_log_file);
		}
		if(g_rule_file) {
			kfree(g_rule_file);
		}
		if(fwmod_class) {
			if(device_conn_tab_created) {
				device_unregister(fwmod_device_conn_tab);
			}
			if(device_rules_created) {
				device_unregister(fwmod_device_rules);
			}
			if(device_log_created) {
				device_unregister(fwmod_device_log);
			}
			device_destroy(fwmod_class, fwmod_dev);
			class_destroy(fwmod_class);
		}
		cdev_del(&fwmod_cdev);
		if(mod_registered) {
			unregister_chrdev_region(fwmod_dev, MINOR_COUNT);
		}
	}
	return rc;
}

/**
 * Unregister the firewall module from the kernel.
 */
static void
__exit fwmod_exit(void)
{
	http_protection_release();
	g_rules_config = 0;
	clean_rule_base(g_rule_base);
	kfree(g_conn_tab_file);
	kfree(g_log_file);
	kfree(g_rule_file_copy);
	kfree(g_rule_file);
	g_rule_base = 0;
	device_unregister(fwmod_device_log);
	device_unregister(fwmod_device_rules);
	device_unregister(fwmod_device_conn_tab);
	device_destroy(fwmod_class, fwmod_dev);
	class_destroy(fwmod_class);
	cdev_del(&fwmod_cdev);
	unregister_chrdev_region(fwmod_dev, MINOR_COUNT);
	nf_unregister_hook(&fwmod_nfho);
	nf_unregister_hook(&fwmod_nfho_lo);
	print("Firewall module removed.\n");
}

/**
 * Set our init and exit functions as the init and exit fuctions
 *  of our firewall module.
 */
module_init(fwmod_init);
module_exit(fwmod_exit);

