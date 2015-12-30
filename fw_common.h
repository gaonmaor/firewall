/*
 * fw_common.h
 * This header contains common typed and definitions for the firewall.
 * Made By: Maor Gaon 301308821
 */

#ifndef FW_COMMON_H_
#define FW_COMMON_H_

/**
 * Used to suppress annoying warnings for unused
 *  fnames due to non debug mode.
 */
#define UNUSED(x) (void)(x)

/**
 * Log levels.
 */
#define DEBUG_INFO      0
#define DEBUG_WARNING  -1
#define DEBUG_ERROR    -2

/* Convert boolean to string. */
#define boolean_to_string(b) ((b)?"true":"false")

#define get_icmp(data)     (struct icmphdr*)(((char *)data) + sizeof(struct iphdr))
#define get_udp(data)      (struct  udphdr*) (((char *)data) + sizeof(struct iphdr))
#define get_tcp(data)      (struct  tcphdr*) (((char *)data) + sizeof(struct iphdr))
#define get_tcp_data(tcp)  (char *)((unsigned char *)tcp + (tcp->doff * 4))
#define get_udp_data(data) (((char *)data) + sizeof(struct iphdr) + sizeof(struct udphdr))

/**
 * Define debug mode.
 * Note No need to define from here, just run: make debug instead of make all.
 */
/*#ifndef __DEBUG__
#define __DEBUG__
#endif*/

#ifndef __DEBUG__

#define debug(level, format, ...) UNUSED(fname);
#define __DEBUG_FUNCTION__
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ctype.h>
#include <linux/stat.h>        /* permission bits on module_param   */
#include <linux/moduleparam.h> /* module_param, MODULE_PARM_DESC... */
#include <linux/init.h>        /* __init, __exit                    */
#include <linux/cdev.h>        /* cdev_*                            */
#include <linux/mm.h>          /* mmap                              */
#include <linux/spinlock.h>    /* spinlock                          */
#include <linux/netfilter.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/time.h>
#include <linux/sort.h>

/**
 * Debugging sections.
 */
typedef enum {
	DESEC_FW		= 1,
	DESEC_POLICY	= 2,
	DESEC_CONN_TAB	= 4,
	DESEC_TCP		= 8,
	DESEC_HTTP		= 0x10,
	DESEC_SQLI		= 0x20,
	DESEC_PM		= 0x40,
	DESEC_DUMP		= 0x80
} DEBUG_SEC;

#define print(format, ...)   printk(KERN_INFO format, ##__VA_ARGS__)
#define error(format, ...)   printk(KERN_ERR format, ##__VA_ARGS__)
#define warning(format, ...) printk(KERN_WARNING format, ##__VA_ARGS__)
#define DEBUG_SECS (DESEC_POLICY | DESEC_HTTP | DESEC_SQLI)
#define __DEBUG_ALL 0
#ifndef __DEBUG_FUNCTION__
#define debug(sec, level, format, ...) if(__DEBUG_ALL || (sec & DEBUG_SECS)) printk(KERN_INFO #level ": " format, \
		##__VA_ARGS__);
#endif
#define fw_malloc(size) kmalloc(size, GFP_KERNEL)
#define fw_malloc_atomic(size) kmalloc(size, GFP_ATOMIC)
#define fw_free kfree
#define atoi(buff) simple_strtoul(buff, 0, 10)

/**
 * Boolean type.
 */
typedef enum {
	FALSE,
	TRUE
} boolean;

/**
 * Protections type.
 */
typedef enum {
	PROT_SQLI
} protection_type_t;

/**
 * Contains the parsers types.
 */
typedef enum {
	HTTP_PARSER
} protection_parser_type_t;

/**
 * Identify the packet direction.
 */
typedef enum {
	CLIENT_TO_SERVER,
	SERVERT_TO_CLIENT,
	ANY
} conn_dir_t;

/**
 * Byte type.
 */
typedef unsigned char byte;

/* Rule base. */
typedef struct {
	__u8	protocol; /* values from: prot_t               */
	__u8	src_mask; /* valid values: 0-32                */
	__u8	dst_mask; /* valid values: 0-32                */
	__u8	action;   /* valid values: NF_ACCEPT, NF_DROP  */
	__be16	src_port;
	__be16	dst_port;
	__be32	src_ip;
	__be32	dst_ip;
} rule_t;

/**
 * The SQL injection protection levels.
 */
typedef enum {
	SQLI_NO_PROT 	= 0,
	SQLI_LOW	 	= 1,
	SQLI_MEDIUM		= 2,
	SQLI_HIGH		= 3
} sqli_prot_mode_t;

/**
 * The protection data for SQL injection.
 */
typedef struct {
	sqli_prot_mode_t 	prot_mode;
} sqli_protection_t;

/**
 * This structure contains the rulebase memory data.
 */
typedef struct {
	/**
	 * Contains all the active connections.
	 * type (conn_table_t)
	 */
	void*				connection_table;
	/**
	 * The verdict rules array.
	 */
	rule_t*				rule_list;
	/**
	 * SQL Injection general protection rule.
	 */
	sqli_protection_t	sqli_prot_data;
	/**
	 * Handle zabbix specific protection on or off.
	 */
	boolean				zabbix_active;
	/**
	 * The current rule list hash.
	 */
	unsigned long		rule_hash;
} rule_base_t;

/* Maximum size of IP string, include IPV6. */
#define MAX_IP_STR 48
/* Maximum number of HTTP headers to parse. */
#define MAX_HTTP_HEADER_COUNT 30
/* Maximum length for get value. */
#define MAX_HTTP_VALUE_SIZE   1500
/* The alphabetic length.*/
#define MAX_BM_PATTERN        256
/* Define the maximum bm algorithm length. */
#define MAX_BM_STRING         MAX_HTTP_VALUE_SIZE

/* 127.0.0.1 in little endian. */
#define localaddr 0x0100007f

/* Auxiliary strings, for your convenience. */
#define DEVICE_NAME_RULES      "rules"
#define DEVICE_NAME_LOG        "log"
#define DEVICE_NAME_CONN_TAB   "conn_tab"
#define CLASS_NAME             "fw5"

// these values represent the number of entries in each mmap()able device,
// they do not represent the size in bytes!
#define RULE_BASE_ENTRIES         0x100
#define LOG_ENTRIES               0x400
#define CONNECTION_TABLE_ENTRIES  0x400

/** HTTP request.
 */
struct http_request_t {
	const char*    request_method; /* "GET", "POST", "HEAD", "CONNECT",
									  "PUT", "DELETE", "OPTIONS",
									  "PROPFIND", "MKCOL"                    */
	const char*    uri;            /* URL-decoded URI                        */
	const char*    http_version;   /* E.g. "1.0", "1.1"                      */
	const char*    query_string;   /* URL after '?' (exclude '?'), or NULL   */
	char           remote_ip[MAX_IP_STR];  /* Remote IP address              */
	char           local_ip[MAX_IP_STR];   /* Local IP address               */
	unsigned short remote_port;    /* Client's port                          */
	unsigned short local_port;     /* Local port number                      */
	int            num_headers;    /* Number of HTTP headers                 */
	struct http_request_header_t {
		const char* name;            /* HTTP header name                     */
		const char* value;           /* HTTP header value                    */
	}              http_headers[MAX_HTTP_HEADER_COUNT];
	struct http_query_string_t {
		const char* name;                /* HTTP attribute name        */
		char value[MAX_HTTP_VALUE_SIZE]; /* HTTP value                 */
	}              queries[MAX_HTTP_HEADER_COUNT];
	int            query_count;    /* Attribute count. */
	char*          content;        /* POST(or websocket message)data,or NULL */
	size_t         content_len;    /* Data length                            */
	int            is_websocket;   /* Connection is a websocket connection   */
	int            status_code;    /* HTTP status code for HTTP error handler*/
	int            wsbits;         /* First byte of the websocket frame      */
};

/* The 3 protocols we will work with. */
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_RES    = 255,
} prot_t;

/* Various reasons to be registered in each log entry. */
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NOT_IPV4              = -2,
	REASON_PROT_NOT_ENFORCED     = -3,
	REASON_NO_MATCHING_RULE      = -4,
	REASON_OUT_OF_STATE          = -5,
	REASON_CONNECTION_TABLE_FULL = -6,
	REASON_XMAS_PACKET           = -7,
	REASON_SQLI                  = -8,
	REASON_ZABBIX				 = -9
} reason_t;


/* Device minor numbers, for your convenience. */
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
	MINOR_CONN_TAB = 2,
} minor_t;


/* Configuration bits. */
typedef enum {
	FW_CONFIG_ACTIVE         	= 0x01,
	FW_CONFIG_ICMP           	= 0x02,
	FW_CONFIG_TCP            	= 0x04,
	FW_CONFIG_UDP            	= 0x08,
	FW_CONFIG_CONN_TRACK     	= 0x10,
	FW_CONFIG_CLEANUP_ACCEPT 	= 0x20,
	/* If both are 0 - no SQLI protection, PROTECT1 - low,
	 * PROTECT2 - medium, both - high.	 */
	FW_CONFIG_SQL_PROTECT1	 	= 0x40,
	FW_CONFIG_SQL_PROTECT2	 	= 0x80,
	FW_CONFIG_ZABBIX			= 0x100
} config_t;

/* auxiliary struct for your convenience. */
typedef struct {
	__u8 action;  /* valid values: NF_ACCEPT, NF_DROP */
	int  reason;  /* values from: reason_t */
} decision_t;


/* logging */
typedef struct {
	unsigned long  modified;     /* seconds since epoch              */
	unsigned char  protocol;     /* values from: prot_t              */
	unsigned char  action;       /* valid values: NF_ACCEPT, NF_DROP */
	unsigned char  hooknum;      /* as received from netfilter hook  */
	unsigned int   src_ip;
	unsigned int   dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	signed int     reason;       // rule#, or values from: reason_t
	unsigned int   count;        // counts this line's hits
} log_row_t;


// connection tracking
typedef struct {
	unsigned int   cli_ip;      // ip of the side that sent the 1st SYN
	unsigned int   ser_ip;      // ip of the other side
	unsigned short cli_port;    // source port of 1st SYN packet
	unsigned short ser_port;    // destination port of 1st SYN packet
	unsigned int   expires;     // in seconds from epoch
	unsigned char  state;       // values from: tcp_conn_t
} connection_t;


// the four states of a TCP connection (simplified!)
typedef enum {
	// connection states
	TCP_CONN_SYN_SENT  = 1,
	TCP_CONN_SYN_ACK   = 2,
	TCP_CONN_ESTAB     = 3,
	TCP_CONN_CLOSING   = 4,
} tcp_conn_t;

/** Reason to string.
 *  Parameters:
 *  	reason - The reason number.
 *  Returns: the string representation.
 *
 */
const char*
reason_to_string(int reason);

#endif /* FW_COMMON_H_ */
