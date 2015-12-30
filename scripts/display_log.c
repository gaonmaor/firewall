/* For the size of the file. */
#include <sys/stat.h>
#include <sys/mman.h> 
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/* logging */
typedef struct {
	unsigned long  modified;     /* seconds since epoch*/
	unsigned char  protocol;     /* values from: prot_t*/
	unsigned char  action;       /* valid values: NF_ACCEPT, NF_DROP*/
	unsigned char  hooknum;      /* as received from netfilter hook*/
	unsigned int   src_ip;
	unsigned int   dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	signed int     reason;       /* rule#, or values from: reason_t*/
	unsigned int   count;        /* counts this line's hits*/
} log_row_t;

static void
check (int test, const char * message, ...)
{
    if (test) {
        va_list args;
        va_start (args, message);
        vfprintf (stderr, message, args);
        va_end (args);
        fprintf (stderr, "\n");
        exit (EXIT_FAILURE);
    }
}

int main ()
{
    /* The file descriptor. */
    int fd;
    /* Information about the file. */
    struct stat s;
    int status;
    size_t size;
    /* The file name to open. */
    const char * file_name = "/dev/fw5_log";
    /* The memory-mapped thing itself. */
    const char * mapped;
    int i;
    log_row_t* lg;

    /* Open the file for reading. */
    fd = open (file_name, O_RDONLY);
    check (fd < 0, "open %s failed: %s", file_name, strerror (errno));

    /* Get the size of the file. */
    status = fstat (fd, & s);
    check (status < 0, "stat %s failed: %s", file_name, strerror (errno));
    /*size = s.st_size;*/
    size = 28672;

    /* Memory-map the file. */
    mapped = mmap (0, size, PROT_READ, MAP_SHARED, fd, 0);
    check (mapped == MAP_FAILED, "mmap %s failed: %s",
           file_name, strerror (errno));

    /* Now do something with the information. */
    lg = (log_row_t *)mapped;
    for (i = 0; lg->protocol && (((void*)lg) - ((void*)mapped)) < size; i++) {
	printf("%d: mod: %lu prt: %u act: %u hoo: %u sa: %u da: %u\n"
		"\t\tsp: %u dp: %u rs: %u ct: %u\n", i,
		lg->modified, lg->protocol, lg->action,
		lg->hooknum, lg->src_ip, lg->dst_ip, lg->src_port, 
		lg->dst_port, lg->reason, lg->count);
	++lg;
    }

    return 0;
}
