/*
 * $Id: lilt.h,v 1.7 2002/01/02 02:43:02 route Exp $
 *
 * Building Open Source Network Security Tools
 * lilt.h - libnids example code
 *
 * Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <termios.h>
#include <ctype.h>
#include <time.h>
#include <nids.h>

/*
 * The following two structures taken from libnids sources need to be used
 * in the reporting function.
 */
struct scan {
  u_int			addr;
  unsigned short	port;
  u_char		flags;
};

struct host {
  struct host	*next;
  struct host	*prev;
  u_int		addr;
  int		modtime;
  int		n_packets;
  struct scan	*packets;
};

struct lilt_pack {
#define M_LEN		128         /* this should be more than enough */
  u_short		mon[M_LEN]; /* list of TCP WKP to monitor */
  u_char		flags;      /* control flags */
#define LP_CONN		0x01        /* there is a connection to watch */
#define LP_WATCH	0x02        /* watch this connection */
#define LP_KILL		0x04        /* kill this connection */
#define LP_DISCARD	0x08        /* discard this connection */
  struct tuple4		t;          /* tuple4 of the connection in question */
  int			tcp_count;  /* number of TCP connections seen */
  int			tcp_killed; /* number of TCP connections killed */
  int			ps_count;   /* number of port scans seen */
};

/* function prototypes */
char *cull_address(struct tuple4);
char *get_time();
int set_ports(char *);
void monitor_tcp(struct tcp_stream *, void *);
void report(int, int, void *, void *);
void command_summary();
void usage(char *);
int interesting(u_short);
void lock_tuple(struct tuple4);
int our_tuple(struct tuple4);
void process_command();

/* EOF */
