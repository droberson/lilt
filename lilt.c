/*
 * $Id: lilt.c,v 1.10 2002/01/02 03:21:27 route Exp $
 *
 * Building Open Source Network Security Tools
 * lilt.c - libnids example source
 *
 * Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 * All rights reserved.
 *
 */

#include "lilt.h"

struct lilt_pack lp;

int main(int argc, char *argv[]) {
  int			c, fd;
  fd_set		read_set;
  struct termios	term;


  memset(&lp, 0, sizeof(lp));

  while ((c = getopt(argc, argv, "m:")) != EOF) {
    switch (c) {
    case 'm':
      /*
       * Set the ports to be monitored. We want them to be
       * of the format x,y,z. If we wanted, we could use
       * libnet's port list chaining functionality here to
       * be more robust.
       */
      if (set_ports(optarg) == -1) {
	fprintf(stderr, "set_ports(): bad port list\n");
	exit(EXIT_FAILURE);
      }
      break;
    default:
      usage(argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  printf("Lilt 1.0 [the littlest network watcher]\n");

  if (lp.mon[0] == 0) {
    /* if the user specified no ports to look for, use these */
    lp.mon[0] = 23;
    lp.mon[1] = 6667;
  }

  /*
   * Change the following libnids defaults:
   * scan_num_ports: 7
   * Slightly more sensitive than the default of 10.
   * syslog: report
   * Use our own function rather than syslog to report portscans.
   * pcap_filter: "tcp"
   * Limit libnids to capturing TCP packets only.
   */
  nids_params.scan_num_ports = 7;
  nids_params.syslog         = report;
  nids_params.pcap_filter    = "tcp";

  /* initialize the library */
  if (nids_init() == 0) {
    fprintf(stderr, "nids_init() failed: %s\n", nids_errbuf);
    exit(EXIT_FAILURE);
  }

  /*
   * Register the TCP callback. We could stack more TCP callback
   * functions here but in this sample program we only have one.
   */
  nids_register_tcp(monitor_tcp);
  printf("TCP monitoring callback registered\n");
  printf("Monitoring connections to the following ports: ");
  for (c = 0; lp.mon[c]; c++) {
    printf("%d ", lp.mon[c]);
  }

  printf("\nLibnids engine initialized, waiting for events...\n");

  /*
   * We want to change the behavior of stdin to not echo characters
   * typed and more importantly we want each character to be handed
   * off as soon as it is pressed (not waiting for \r). To do this
   * we have to manipulate the termios structure and change the
   * normal behavior of stdin. First we get the current terminal
   * state of stdin. If any of this fails, we'll warn, but not quit.
   */
  c = tcgetattr(STDIN_FILENO, &term);
  if (c == -1) {
    perror("main(): tcgetattr():");
    /* nonfatal */
  } else {
    /* disable canonical mode and terminal echo */
    term.c_lflag &= ~ICANON;
    term.c_lflag &= ~ECHO;

    /* set our changed state "NOW" */
    c = tcsetattr(STDIN_FILENO, TCSANOW, &term);
    if (c == -1) {
      perror("main(): tcsetattr():");
      /* nonfatal */
    }
  }

  /*
   * Lilt is driven by commands from the user and input from the
   * network. Since we want to monitor for both at the "same time"
   * we need to do synchronous I/O multiplexing across these two
   * input streams. We'll watch the libnids descruiptor to see if
   * there is any network traffic we need to pay attention to and
   * also we monitor stdin to see if the user hits a key we need to
   * process. To do this, we call nids_getfd() to get the underlying
   * network file descriptor (which is really a wrapper to
   * pcap_fileno()). Then we call nids_next() in conjunction with
   * select().
   */
  for (fd = nids_getfd();;) {
    FD_ZERO(&read_set);
    FD_SET(fd, &read_set);
    FD_SET(STDIN_FILENO, &read_set);

    /* check the status of our file descriptors */
    c = select(fd + 1, &read_set, 0, 0, NULL);
    if (c > 0) {
      /* input from libnids? */
      if (FD_ISSET(fd, &read_set)) {
	/*
	 * nids_next() handles the calling of our callback
	 * function.
	 */
	if (nids_next() == 0) {
	  /* non-fatal, pcap_next() probably returned NULL */
	  continue;
	}
      }

      /* input from the user? */
      if (FD_ISSET(STDIN_FILENO, &read_set)) {
	/* hand the keypress off to be processed */
	process_command(argv[0]);
      }
    }
    if (c == -1) {
      perror("select: ");
    }
  }
  /* NOT REACHED */
  return EXIT_SUCCESS;
}

int set_ports(char *list) {
  u_short	p;
  u_char	*q;
  int		i;

  q = list;

  /* pull out ports and stick them in our port list array */
  for (i = 0; q; i++) {
    if (i > M_LEN) {
      /* list too long */
      return -1;
    }
    p = atoi(q);
    if (p == 0) {
      return -1;
    }
    else {
      lp.mon[i] = p;
    }
    if ((q = strchr(q, (char)','))) {
      *q = '\0';
      q++;
    }
  }
  return 1;
}

void report(int type, int err, void *unused, void *data) {
  int		i;
  char		buf[BUFSIZ];
  struct host	*offender;

  /* port scan warning? */
  if (type == NIDS_WARN_SCAN) {
    lp.ps_count++;
    offender = (struct host *)data;
    fprintf(stderr, "\n-[%s: portscan detected from %s]-\n",
	    get_time(),
	    inet_ntoa(*((struct in_addr *)&offender->addr)));

    /* pull out IPs and ports scanned */
    for (memset(buf, 0, BUFSIZ), i = 0; i < offender->n_packets; i++) {
      sprintf(buf + strlen(buf), " %s",
	      inet_ntoa(*((struct in_addr *)&offender->packets[i].addr)));
      sprintf(buf + strlen(buf), ":%hi", offender->packets[i].port);
      strcat(buf, "\n");
    }
    fprintf(stderr, "%s", buf);
  }
}

void monitor_tcp(struct tcp_stream *stream, void *unused) {
  int			i;
  struct half_stream	*half;

  /*
   * First check to see if we have a connection we're watching
   * and the user presses 'D' to discard it.
   */
  if (lp.flags & LP_DISCARD) {
    /* clear out all the state for this connection */
    lp.flags &= ~LP_DISCARD;
    lp.flags &= ~LP_WATCH;
    lp.flags &= ~LP_KILL;
    memset(&lp.t, 0, sizeof(lp.t));
  }

  /* TCP SYN packet */
  if (stream->nids_state == NIDS_JUST_EST) {
    /* if we already have a connection in scope, ignore this one */
    if (lp.flags & LP_CONN) {
      return;
    }

    /* see if this connection is to a port we're monitoring */
    if (!interesting(stream->addr.dest)) {
      return;
    }

    /* lock this conneciton in scope */
    lock_tuple(stream->addr);
    lp.flags |= LP_CONN;

    lp.tcp_count++;
    fprintf(stderr, "\n-[%s: TCP connection: %s]-\n",
	    get_time(),
	    cull_address(stream->addr));

    /* we want data from both ends of the connection */
    stream->client.collect++;
    stream->server.collect++;
    return;
  }

  /* TCP FIN or RST packet */
  if (stream->nids_state == NIDS_CLOSE || stream->nids_state == NIDS_RESET) {
    /* if this isn't data from our locked connection return */
    if (!our_tuple(stream->addr)) {
      return;
    }
    fprintf (stderr, "\n-[%s: TCP connection terminated]-\n", get_time());

    if (lp.flags & LP_KILL) {
      /* we were set to kill this connection. increment counter */
      lp.tcp_killed++;
    }

    /* clear out all the state for this connection */
    lp.flags &= ~LP_CONN;
    lp.flags &= ~LP_WATCH;
    lp.flags &= ~LP_KILL;
    memset(&lp.t, 0, sizeof(lp.t));
    return;
  }

  /* TCP data packet */
  if (stream->nids_state == NIDS_DATA) {
    /* if this isn't data from our locked connection return */
    if (!our_tuple(stream->addr)) {
      return;
    }
    if (stream->client.count_new) {
      half = &stream->client;
    } else {
      half = &stream->server;
    }
    /* if we're not set to watch the connection, return */
    if (!(lp.flags & LP_WATCH)) {
      return;
    }
    if (lp.flags & LP_KILL) {
      /* kill the connection */
      nids_killtcp(stream);
      /* dump the rest of the data */
      nids_discard(stream, half->count_new);
      return;
    }
    for (i = 0; i < half->count_new; i++) {
      /* we only want to print characters that are printable! */
      if (isascii(half->data[i])) {
	fprintf(stderr, "%c", half->data[i]);
      }
    }
  }
}

/* peel off the character and process it */
void process_command() {
  int	i;
  char	buf[1];

  if (read(STDIN_FILENO, buf, 1) == -1) {
    perror("read error:");
    return;
  }

  switch (toupper(buf[0])) {
  case '?':
    /* help */
    command_summary();
    break;
  case 'D':
    /* if we have a conneciton, discard it */
    if (lp.flags & LP_DISCARD) {
      /* got it the first time you typed it dorkus! */
      return;
    }
    if (lp.flags & LP_CONN) {
      lp.flags |= LP_DISCARD;
      lp.flags &= ~LP_CONN;
      fprintf(stderr, "\n-[discarded connection]-\n");
    }
    break;
  case 'K':
    /* if we have a connection, kill it */
    if (lp.flags & LP_KILL) {
      /* got it the first time you typed it dorkus! */
      return;
    }
    if (lp.flags & LP_CONN) {
      lp.flags |= LP_KILL;
      fprintf(stderr, "\n-[killing connection]-\n");
    }
    break;
  case 'P':
    /* ports we're watching */
    fprintf(stderr, "\n-[lite monitor ports]-\n");
    for (i = 0; lp.mon[i]; i++) {
      fprintf(stderr, "%d ", lp.mon[i]);
    }
    fprintf(stderr, "\n");
    break;
  case 'Q':
    /* quit */
    fprintf(stderr, "\n-[later dorkus!]-\n");
    exit(EXIT_SUCCESS);
  case 'S':
    /* statistics */
    fprintf(stderr, "\n-[lilt statistics]-\n");
    fprintf(stderr, "TCP connections:\t%d\n", lp.tcp_count);
    fprintf(stderr, "TCP connections killed:\t%d\n", lp.tcp_killed);
    fprintf(stderr, "port scans detected:\t%d\n", lp.ps_count);
    break;
  case 'W':
    /* if we have a connection, watch it */
    if (lp.flags & LP_CONN) {
      lp.flags |= LP_WATCH;
      fprintf(stderr, "\n-[watching connection]-\n");
    }
    break;
  default:
    break;
  }
}

/* basically pulled from libnids sample code */
char *cull_address(struct tuple4 addr) {
  static char	buf[256];

  strcpy(buf, inet_ntoa(*((struct in_addr *)&addr.saddr)));
  sprintf(buf + strlen(buf), ".%d -> ", addr.source);
  strcat(buf, inet_ntoa(*((struct in_addr *)&addr.daddr)));
  sprintf(buf + strlen(buf), ".%d", addr.dest);

  return buf;
}

int interesting(u_short port) {
  int	i;

  /* check our TCP WKP list for the port in question */
  for (i = 0; lp.mon[i]; i++) {
    if (lp.mon[i] == port) {
      return 1;
    }
  }
  return 0;
}

int our_tuple(struct tuple4 addr) {
  /* check to see if this packet belongs to us */
  if (addr.source == lp.t.source && addr.dest == lp.t.dest &&
      addr.saddr == lp.t.saddr && addr.daddr == lp.t.daddr) {
    return 1;
  } else if (addr.source == lp.t.dest && addr.dest == lp.t.source &&
	     addr.saddr == lp.t.saddr && addr.daddr == lp.t.daddr) {
    return 1;
  } else {
    return 0;
  }
}

void lock_tuple(struct tuple4 addr) {
  /* lock this tuple in to our radar */
  lp.t.source = addr.source;
  lp.t.dest = addr.dest;
  lp.t.saddr = addr.saddr;
  lp.t.daddr = addr.daddr;
}

char *get_time() {
  int		i;
  time_t	t;
  static char	buf[26];

  t = time((time_t *)NULL);
  strcpy(buf, ctime(&t));

  /* cut out the day, year, and \n */
  for (i = 0; i < 20; i++) {
    buf[i] = buf[i + 4];
  }

  buf[15] = 0;

  return buf;
}

void usage(char *name) {
  fprintf(stderr,
	  "usage: %s\n"
	  "-m ports\tList of TCP ports to monitor (x,y,z)\n",
	  name);
}

void command_summary() {
  /* print the commands that are available to the user in brackets */
  fprintf(stderr, "\n-[lilt command summary]-\n[?] - this blurb\n");
  if (lp.flags & LP_CONN) {
    fprintf(stderr, "[d] - discard connection from scope\n");
    fprintf(stderr, "[k] - kill connection in scope\n");
  } else {
    fprintf(stderr, " d  - discardconnection from scope\n");
    fprintf(stderr, " k  - kill connection in scope\n");
  }
  fprintf(stderr, "[p] - display ports being monitored\n");
  fprintf(stderr, "[q] - quit lilt\n");
  fprintf(stderr, "[s] - statistics\n");
  if (lp.flags & LP_CONN) {
    fprintf(stderr, "[w] - watch connection in scope\n");
  } else {
    fprintf(stderr, " w  - watch connection in scope\n");
  }
}

/* EOF */

