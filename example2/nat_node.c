
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <pthread.h>
#include <signal.h>

#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <pwd.h>
#include <fcntl.h>
#include  <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <netdb.h>
#include <net/if.h>

typedef struct sockaddr_storage IP;
typedef struct sockaddr_in6 IP6;
typedef struct sockaddr_in IP4;
typedef unsigned char UCHAR;

#define FULL_ADDSTRLEN (INET6_ADDRSTRLEN + 8)

#define UDP_MAX_EVENTS 32
#define UDP_BUF 1460
#define CONF_EPOLL_WAIT 1000

#define DEFAULT_PORT "4568"


enum { PING, PONG, PUNCH_HELP, PUNCH_NOW };

int sockfd = -1;
int running = 1;
int own_id = 0;


struct MSG {
  int type;
  int own_id;
  int id; /* the id of the sender */
  IP addr;
};

struct Node {
  int id;
  IP addr;
  struct Node *next;
};

struct Node *nodes = NULL;


void cmd_to_args(char *str, int *argc, char **argv, int max_argv)
{
    int len, i;

    len = strlen(str);
    *argc = 0;

  /* Zero out white/control characters  */
    for(i = 0; i <= len; i++) {
    if (str[i] <= ' ') {
            str[i] = '\0';
    }
    }

  /* Record strings */
    for(i = 0; i <= len; i++) {

        if (str[i] == '\0') {
      continue;
    }

    if (*argc >= max_argv - 1) {
      break;
    }

        argv[*argc] = &str[i];
        *argc += 1;
        i += strlen(&str[i]);
    }

  argv[*argc] = NULL;
}


/* Compare two ip addresses */
int addr_equal(const IP *addr1, const IP *addr2)
{
  if (addr1->ss_family != addr2->ss_family) {
    return 0;
  } else if (addr1->ss_family == AF_INET) {
    const IP4 *a1 = (IP4 *)addr1;
    const IP4 *a2 = (IP4 *)addr2;
    return (memcmp(&a1->sin_addr, &a2->sin_addr, 4) == 0) && (a1->sin_port == a2->sin_port);
  } else if (addr1->ss_family == AF_INET6) {
    const IP6 *a1 = (IP6 *)addr1;
    const IP6 *a2 = (IP6 *)addr2;
    return (memcmp(&a1->sin6_addr, &a2->sin6_addr, 16) == 0) && (a1->sin6_port == a2->sin6_port);
  } else {
    return 0;
  }
}

int set_port(IP *addr, unsigned short port)
{
  if (addr->ss_family == AF_INET) {
    ((IP4 *)addr)->sin_port = htons(port);
  } else if (addr->ss_family == AF_INET6) {
    ((IP6 *)addr)->sin6_port = htons(port);
  } else {
    return 1;
  }
  return 0;
}

int get_port(IP *addr, unsigned short *port)
{
  if (addr->ss_family == AF_INET) {
    *port = ntohs(((IP4 *)addr)->sin_port);
  } else if (addr->ss_family == AF_INET6) {
    *port = ntohs(((IP6 *)addr)->sin6_port);
  } else {
    return 1;
  }
  return 0;
}

char* str_addr(IP *addr, char *addrbuf)
{
  char buf[INET6_ADDRSTRLEN+1];
  unsigned short port;

  switch(addr->ss_family) {
    case AF_INET6:
      port = ntohs(((IP6 *)addr)->sin6_port);
      inet_ntop(AF_INET6, &((IP6 *)addr)->sin6_addr, buf, sizeof(buf));
      sprintf(addrbuf, "[%s]:%d", buf, port);
      break;
    case AF_INET:
      port = ntohs(((IP4 *)addr)->sin_port);
      inet_ntop(AF_INET, &((IP4 *)addr)->sin_addr, buf, sizeof(buf));
      sprintf(addrbuf, "%s:%d", buf, port);
      break;
    default:
      sprintf(addrbuf, "<invalid address>");
  }
  return addrbuf;
}

int addr_parse(IP *addr, const char *addr_str, const char *port_str, int af)
{
  struct addrinfo hints;
  struct addrinfo *info = NULL;
  struct addrinfo *p = NULL;

  memset(&hints, '\0', sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = af;

  if (getaddrinfo(addr_str, port_str, &hints, &info) != 0) {
    printf("addr: '%s'\n", addr_str);
    printf("port: '%s'\n", port_str);
    return 1;
  }

  p = info;
  while (p != NULL) {
    if (p->ai_family == AF_INET6) {
      memcpy(addr, p->ai_addr, sizeof(IP6));
      freeaddrinfo(info);
      return 0;
    }
    if (p->ai_family == AF_INET) {
      memcpy(addr, p->ai_addr, sizeof(IP4));
      freeaddrinfo(info);
      return 0;
    }
    p = p->ai_next;
  }

  freeaddrinfo(info);
  return 1;
}

int addr_parse_full(IP *addr, const char *full_addr_str, const char* default_port, int af)
{
  char addr_buf[256];

  char *addr_beg, *addr_tmp;
  char *last_colon;
  const char *addr_str = NULL;
  const char *port_str = NULL;
  int len;

  len = strlen(full_addr_str);
  if (len >= (sizeof(addr_buf) - 1)) {
    /* address too long */
    return 1;
  } else {
    addr_beg = addr_buf;
  }

  memset(addr_buf, '\0', sizeof(addr_buf));
  memcpy(addr_buf, full_addr_str, len);

  last_colon = strrchr(addr_buf, ':');

  if (addr_beg[0] == '[') {
    /* [<addr>] or [<addr>]:<port> */
    addr_tmp = strrchr(addr_beg, ']');

    if (addr_tmp == NULL) {
      /* broken format */
      return 1;
    }

    *addr_tmp = '\0';
    addr_str = addr_beg + 1;

    if (*(addr_tmp+1) == '\0') {
      port_str = default_port;
    } else if (*(addr_tmp+1) == ':') {
      port_str = addr_tmp + 2;
    } else {
      /* port expected */
      return 1;
    }
  } else if (last_colon && last_colon == strchr(addr_buf, ':')) {
    /* <non-ipv6-addr>:<port> */
    addr_tmp = last_colon;
    if (addr_tmp) {
      *addr_tmp = '\0';
      addr_str = addr_buf;
      port_str = addr_tmp+1;
    } else {
      addr_str = addr_buf;
      port_str = default_port;
    }
  } else {
    /* <addr> */
    addr_str = addr_buf;
    port_str = default_port;
  }

  return addr_parse(addr, addr_str, port_str, af);
}

int net_set_nonblocking(int fd)
{
    int rc;
  int nonblocking = 1;

    rc = fcntl(fd, F_GETFL, 0);
    if (rc < 0)
        return -1;

    rc = fcntl(fd, F_SETFL, nonblocking?(rc | O_NONBLOCK):(rc & ~O_NONBLOCK));
    if (rc < 0)
        return -1;

    return 0;
}

int net_bind(
  const char *name,
  const char* addr,
  const char* port,
  const char* ifce,
  int protocol, int af
)
{
  char addrbuf[FULL_ADDSTRLEN+1];
  int sock;
  int val;
  IP sockaddr;

  if (af != AF_INET && af != AF_INET6) {
    printf("NET: Unknown address family value.");
    return -1;
  }

  if (addr_parse(&sockaddr, addr, port, af) != 0) {
    printf("NET: Failed to parse ip address '%s' and port '%s'.", addr, port);
    return -1;
  }

  if (protocol == IPPROTO_TCP) {
    sock = socket(sockaddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
  } else if (protocol == IPPROTO_UDP) {
    sock = socket(sockaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
  } else {
    sock = -1;
  }

  if (sock < 0) {
    printf("NET: Failed to create socket: %s", strerror(errno));
    return -1;
  }

  val = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
    printf("NET: Failed to set socket option SO_REUSEADDR: %s", strerror(errno));
    return -1;
  }

  if (ifce && setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifce, strlen(ifce))) {
    printf("NET: Unable to bind to device '%s': %s", ifce, strerror(errno));
    return -1;
  }

  if (af == AF_INET6) {
    val = 1;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) < 0) {
      printf("NET: Failed to set socket option IPV6_V6ONLY: %s", strerror(errno));
      return -1;
    }
  }

  if (bind(sock, (struct sockaddr*) &sockaddr, sizeof(IP)) < 0) {
    printf("NET: Failed to bind socket to address: '%s'", strerror(errno));
    close(sock);
    return -1;
  }

  if (net_set_nonblocking(sock) < 0) {
    printf("NET: Failed to make socket nonblocking: '%s'", strerror(errno));
    return -1;
  }

  if (protocol == IPPROTO_TCP && listen(sock, 5) < 0) {
    printf("NET: Failed to listen on socket: '%s'", strerror(errno));
    return -1;
  }

  printf(ifce ? "%s: Bind to %s, interface %s\n" : "%s: Bind to %s\n" ,
    name, str_addr(&sockaddr, addrbuf), ifce
  );

  return sock;
}

int is_own_addr(IP* addr)
{
  int fd;
  struct ifreq ifr;
  int af = AF_INET;
  
  if (addr->ss_family != af) {
    printf("error in is_own_addr");
    exit(1);
  }

  fd = socket(af, SOCK_DGRAM, 0);

  /* I want to get an IPv4 IP address */
  ifr.ifr_addr.sa_family = af;

  /* I want IP address attached to "eth0" */
  strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);

  ioctl(fd, SIOCGIFADDR, &ifr);

  close(fd);

  return memcmp(&((IP4 *)&ifr.ifr_addr)->sin_addr, &((IP4*)addr)->sin_addr, 4) == 0;
 
  
  return 0;
}

typedef void fd_callback(int rc, int fd, time_t now);

struct task {
  int fd;
  fd_callback *callback;
};

struct task tasks[8];
int numtasks = 0;

void task_add(int fd, fd_callback *callback)
{
  tasks[numtasks].fd = fd;
  tasks[numtasks].callback = callback;
  numtasks++;
}

void *run_loop(void *_)
{
  int val;
  int i;
  int rc;
  fd_set fds_working;
  fd_set fds;
  int max_fd = -1;

  struct timeval tv;
  struct timeval time_now;

  FD_ZERO(&fds);
  FD_ZERO(&fds_working);

  for(i = 0; i < numtasks; ++i) {
    struct task *t = &tasks[i];
    if (t->fd > max_fd) {
      max_fd = t->fd;
    }
    FD_SET(t->fd, &fds);
  }

  while (running) {
    gettimeofday(&time_now, NULL);

        tv.tv_sec = 0;
        tv.tv_usec = 500000;

    memcpy(&fds_working, &fds, sizeof(fds));

    rc = select(max_fd + 1, &fds_working, NULL, NULL, &tv);
    
    if (rc < 0) {
      if (errno == EINTR) {
        printf("NET: EINTR\n");
        continue;
      } else {
        printf("NET: Error using select: %s\n", strerror(errno));
        return NULL;
      }
    }

    for(i = 0; i < numtasks; ++i) {
      struct task *t = &tasks[i];
      if (rc == 0) {
        t->callback(0, t->fd, time_now.tv_sec);
      } else if (FD_ISSET(t->fd, &fds_working)) {
        t->callback(rc, t->fd, time_now.tv_sec );
      }
    }
  }
  return NULL;
}

struct Node *find_node_by_addr(IP *addr)
{
  struct Node *n = nodes;
  while (n != NULL) {
    if (addr_equal(&n->addr, addr)) {
      return n;
    }
    n = n->next;
  }
  return NULL;
}

struct Node *find_node_by_id(int id)
{
  struct Node *n = nodes;
  while (n != NULL) {
    if (n->id == id) {
      return n;
    }
    n = n->next;
  }
  return NULL;
}

void add_node(int id, IP *addr)
{
  char addrbuf[128];
  struct Node *n;
  struct Node *new;

  /* after hole punching the port will have changed for our own connection */
  n = find_node_by_id(id);
  if (n != NULL) {
    memcpy(&n->addr, addr, sizeof(IP));
    return;
  }
  
  //printf("add_node: %s  [%d]\n", str_addr(addr, addrbuf), id);

  new = calloc(1, sizeof(struct Node));
  n = nodes;

  new->id = id;
  memcpy(&new->addr, addr, sizeof(IP));
  
  if (nodes == NULL) {
    nodes = new;
  } else while (n != NULL) {
    if (n->next == NULL) {
      n->next = new;
      break;
    }
    n = n->next;
  }
}

/* 
  We want a server that is not behind a NAT or that
  is at least connected to both other peers.
  
  We choose the first node that is not addr.
  This is a very broken approach. :/
*/
struct Node *find_server(IP *addr)
{
  struct Node *n = nodes;
  
  while (n) {
    if (!addr_equal(addr, &n->addr)) {
      return n;
    }
    
    n = n->next;
  }
  
  return NULL;
}

/* Request a 'server' to coordinate the hole punching between me and addr. */
void request_punch_help(int sock, IP *addr)
{
  char addrbuf1[128];
  char addrbuf2[128];
  struct MSG msg;

  struct Node *s = find_server(addr);
  if (s == NULL) {
    printf("could not find server for %s\n", str_addr(addr, addrbuf1));
    return;
  }
  
  msg.type = PUNCH_HELP;
  msg.own_id = own_id;
  memcpy(&msg.addr, addr, sizeof(IP));

  int rc = sendto(sock, &msg, sizeof(struct MSG), 0, (struct sockaddr *) &s->addr, sizeof(IP));
  printf("send request to %s to coordinate punching beween me and %s\n", str_addr(&s->addr, addrbuf1), str_addr(addr, addrbuf2));
}

void send_ping(int sock, IP *addr)
{
  char addrbuf[128];
  struct MSG msg;

  memset(&msg, 0, sizeof(msg));
  msg.type = PING;
  msg.own_id = own_id;
  
  printf("send ping to %s\n", str_addr(addr, addrbuf));
  int rc = sendto(sock, &msg, sizeof(struct MSG), 0, (struct sockaddr *)addr, sizeof(IP));
  if (rc  < 0) {
    printf("error: %s\n", strerror(rc));
  }
}

/* Instruct both that they should start sending each otehr udp packets in order to punch a hole. */
void send_punch_now(int sock, IP *send_to, int id, IP *addr)
{
  char addrbuf1[128];
  char addrbuf2[128];
  struct MSG msg;

  msg.type = PUNCH_NOW;
  msg.own_id = own_id;
  msg.id = id;
  memcpy(&msg.addr, addr, sizeof(IP));
  
  printf("Send map request to %s to punch %s\n", str_addr(send_to, addrbuf1), str_addr(addr, addrbuf2));
  
  int rc = sendto(sock, &msg, sizeof(struct MSG), 0, (struct sockaddr *)send_to, sizeof(IP));
  if (rc  < 0) {
    printf("error: %s\n", strerror(rc));
  }
}

const char * type2str(int t)
{
  switch(t) {
    case PONG: return "PONG";
    case PUNCH_NOW: return "PUNCH_NOW";
    case PING: return "PING";
    case PUNCH_HELP: return "PUNCH_HELP";
    default: return "<unknown>";
  }
}

void ping_all_nodes(int sock)
{
  struct Node *node = nodes;
  while (node) {
    send_ping(sock, &node->addr);
    node = node->next;
  }
}

void client_handle(int rc, int sock, time_t now)
{
  char buf[512];
  char addrbuf[128];
  socklen_t addrlen_ret;
  struct MSG msg;
  IP punch_addr;
  IP c_addr;
  IP *addr;
  struct Node *a;
  struct Node *b;
  int i;
  
  memset(&c_addr, '\0', sizeof(IP));
  memset(buf, '\0', sizeof(buf));
  addrlen_ret = sizeof(IP);
  rc = recvfrom(sock, buf, sizeof(buf)-1, 0, (struct sockaddr *) &c_addr, &addrlen_ret);

  if (rc <= 0) {
    return;
  }

  if (rc != sizeof(struct MSG)) {
    printf("Invalid packet size received.\n");
    return;
  }
  
  if (msg.own_id == own_id) {
    return;
  }

  memcpy(&msg, buf, rc);

  printf("#received packet#\n");
  printf("c_addr: %s\n", str_addr(&c_addr, addrbuf));
  printf("msg.type: %s\n", type2str(msg.type));
  printf("msg.own_id: %d\n", msg.own_id);
  printf("msg.id: %d\n", msg.id);
  printf("msg.addr: %s\n\n", str_addr(&msg.addr, addrbuf));

  switch(msg.type) {
    case PONG:
      add_node(msg.own_id, &c_addr);
      break;
    case PING:
      add_node(msg.own_id, &c_addr);
      
      msg.type = PONG;
      msg.own_id = own_id;
      memcpy(&msg.addr, &c_addr, sizeof(IP));

      sendto(sock, &msg, sizeof(struct MSG), 0, (struct sockaddr *)&c_addr, sizeof(IP));
      break;
    case PUNCH_NOW:
      memcpy(&punch_addr, &msg.addr, sizeof(IP));
      
      unsigned short port = 0;
      get_port(&punch_addr, &port);
      
      /* The actual hole punching.
        We don't know on what port the other router will expect our packets.
        So we test several ports starting from the port that the server is allowed
        to use to contact the other peer.
      */
      for(i = 0; i < 10; i++) {
        set_port(&punch_addr, port + i);
        send_ping(sock, &punch_addr);
      }
      break;
    case PUNCH_HELP: //received from the "server"
      //b sends us this request to help to make contact to a
      //the server must have a and b in his own record
      a = find_node_by_addr(&msg.addr);
      b = find_node_by_id(msg.own_id);
      
      if (a == NULL) {
        printf("(E) sender addr not found!\n");
        break;
      }

      if (b == NULL) {
        printf("(E) own id not found!\n");
        break;
      }
      
      if (b->id == a->id) {
        printf("(E) Id is the same\n");
        break;
      }

      send_punch_now(sock, &b->addr, a->id, &a->addr);
      send_punch_now(sock, &a->addr, b->id, &b->addr);
      break;
    default: ;
  }
}

void cmd_handle(int rc, int sock, time_t now)
{
  char addrbuf[128];
  char request[512];
  char* argv[32];
  int argc;
  IP addr;

  if (rc <= 0) {
    return;
  }
  
  fgets(request, sizeof(request), stdin);
  
  cmd_to_args(request, &argc, &argv[0], 32);
  
  if (argc == 1 && strcmp(argv[0], "q") == 0) {
    //quiet
    printf("exit now\n");
    running = 0;
  } else if (argc == 1 && strcmp(argv[0], "d") == 0) {
    //debug
    struct Node *n = nodes;
    int i = 0;
    while (n) {
      printf(" %s | %d\n", str_addr(&n->addr, addrbuf), n->id);
      i += 1;
      n = n->next;
    }
    printf("%d nodes\n", i);
  } else if (argc == 2 && strcmp(argv[0], "p") == 0) {
    //ping
    rc = addr_parse_full(&addr, argv[1], DEFAULT_PORT, AF_INET);
    if (rc == 0) {
      send_ping(sockfd, &addr);
    } else {
      printf("Failed to parse address.\n");
    }
  } else if (argc == 2 && strcmp(argv[0], "c") == 0) {
    //connect
    rc = addr_parse_full(&addr, argv[1], DEFAULT_PORT, AF_INET);
    if (rc == 0) {
      request_punch_help(sockfd, &addr);
    } else {
      printf("Failed to parse address.\n");
    }
  } else {
    printf(
      "Usage:\n"
      "[p]ing <ip_addr>:[port]\n"
      "[c]onnect <ip_addr>:[port]\n"
      "[d]ebug\n"
      "[q]uit\n\n"
    );
  }
}

int main(int argc, char **argv)
{
  char addrbuf[128];
  int rc;
  int i;
  IP c_addr;

  srand (time(NULL));
  
  own_id = rand() % 1000;
  printf("own_id %d\n", own_id);

  sockfd = net_bind("client", "0.0.0.0", DEFAULT_PORT, NULL, IPPROTO_UDP, AF_INET);
  task_add(sockfd, &client_handle);
  
  task_add(STDIN_FILENO, &cmd_handle);
  
  pthread_t run_thread;
  pthread_attr_t attr;

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  pthread_create(&run_thread, &attr, &run_loop, NULL);
  
  pthread_join(run_thread, NULL);
  
  return 0;
}
