/* mini_httpd - small HTTP server
**
** Copyright © 1999,2000 by Jef Poskanzer <jef@acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/


#include "version.h"
#include "port.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef USE_SSL
#include <openssl/ssl.h>
#endif /* USE_SSL */

#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h> 
#endif 


#define ERR_DIR "errors"
#define DEFAULT_HTTP_PORT 80
#ifdef USE_SSL
#define DEFAULT_HTTPS_PORT 443
#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"
#endif /* USE_SSL */
#define DEFAULT_USER "nobody"
#define CGI_NICE 10
#define CGI_PATH "/usr/local/bin:/usr/ucb:/bin:/usr/bin"
#define CGI_LD_LIBRARY_PATH "/usr/local/lib:/usr/lib"
#define AUTH_FILE ".htpasswd"

#define METHOD_GET 1
#define METHOD_HEAD 2
#define METHOD_POST 3

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif


/* A multi-family sockaddr. */
typedef union {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
#ifdef HAVE_SOCKADDR_IN6
    struct sockaddr_in6 sa_in6;
#endif /* HAVE_SOCKADDR_IN6 */
#ifdef HAVE_SOCKADDR_STORAGE
    struct sockaddr_storage sa_stor;
#endif /* HAVE_SOCKADDR_STORAGE */
    } usockaddr;


static char* argv0;
static int debug;
static int port;
static int do_chroot;
static int vhost;
static char* user;
static char* cgi_pattern;
static char* hostname;
static char hostname_buf[500];
static u_int hostaddr;
static char* logfile;
static char* pidfile;
static FILE* logfp;
static int listen_fd;
#ifdef USE_SSL
static int do_ssl;
static SSL_CTX* ssl_ctx;
#endif /* USE_SSL */


/* Request variables. */
static int conn_fd;
#ifdef USE_SSL
static SSL* ssl;
#endif /* USE_SSL */
static usockaddr client_addr;
static char* request;
static int request_size, request_len, request_idx;
static int method;
static char* path;
static char* file;
struct stat sb;
static char* query;
static char* protocol;
static int status;
static long bytes;
static char* req_hostname;

static char* authorization;
static long content_length;
static char* content_type;
static char* cookie;
static char* host;
static time_t if_modified_since;
static char* referer;
static char* useragent;

static char* remoteuser;


/* Forwards. */
static void usage( void );
static void handle_request( void );
static void de_dotdot( char* file );
static void do_file( void );
static void do_dir( void );
static void do_cgi( void );
static void cgi_interpose_input( int wfd );
static void cgi_interpose_output( int rfd, int parse_headers );
static char** make_argp( void );
static char** make_envp( void );
static char* build_env( char* fmt, char* arg );
static void auth_check( char* dirname );
static void send_authenticate( char* realm );
static char* virtual_file( char* file );
static void send_error( int s, char* title, char* extra_header, char* text );
static void send_error_body( int s, char* title, char* text );
static int send_error_file( char* filename );
static void send_error_tail( void );
static void add_headers( int s, char* title, char* extra_header, char* mime_type, long b, time_t mod );
static void start_request( void );
static void add_to_request( char* str, int len );
static char* get_request_line( void );
static void start_response( void );
static void add_to_response( char* str, int len );
static void send_response( void );
static int my_read( char* buf, int size );
static int my_write( char* buf, int size );
static void add_to_buf( char** bufP, int* bufsizeP, int* buflenP, char* str, int len );
static void make_log_entry( void );
static char* get_method_str( int m );
static char* get_mime_type( char* name );
static void handle_sigterm( int sig );
static void handle_sigchld( int sig );
static void lookup_hostname( usockaddr* usaP, size_t sa_len );
static char* ntoa( usockaddr* usaP );
static size_t sockaddr_len( usockaddr* usaP );
static void strdecode( char* to, char* from );
static int hexit( char c );
static int b64_decode( const char* str, unsigned char* space, int size );
static int match( const char* pattern, const char* string );
static int match_one( const char* pattern, int patternlen, const char* string );


int
main( int argc, char** argv )
    {
    int argn;
    uid_t uid;
    usockaddr host_addr;
    usockaddr usa;
    int i, sz, r;

    /* Parse args. */
    argv0 = argv[0];
    debug = 0;
    port = -1;
    do_chroot = 0;
    vhost = 0;
    cgi_pattern = (char*) 0;
    user = DEFAULT_USER;
    hostname = (char*) 0;
    logfile = (char*) 0;
    pidfile = (char*) 0;
    logfp = (FILE*) 0;
#ifdef USE_SSL
    do_ssl = 0;
#endif /* USE_SSL */
    argn = 1;
    while ( argn < argc && argv[argn][0] == '-' )
	{
	if ( strcmp( argv[argn], "-D" ) == 0 )
	    debug = 1;
#ifdef USE_SSL
	else if ( strcmp( argv[argn], "-S" ) == 0 )
	    do_ssl = 1;
#endif /* USE_SSL */
	else if ( strcmp( argv[argn], "-p" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    port = atoi( argv[argn] );
	    }
	else if ( strcmp( argv[argn], "-c" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    cgi_pattern = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-u" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    user = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-h" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    hostname = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-r" ) == 0 )
	    do_chroot = 1;
	else if ( strcmp( argv[argn], "-v" ) == 0 )
	    vhost = 1;
	else if ( strcmp( argv[argn], "-l" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    logfile = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-i" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    pidfile = argv[argn];
	    }
	else
	    usage();
	++argn;
	}
    if ( argn != argc )
	usage();

    if ( port == -1 )
	{
#ifdef USE_SSL
	if ( do_ssl )
	    port = DEFAULT_HTTPS_PORT;
	else
	    port = DEFAULT_HTTP_PORT;
#else /* USE_SSL */
	port = DEFAULT_HTTP_PORT;
#endif /* USE_SSL */
	}

    if ( logfile != (char*) 0 )
	{
	/* Open the log file. */
	logfp = fopen( logfile, "a" );
	if ( logfp == (FILE*) 0 )
	    {
	    perror( logfile );
	    exit( 1 );
	    }
	}

    /* Look up hostname. */
    lookup_hostname( &host_addr, sizeof(host_addr) );
    if ( hostname == (char*) 0 )
	{
	(void) gethostname( hostname_buf, sizeof(hostname_buf) );
	hostname = hostname_buf;
	}

    /* Set up listen socket. */
    listen_fd = socket( host_addr.sa.sa_family, SOCK_STREAM, 0 );
    if ( listen_fd < 0 )
	{
	perror( "socket" );
	exit( 1 );
	}
    (void) fcntl( listen_fd, F_SETFD, 1 );
    i = 1;
    if ( setsockopt( listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*) &i, sizeof(i) ) < 0 )
	{
	perror( "setsockopt" );
	exit( 1 );
	}

    if ( bind( listen_fd, &host_addr.sa, sockaddr_len( &host_addr ) ) < 0 )
	{
	perror( "bind" );
	exit( 1 );
	}
    if ( listen( listen_fd, 1024 ) < 0 )
	{
	perror( "listen" );
	exit( 1 );
	}

#ifdef USE_SSL
    if ( do_ssl )
	{
	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new( SSLv23_server_method() );
	if ( SSL_CTX_use_certificate_file( ssl_ctx, CERT_FILE, SSL_FILETYPE_PEM ) == 0 ||
	     SSL_CTX_use_PrivateKey_file( ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM ) == 0 ||
	     SSL_CTX_check_private_key( ssl_ctx ) == 0 )
	    {
	    ERR_print_errors_fp( stderr );
	    exit( 1 );
	    }
	}
#endif /* USE_SSL */

    if ( ! debug )
	{
	/* Make ourselves a daemon. */
#ifdef HAVE_DAEMON
	if ( daemon( 1, 1 ) < 0 )
	    {
	    perror( "daemon" );
	    exit( 1 );
	    }
#else
	switch ( fork() )
	    {
	    case 0:
	    break;
	    case -1:
	    perror( "fork" );
	    exit( 1 );
	    default:
	    exit( 0 );
	    }
#ifdef HAVE_SETSID
	(void) setsid();
#endif
#endif
	}
    else
	{
	/* Even if we don't daemonize, we still want to disown our parent
	** process.
	*/
#ifdef HAVE_SETSID
	(void) setsid();
#endif /* HAVE_SETSID */
	}

    if ( pidfile != (char*) 0 )
        {
	/* Write the PID file. */
	FILE* pidfp = fopen( pidfile, "w" );
        if ( pidfp == (FILE*) 0 )
            {
	    perror( pidfile );
            exit( 1 );
            }
        (void) fprintf( pidfp, "%d\n", (int) getpid() );
        (void) fclose( pidfp );
        }

    /* Read zone info now, in case we chroot(). */
    tzset();

    /* If we're root, start becoming someone else. */
    if ( getuid() == 0 )
	{
	struct passwd* pwd;
	pwd = getpwnam( user );
	if ( pwd == (struct passwd*) 0 )
	    {
	    (void) fprintf( stderr, "%s: unknown user - '%s'\n", argv0, user );
	    exit( 1 );
	    }
	/* Set aux groups to null. */
	if ( setgroups( 0, (const gid_t*) 0 ) < 0 )
	    {
	    perror( "setgroups" );
	    exit( 1 );
	    }
	/* Set primary group. */
	if ( setgid( pwd->pw_gid ) < 0 )
	    {
	    perror( "setgid" );
	    exit( 1 );
	    }
	/* Try setting aux groups correctly - not critical if this fails. */
	if ( initgroups( user, pwd->pw_gid ) < 0 )
	    perror( "initgroups" );
#ifdef HAVE_SETLOGIN
	/* Set login name. */
	(void) setlogin( user );
#endif /* HAVE_SETLOGIN */
	/* Save the new uid for setting after we chroot(). */
	uid = pwd->pw_uid;
	}

    /* Chroot if requested. */
    if ( do_chroot )
	{
	char cwd[1000];
	(void) getcwd( cwd, sizeof(cwd) - 1 );
	if ( chroot( cwd ) < 0 )
	    {
	    perror( "chroot" );
	    exit( 1 );
	    }
	/* Always chdir to / after a chroot. */
	if ( chdir( "/" ) < 0 )
	    {
	    perror( "chroot chdir" );
	    exit( 1 );
	    }

	}

    /* If we're root, become someone else. */
    if ( getuid() == 0 )
	{
	/* Set uid. */
	if ( setuid( uid ) < 0 )
	    {
	    perror( "setuid" );
	    exit( 1 );
	    }
	/* Check for unnecessary security exposure. */
	if ( ! do_chroot )
	    (void) fprintf( stderr,
		"%s: started as root without requesting chroot(), warning only\n", argv0 );
	}

    /* Catch various termination signals. */
    (void) signal( SIGTERM, handle_sigterm );
    (void) signal( SIGINT, handle_sigterm );
    (void) signal( SIGHUP, handle_sigterm );
    (void) signal( SIGUSR1, handle_sigterm );

    /* Catch defunct children. */
    (void) signal( SIGCHLD, handle_sigchld );

    /* And get EPIPE instead of SIGPIPE. */
    (void) signal( SIGPIPE, SIG_IGN );

    /* Main loop. */
    for (;;)
	{
	sz = sizeof(usa);
	conn_fd = accept( listen_fd, &usa.sa, &sz );
	if ( conn_fd < 0 )
	    {
	    perror( "accept" );
	    exit( 1 );
	    }
	r = fork();
	if ( r < 0 )
	    {
	    perror( "fork" );
	    exit( 1 );
	    }
	if ( r == 0 )
	    {
	    /* Child process. */
	    client_addr = usa;
	    (void) close( listen_fd );
	    handle_request();
	    exit( 0 );
	    }
	(void) close( conn_fd );
	}
    }


static void
usage( void )
    {
#ifdef USE_SSL
    (void) fprintf( stderr, "usage:  %s [-S] [-p port] [-c cgipat] [-u user] [-h hostname] [-r] [-v] [-l logfile] [-i pidfile]\n", argv0 );
#else /* USE_SSL */
    (void) fprintf( stderr, "usage:  %s [-p port] [-c cgipat] [-u user] [-h hostname] [-r] [-v] [-l logfile] [-i pidfile]\n", argv0 );
#endif /* USE_SSL */
    exit( 1 );
    }


/* This runs in a child process, and exits when done, so cleanup is
** not needed.
*/
static void
handle_request( void )
    {
    char* method_str;
    char* line;
    char* cp;

    /* Initialize the request variables. */
    remoteuser = (char*) 0;
    method = -1;
    path = (char*) 0;
    file = (char*) 0;
    query = "";
    protocol = "HTTP/1.0";
    status = 0;
    bytes = -1;
    req_hostname = (char*) 0;

    authorization = (char*) 0;
    content_type = (char*) 0;
    content_length = -1;
    cookie = (char*) 0;
    host = (char*) 0;
    if_modified_since = (time_t) -1;
    referer = "";
    useragent = "";

#ifdef USE_SSL
    if ( do_ssl )
	{
	ssl = SSL_new( ssl_ctx );
	SSL_set_fd( ssl, conn_fd );
	if ( SSL_accept( ssl ) == 0 )
	    {
	    ERR_print_errors_fp( stderr );
	    exit( 1 );
	    }
	}
#endif /* USE_SSL */

    /* Read in the request. */
    start_request();
    for (;;)
	{
	char buf[10000];
	int r = my_read( buf, sizeof(buf) );
	if ( r <= 0 )
	    break;
	add_to_request( buf, r );
	if ( strstr( request, "\r\n\r\n" ) != (char*) 0 ||
	     strstr( request, "\n\n" ) != (char*) 0 )
	    break;
	}

    /* Parse the first line of the request. */
    method_str = get_request_line();
    path = strpbrk( method_str, " \t\n\r" );
    if ( path == (char*) 0 )
	send_error( 400, "Bad Request", (char*) 0, "Can't parse request." );
    *path++ = '\0';
    path += strspn( path, " \t\n\r" );
    protocol = strpbrk( path, " \t\n\r" );
    if ( protocol == (char*) 0 )
	send_error( 400, "Bad Request", (char*) 0, "Can't parse request." );
    *protocol++ = '\0';
    query = strchr( path, '?' );
    if ( query == (char*) 0 )
	query = "";
    else
	*query++ = '\0';

    /* Parse the rest of the request headers. */
    while ( ( line = get_request_line() ) != (char*) 0 )
	{
	if ( line[0] == '\0' )
	    break;
	else if ( strncasecmp( line, "Authorization:", 14 ) == 0 )
	    {
	    cp = &line[14];
	    cp += strspn( cp, " \t" );
	    authorization = cp;
	    }
	else if ( strncasecmp( line, "Content-Length:", 15 ) == 0 )
	    {
	    cp = &line[15];
	    cp += strspn( cp, " \t" );
	    content_length = atol( cp );
	    }
	else if ( strncasecmp( line, "Content-Type:", 13 ) == 0 )
	    {
	    cp = &line[13];
	    cp += strspn( cp, " \t" );
	    content_type = cp;
	    }
	else if ( strncasecmp( line, "Cookie:", 7 ) == 0 )
	    {
	    cp = &line[7];
	    cp += strspn( cp, " \t" );
	    cookie = cp;
	    }
	else if ( strncasecmp( line, "Host:", 5 ) == 0 )
	    {
	    cp = &line[5];
	    cp += strspn( cp, " \t" );
	    host = cp;
	    }
	else if ( strncasecmp( line, "If-Modified-Since:", 18 ) == 0 )
	    {
	    cp = &line[18];
	    cp += strspn( cp, " \t" );
	    if_modified_since = tdate_parse( cp );
	    }
	else if ( strncasecmp( line, "Referer:", 8 ) == 0 )
	    {
	    cp = &line[8];
	    cp += strspn( cp, " \t" );
	    referer = cp;
	    }
	else if ( strncasecmp( line, "User-Agent:", 11 ) == 0 )
	    {
	    cp = &line[11];
	    cp += strspn( cp, " \t" );
	    useragent = cp;
	    }
	}

    if ( strcasecmp( method_str, get_method_str( METHOD_GET ) ) == 0 )
	method = METHOD_GET;
    else if ( strcasecmp( method_str, get_method_str( METHOD_HEAD ) ) == 0 )
	method = METHOD_HEAD;
    else if ( strcasecmp( method_str, get_method_str( METHOD_POST ) ) == 0 )
	method = METHOD_POST;
    else
	send_error( 501, "Not Implemented", (char*) 0, "That method is not implemented." );

    strdecode( path, path );
    if ( path[0] != '/' )
	send_error( 400, "Bad Request", (char*) 0, "Bad filename." );
    file = &(path[1]);
    if ( file[0] == '\0' )
	file = "./";
    de_dotdot( file );
    if ( file[0] == '/' ||
	 ( file[0] == '.' && file[1] == '.' &&
	   ( file[2] == '\0' || file[2] == '/' ) ) )
	send_error( 400, "Bad Request", (char*) 0, "Illegal filename." );
    if ( vhost )
	file = virtual_file( file );

    if ( stat( file, &sb ) < 0 )
	send_error( 404, "Not Found", (char*) 0, "File not found." );
    if ( ! S_ISDIR( sb.st_mode ) )
	do_file();
    else
	{
	char idx[10000];
	if ( file[strlen(file) - 1] != '/' )
	    {
	    char location[10000];
	    (void) snprintf( location, sizeof(location), "Location: %s/", path );
	    send_error( 302, "Found", location, "Directories must end with a slash." );
	    }
	(void) snprintf( idx, sizeof(idx), "%sindex.html", file );
	if ( stat( idx, &sb ) >= 0 )
	    {
	    file = idx;
	    do_file();
	    }
	else
	    {
	    (void) snprin