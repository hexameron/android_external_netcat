/* $OpenBSD: netcat.c,v 1.103 2011/10/04 08:34:34 fgsch Exp $ */
/*
 * Copyright (c) 2001 Eric Jackson <ericj@monkey.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Re-written nc(1) for OpenBSD. Original implementation by
 * *Hobbit* <hobbit@avian.org>.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include "atomicio.h"

#ifndef SUN_LEN
#define SUN_LEN(su) \
	(sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

#define PORT_MAX_LEN	6
#define UNIX_DG_TMP_SOCKET_SIZE	19

int uflag = 0;					/* UDP - Default to TCP */
int timeout = -1;
int family = AF_UNSPEC;
char *unix_dg_tmp_socket;

void	build_ports(char *);
void	help(void);
void	readwrite(int);
int	remote_connect(const char *, const char *, struct addrinfo);
int	timeout_connect(int, const struct sockaddr *, socklen_t);
void	usage(int);

int
main(int argc, char *argv[])
{
	int ch, s;
	char *host, *uport;
	struct addrinfo hints;

	s = 0;
	host = NULL;
	uport = NULL;

	while ((ch = getopt(argc, argv,
	    "uh")) != -1) {
		switch (ch) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'h':
			help();
			break;
		case 'u':
			uflag = 1;
			break;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	if (argv[0] && !argv[1]) {
		uport = argv[0];
		host = NULL;
	} else if (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} else
		usage(1);

	/* Initialize addrinfo structure. */
	{
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
	}

	s = remote_connect(host, uport, hints);
	if (s >= 0) {
		readwrite(s);
		close(s);
	}
	exit( 0 );
}

/* 48KHz very long wav header */
void writewavheader()
{
	char wavhead[] = {
	0x52,0x49, 0x46,0x46, 0x64,0x19, 0xff,0x7f, 0x57,0x41, 0x56,0x45, 0x66,0x6d, 0x74,0x20,
#if 0
	// 24kHz
	0x10,0x00, 0x00,0x00, 0x01,0x00, 0x01,0x00, 0xc0,0x5d, 0x00,0x00, 0xc0,0x5d, 0x00,0x00,
#else
	// 48kHz
	0x10,0x00, 0x00,0x00, 0x01,0x00, 0x01,0x00, 0x80,0xbb, 0x00,0x00, 0x80,0xbb, 0x00,0x00,
#endif
	0x02,0x00, 0x10,0x00, 0x64,0x61, 0x74,0x61, 0x40,0x19, 0xff,0x7f, 0x00,0x00, 0x00,0x00
	};
	// 0x18 is samplerate, 0x1c is rate * channels * bytes per sample
	atomicio(vwrite, fileno(stdout), wavhead, sizeof(wavhead));
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
int
remote_connect(const char *host, const char *port, struct addrinfo hints)
{
	struct addrinfo *res, *res0;
	int s, error;

	if ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		if ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

		if (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			break;

		close(s);
		s = -1;
	} while ((res0 = res0->ai_next) != NULL);

	freeaddrinfo(res);

	return (s);
}

int
timeout_connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	struct pollfd pfd;
	socklen_t optlen;
	int flags, optval;
	int ret;

	if (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	if ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		if ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = sizeof(optval);
			if ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} else if (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} else
			err(1, "poll failed");
	}

	if (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	return (ret);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor
 */
void
readwrite(int nfd)
{
	struct pollfd pfd;
	unsigned char buf[16384];
	int lfd = fileno(stdout);
	int n, plen;

	plen = 4096;

	/* Setup Network FD */
	pfd.fd = nfd;
	pfd.events = POLLIN;

	writewavheader();
	while (pfd.fd != -1) {

		if ((n = poll(&pfd, 1, timeout)) < 0) {
			close(nfd);
			err(1, "Polling Error");
		}

		if (n == 0)
			return;

		if (pfd.revents & POLLIN) {
			if ((n = read(nfd, buf, plen)) < 0)
				return;
			else if (n == 0) {
				shutdown(nfd, SHUT_RD);
				pfd.fd = -1;
				pfd.events = 0;
			} else {
				if (atomicio(vwrite, lfd, buf, n) != n)
					return;
			}
		}

	}
}

void
help(void)
{
	usage(0);
	fprintf(stderr, "\tCommand Summary:\n\
	\t-4		Use IPv4\n\
	\t-6		Use IPv6\n\
	\t-h		This help text\n\
	\t-u		UDP mode\n");
	exit(1);
}

void
usage(int ret)
{
	fprintf(stderr,
	    "usage: wavcat [-46uh]  [host] [port]\n");
	if (ret)
		exit(1);
}
