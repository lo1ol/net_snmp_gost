/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright Copyright 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
/* 
 * See the following web pages for useful documentation on this transport:
 * http://www.net-snmp.org/wiki/index.php/TUT:Using_TLS
 * http://www.net-snmp.org/wiki/index.php/Using_FIOT
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-features.h>

netsnmp_feature_require(cert_util);
netsnmp_feature_require(sockaddr_size);

#include <net-snmp/library/snmpIPBaseDomain.h>
#include <net-snmp/library/snmpFIOTUDPDomain.h>
#include <net-snmp/library/snmpUDPIPv6Domain.h>
#include <net-snmp/library/snmp_assert.h>

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include "../memcheck.h"

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/config_api.h>

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/system.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/callback.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rand.h"

#include "libakrypt.h"
#include "ak_fiot.h"

#include <net-snmp/library/snmpSocketBaseDomain.h>
#include <net-snmp/library/snmpTLSBaseDomain.h>
#include <net-snmp/library/snmpUDPDomain.h>
#include <net-snmp/library/cert_util.h>
#include <net-snmp/library/snmp_openssl.h>

#ifndef INADDR_NONE
#define INADDR_NONE	-1
#endif


oid             netsnmpFIOTUDPDomain[] = { TRANSPORT_DOMAIN_FIOT_UDP_IP };
size_t          netsnmpFIOTUDPDomain_len = OID_LENGTH(netsnmpFIOTUDPDomain);

static netsnmp_tdomain fiotudpDomain;

static int
netsnmp_fiotudp_recv(netsnmp_transport *t, void *buf, int size,
                     void **opaque, int *olength)
{
    int             rc = -1;
    return rc;
}



static int
netsnmp_fiotudp_send(netsnmp_transport *t, const void *buf, int size,
                     void **opaque, int *olength)
{
    int rc = -1;
    return rc;
}



static int
netsnmp_fiotudp_close(netsnmp_transport *t)
{
    return -1;
}

static netsnmp_transport *
_transport_common(netsnmp_transport *t, int local)
{
    char *tmp = NULL;
    int tmp_len;

    DEBUGTRACETOK("9:fiotudp");

    if (NULL == t)
        return NULL;

    /** save base transport for clients; need in send/recv functions later */
    if (t->data) { /* don't copy data */
        tmp = t->data;
        tmp_len = t->data_length;
        t->data = NULL;
    }
    t->base_transport = netsnmp_transport_copy(t);

    if (tmp) {
        t->data = tmp;
        t->data_length = tmp_len;
    }
    if (NULL != t->data &&
        t->data_length == sizeof(netsnmp_indexed_addr_pair)) {
        _netsnmpTLSBaseData *tlsdata =
            netsnmp_tlsbase_allocate_tlsdata(t, local);
        tlsdata->addr = t->data;
        t->data = tlsdata;
        t->data_length = sizeof(_netsnmpTLSBaseData);
    }

    /*
     * Set Domain
     */
    t->domain = netsnmpFIOTUDPDomain;                                     
    t->domain_length = netsnmpFIOTUDPDomain_len;     

    t->f_recv          = netsnmp_fiotudp_recv;
    t->f_send          = netsnmp_fiotudp_send;
    t->f_close         = netsnmp_fiotudp_close;
    t->f_config        = NULL;
    t->f_setup_session = NULL;
    t->f_accept        = NULL;
    t->f_fmtaddr       = NULL;
    t->f_get_taddr     = NULL;

    t->flags = NETSNMP_TRANSPORT_FLAG_TUNNELED;

    return t;
}

netsnmp_transport *
netsnmp_fiotudp_transport(const struct netsnmp_ep *ep, int local)
{
    const struct sockaddr_in *addr = &ep->a.sin;
    netsnmp_transport *t, *t2;

    DEBUGTRACETOK("fiotudp");

    t = netsnmp_udp_transport(ep, local);
    if (NULL == t)
        return NULL;

    t2 = _transport_common(t, local);
    if (!t2) {
        netsnmp_transport_free(t);
        return NULL;
    }

    return t2;
}


netsnmp_transport *
netsnmp_fiotudp_create_ostring(const void *o, size_t o_len, int local)
{
    struct netsnmp_ep ep;

    memset(&ep, 0, sizeof(ep));
    if (netsnmp_ipv4_ostring_to_sockaddr(&ep.a.sin, o, o_len))
        return netsnmp_fiotudp_transport(&ep, local);
    else
        return NULL;
}

void
netsnmp_fiotudp_ctor(void)
{
    static const char indexname[] = "_netsnmp_addr_info";
    static const char *prefixes[] = { "fiotudp", "fiot"
    };
    int i, num_prefixes = sizeof(prefixes) / sizeof(char *);

    DEBUGMSGTL(("fiotudp", "registering FIOT constructor\n"));

    /* config settings */

    fiotudpDomain.name = netsnmpFIOTUDPDomain;
    fiotudpDomain.name_length = netsnmpFIOTUDPDomain_len;
    fiotudpDomain.prefix = calloc(num_prefixes + 1, sizeof(char *));
    for (i = 0; i < num_prefixes; ++ i)
        fiotudpDomain.prefix[i] = prefixes[i];

    fiotudpDomain.f_create_from_tstring_new = NULL;
    fiotudpDomain.f_create_from_ostring     = netsnmp_fiotudp_create_ostring;

    netsnmp_tdomain_register(&fiotudpDomain);
}
