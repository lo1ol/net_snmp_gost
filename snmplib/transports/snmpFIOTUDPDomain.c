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

#define WE_ARE_SERVER 0
#define WE_ARE_CLIENT 1

oid             netsnmpFIOTUDPDomain[] = { TRANSPORT_DOMAIN_FIOT_UDP_IP };
size_t          netsnmpFIOTUDPDomain_len = OID_LENGTH(netsnmpFIOTUDPDomain);

static netsnmp_tdomain fiotudpDomain;

typedef struct fiot_cache_s {
   struct fiot_cache_s *next;
   struct netsnmp_sockaddr_storage *sas;
   struct fiot fctx;
} fiot_cache;

static fiot_cache *fiot_cache_list = NULL;

static fiot_cache *find_fiot_cache(const netsnmp_sockaddr_storage *from_addr)
{
    fiot_cache *cachep = NULL;

    for (cachep = fiot_cache_list; cachep; cachep = cachep->next) {

        if (cachep->sas.sa.sa_family != from_addr->sa.sa_family)
            continue;

        if ((from_addr->sa.sa_family == AF_INET) &&
            ((cachep->sas.sin.sin_addr.s_addr !=
              from_addr->sin.sin_addr.s_addr) ||
             (cachep->sas.sin.sin_port != from_addr->sin.sin_port)))
                continue;
        /* found an existing connection */
        break;
    }
    return cachep;
}

static int remove_fiot_cache(fiot_cache *thiscache)
{
    fiot_cache *cachep = NULL, *prevcache = NULL;

    cachep = fiot_cache_list;
    while (cachep) {
        if (cachep == thiscache) {

            /* remove it from the list */
            if (NULL == prevcache) {
                /* at the first cache in the list */
                fiot_cache_list = thiscache->next;
            } else {
                prevcache->next = thiscache->next;
            }

            return SNMPERR_SUCCESS;
        }
        prevcache = cachep;
        cachep = cachep->next;
    }
    return SNMPERR_GENERR;
}

/* frees the contents of a fiot_cache */
static void free_fiot_cache(fiot_cache *cachep)
{
    DEBUGMSGTL(("9:fiotudp:fiot_cache", "releasing %p\n", cachep));
    ak_fiot_context_destroy( &cachep->fctx );
    free(cachep);
}

static void remove_and_free_fiot_cache(fiot_cache *cachep)
{
    /** no debug, remove_fiot_cache does it */
    remove_fiot_cache(cachep);
    free_fiot_cache(cachep);
}

static fiot_cache *
start_new_cached_connection(netsnmp_transport *t,
                            struct sockaddr_in *remote_addr,
                            int we_are_client)
{
    fiot_cache *cachep = NULL;

    DEBUGTRACETOK("9:fiotudp");

    cachep = malloc(sizeof(fiot_cache));
    if (!cachep)
        return NULL;

   int rc;
    struct sockaddr_in cl_addr;
   ak_fiot ctx = &cachep->fctx;
   char msg; 
   int error = ak_error_ok, fd = -1;
   socklen_t opt = sizeof( cl_addr );
   fd=t->sock;
   
  /* часть вторая: аутентификация клиента и выполнение протокола выработки общих ключей */


  /* устанавливаем криптографические параметры взаимодействия и запускаем протокол выработки ключей */
  /* создаем контекст защищенного соединения */
   if(( error = ak_fiot_context_create( ctx )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect fiot context creation" );
        return NULL;
   }
   
   if (we_are_client) {
   	/* устанавливаем роль */
  	 if(( error = ak_fiot_context_set_role( ctx, client_role )) != ak_error_ok ) goto exit;
  	/* устанавливаем идентификатор сервера */
  	 if(( error = ak_fiot_context_set_user_identifier( ctx, server_role,
                                                 "serverID", 8 )) != ak_error_ok ) goto exit;
  	 if(( error = ak_fiot_context_set_user_identifier( ctx, client_role,
                             "Client with long identifier", 27 )) != ak_error_ok ) goto exit;

  	/* устанавливаем сокет для внешнего (шифрующего) интерфейса */
  	 if(( error = ak_fiot_context_set_interface_descriptor( ctx,
                                    encryption_interface, t->sock )) != ak_error_ok ) goto exit;
  	/* устанавливаем идентификатор ключа аутентификации */
  	 if(( error = ak_fiot_context_set_psk_identifier( ctx,
                                          ePSK_key, "12345", 5 )) != ak_error_ok ) goto exit;
  	 if(( error = ak_fiot_context_set_curve( ctx,
                              tc26_gost3410_2012_256_paramsetA )) != ak_error_ok ) goto exit;
  	 if(( error = ak_fiot_context_set_initial_crypto_mechanism( ctx,
                                             magmaGOST3413ePSK )) != ak_error_ok ) goto exit;
  	/* здесь реализация протокола */
  	 if(( error = ak_fiot_context_keys_generation_protocol( ctx )) != ak_error_ok ) goto exit;
   	 
	 printf( "echo-client: server authentication is Ok\n" );
   } else {
   	/* устанавливаем роль */
   	 if(( error = ak_fiot_context_set_role( ctx, server_role )) != ak_error_ok ) goto exit;
  	/* устанавливаем идентификатор сервера */
  	 if(( error = ak_fiot_context_set_user_identifier( ctx, server_role,
                                                       "serverID", 8 )) != ak_error_ok ) goto exit;
  	/* устанавливаем сокет для внешнего (шифрующего) интерфейса */
  	 if(( error = ak_fiot_context_set_interface_descriptor( ctx,
                                            encryption_interface, fd )) != ak_error_ok ) goto exit;
  	 if(( error = ak_fiot_context_set_client( ctx,
                                            *remote_addr )) != ak_error_ok ) goto exit;
  	/* устанавливаем набор криптографических алгоритмов для обмена зашифрованной информацией */
  	 if(( error =  ak_fiot_context_set_server_policy( ctx,
                                            magmaCTRplusGOST3413 )) != ak_error_ok ) goto exit;
  	/* теперь выполняем протокол */
  	 if(( error = ak_fiot_context_keys_generation_protocol( ctx )) != ak_error_ok ) goto exit;
  	 
	 printf( "echo-server: client authentication is Ok\n" );
   }
    


    DEBUGMSGTL(("fiotudp", "starting a new connection\n"));
    cachep->next = fiot_cache_list;
    fiot_cache_list = cachep;

    exit:

    return cachep;
}

static fiot_cache *
find_or_create_fiot_cache(netsnmp_transport *t,
                         struct netsnmp_sockaddr_storage *from_addr,
                         int we_are_client)
{
    fiot_cache *cachep = find_fiot_cache(from_addr);

    if (NULL == cachep) {
        /* none found; need to start a new context */
        cachep = start_new_cached_connection(t, from_addr, we_are_client);
        if (NULL == cachep) {
            snmp_log(LOG_ERR, "failed to open a new fiot connection\n");
        }
    } else {
        DEBUGMSGT(("9:fiotudp:fiot_cache:found", "%p\n", cachep));
    }
    return cachep;
}




static int
netsnmp_fiotudp_recv(netsnmp_transport *t, void *buf, int size,
                     void **opaque, int *olength)
{
   int             rc = -1;
   struct sockaddr_in cl_addr;
   char msg;
   int error = ak_error_ok, fd = -1;
   socklen_t opt = sizeof( cl_addr );
   ak_fiot ctx;
   
   if (ak_network_recvfrom(t->sock, &msg, 1, MSG_PEEK, &cl_addr, &opt) <= 0) {
                ak_error_message(ak_error_read_data, __func__, "wrong first client message receiving");
   		return rc;
   }

   rc = t->base_transport->f_recv(t, buf, size, &opaque, &olen);

   fiot_cache* cachep = find_or_create_fiot_cache(t, &cl_addr, WE_ARE_SERVER);
   ctx = &cachep->fctx;

   size_t length;
   message_t mtype = undefined_message;
   
   ak_uint8 *data = ak_fiot_context_read_frame( ctx, &length, &mtype );
   if( data != NULL ) {
     printf( "echo-server: recived length %lu\n", length );
   }

   *olength=length;
   *opaque = malloc(sizeof(netsnmp_tmStateReference));
   memcpy(*opaque, data, length);

  data = ak_fiot_context_read_frame( ctx, &length, &mtype );
   if( data != NULL ) {
     printf( "echo-server: recived length %lu\n", length );
   }

   memcpy(buf, data, length);
   rc = length;

   return rc;
}


static netsnmp_indexed_addr_pair *
_extract_addr_pair(netsnmp_transport *t, const void *opaque, int olen)
{
    if (opaque) {
        switch (olen) {
        case sizeof(netsnmp_tmStateReference): {
            const netsnmp_tmStateReference *tmStateRef = opaque;

            if (tmStateRef->have_addresses)
                return &tmStateRef->addresses;
            break;
        }
        default:
            netsnmp_assert(0);
        }
    }

    if (t && t->data) {
        switch (t->data_length) {
        case sizeof(netsnmp_indexed_addr_pair):
            return t->data;
        case sizeof(_netsnmpTLSBaseData): {
            _netsnmpTLSBaseData *tlsdata = t->data;

            return tlsdata->addr;
        }
        default:
            netsnmp_assert(0);
        }
    }

    return NULL;
}


static int
netsnmp_fiotudp_send(netsnmp_transport *t, const void *buf, int size,
                     void **opaque, int *olength)
{
    int error = ak_error_ok;
    int rc = -1;
    ak_fiot ctx;
    netsnmp_indexed_addr_pair* addr_pair;

    addr_pair = _extract_addr_pair(t, opaque ? *opaque : NULL, olength ? *olength : 0); 
    netsnmp_tmStateReference* tmStateRef = *opaque;
    tmStateRef->addresses = *addr_pair;
    tmStateRef->have_addresses = 1;
    tmStateRef->transportSecurityLevel = SNMP_SEC_LEVEL_AUTHPRIV;

    fiot_cache* cachep = find_or_create_fiot_cache(t, &addr_pair->remote_addr, WE_ARE_CLIENT);
    ctx = &cachep->fctx;

   if(( error = ak_fiot_context_write_frame( ctx, *opaque, *olength,
                                             encrypted_frame, application_data )) != ak_error_ok ) {
     ak_error_message( error, __func__, "write error" );
   } else {
           printf("echo-client: send %d bytes\n", *olength);
           rc = size;
   }

   if(( error = ak_fiot_context_write_frame( ctx, buf, size,
                                             encrypted_frame, application_data )) != ak_error_ok ) {
     ak_error_message( error, __func__, "write error" );
   } else {
	   printf("echo-client: send %d bytes\n", size);
   	   rc = size;
   }

  return rc;
}


static int
netsnmp_fiotudp_close(netsnmp_transport *t)
{
    return -1;
}

static char *
netsnmp_fiotudp_fmtaddr(netsnmp_transport *t, const void *data, int len,
                        const char *pfx,
                        char *(*fmt_base_addr)(const char *pfx,
                                               netsnmp_transport *t,
                                               const void *data, int len))
{
    if (!data) {
        data = t->data;
        len = t->data_length;
    }

    switch (data ? len : 0) {
    case sizeof(netsnmp_indexed_addr_pair):
        return netsnmp_ipv4_fmtaddr(pfx, t, data, len);
    case sizeof(netsnmp_tmStateReference): {
        const netsnmp_tmStateReference *r = data;
        const netsnmp_indexed_addr_pair *p = &r->addresses;
        netsnmp_transport *bt = t->base_transport;

        if (r->have_addresses) {
            return fmt_base_addr("FIOTUDP", t, p, sizeof(*p));
        } else if (bt && t->data_length == sizeof(_netsnmpTLSBaseData)) {
            _netsnmpTLSBaseData *tlsdata = t->data;
            netsnmp_indexed_addr_pair *tls_addr = tlsdata->addr;

            return bt->f_fmtaddr(bt, tls_addr, sizeof(*tls_addr));
        } else if (bt) {
            return bt->f_fmtaddr(bt, t->data, t->data_length);
        } else {
            return strdup("FIOTUDP: unknown");
        }
    }
    case sizeof(_netsnmpTLSBaseData): {
        const _netsnmpTLSBaseData *b = data;
        char *buf;

        if (asprintf(&buf, "FIOTUDP: %s", b->addr_string) < 0)
            buf = NULL;
        return buf;
    }
    case 0:
        return strdup("FIOTUDP: unknown");
    default: {
        char *buf;

        if (asprintf(&buf, "FIOTUDP: len %d", len) < 0)
            buf = NULL;
        return buf;
    }
    }
}

static char *
netsnmp_fiotudp4_fmtaddr(netsnmp_transport *t, const void *data, int len)
{
    return netsnmp_fiotudp_fmtaddr(t, data, len, "FIOTUDP",
                                   netsnmp_ipv4_fmtaddr);
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
    t->f_config        = netsnmp_tlsbase_config;
    t->f_setup_session = netsnmp_tlsbase_session_init;
    t->f_accept        = NULL;
    t->f_fmtaddr       = netsnmp_fiotudp4_fmtaddr;
    t->f_get_taddr     = netsnmp_ipv4_get_taddr;

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

    if (!local) {
        /* fiot needs to bind the socket for SSL_write to work */
        if (connect(t->sock, (const struct sockaddr *)addr, sizeof(*addr)) < 0)
            snmp_log(LOG_ERR, "fiot: failed to connect\n");
    }

    return t2;
}

netsnmp_transport *
netsnmp_fiotudp_create_tstring(const char *str, int isserver,
                               const char *default_target)
{
    struct netsnmp_ep ep;
    netsnmp_transport *t;
    char buf[SPRINT_MAX_LEN], *cp;
    _netsnmpTLSBaseData *tlsdata;

    if (netsnmp_sockaddr_in3(&ep, str, default_target))
        t = netsnmp_fiotudp_transport(&ep, isserver);
    else
        return NULL;
    
    /* see if we can extract the remote hostname */
    if (!isserver && t && t->data && str) {
        tlsdata = t->data;
        /* search for a : */
        if (NULL != (cp = strrchr(str, ':'))) {
            sprintf(buf, "%.*s", (int) SNMP_MIN(cp - str, sizeof(buf) - 1),
                    str);
        } else {
            /* else the entire spec is a host name only */
            strlcpy(buf, str, sizeof(buf));
        }
        tlsdata->their_hostname = strdup(buf);
    }

    return t;
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
    if( !ak_libakrypt_create( ak_function_log_syslog )) { ak_libakrypt_destroy(); return; } 
    ak_log_set_level( fiot_log_minimal );

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

    fiotudpDomain.f_create_from_tstring_new = netsnmp_fiotudp_create_tstring;
    fiotudpDomain.f_create_from_ostring     = netsnmp_fiotudp_create_ostring;

    netsnmp_tdomain_register(&fiotudpDomain);
}
