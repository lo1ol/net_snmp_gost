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
   char ip[16];
   struct sockaddr_in cl_addr;
   struct fiot ctx;
   char msg;
   int error = ak_error_ok, fd = -1;
   socklen_t opt = sizeof( cl_addr );
   if (ak_network_recvfrom(t->sock, &msg, 1, MSG_PEEK, &cl_addr, &opt) <= 0) {
                ak_error_message(ak_error_read_data, __func__, "wrong first client message receiving");
   		return rc;
   }

   if (ak_network_connect(t->sock, &cl_addr, opt) != ak_error_ok) {
                ak_error_message(error, __func__, "wrong UDP-connection to client address");
   		return rc;
   }
   fd = t->sock;

   if( ak_network_inet_ntop( AF_INET, &cl_addr.sin_addr, ip, (socklen_t) sizeof( ip )) == NULL ) {
	ak_error_message_fmt( -1, __func__,
                                        "can't determine client's address (%s)", strerror( errno ));
  	return rc;
   }
   printf( "echo-server: accepted client from %s:%u\n", ip, cl_addr.sin_port );


  /* часть вторая: аутентификация клиента и выполнение протокола выработки общих ключей */


  /* устанавливаем криптографические параметры взаимодействия и запускаем протокол выработки ключей */
  /* создаем контекст защищенного соединения */
   if(( error = ak_fiot_context_create( &ctx )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect fiot context creation" );
   	return rc;
   }

  /* устанавливаем роль */
   if(( error = ak_fiot_context_set_role( &ctx, server_role )) != ak_error_ok ) goto exit;
  /* устанавливаем идентификатор сервера */
   if(( error = ak_fiot_context_set_user_identifier( &ctx, server_role,
                                                       "serverID", 8 )) != ak_error_ok ) goto exit;
  /* устанавливаем сокет для внешнего (шифрующего) интерфейса */
   if(( error = ak_fiot_context_set_interface_descriptor( &ctx,
                                            encryption_interface, fd )) != ak_error_ok ) goto exit;
   if(( error = ak_fiot_context_set_client( &ctx,
                                            &cl_addr )) != ak_error_ok ) goto exit;
  /* устанавливаем набор криптографических алгоритмов для обмена зашифрованной информацией */
   if(( error =  ak_fiot_context_set_server_policy( &ctx,
                                            magmaCTRplusGOST3413 )) != ak_error_ok ) goto exit;
  /* теперь выполняем протокол */
   if(( error = ak_fiot_context_keys_generation_protocol( &ctx )) != ak_error_ok ) goto exit;
   printf( "echo-server: client authentication is Ok\n" );

   size_t length;
   message_t mtype = undefined_message;
   ak_uint8 *data = ak_fiot_context_read_frame( &ctx, &length, &mtype );
   if( data != NULL ) {
     data[length-1] = 0;
     printf( "echo-server: recived length %lu\n", length );
   }

   strncpy(buf, data, length);
   rc = length;

  exit:
   ak_fiot_context_destroy( &ctx );
   return rc;
}



static int
netsnmp_fiotudp_send(netsnmp_transport *t, const void *buf, int size,
                     void **opaque, int *olength)
{
    int error = ak_error_ok;
    int rc = -1;
    struct fiot ctx;
    struct sockaddr_in socket_address;

  /* создаем контекст защищенного соединения */
   if(( error = ak_fiot_context_create( &ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect context creation" );

  /* устанавливаем роль */
   if(( error = ak_fiot_context_set_role( &ctx, client_role )) != ak_error_ok ) goto exit;
  /* устанавливаем идентификатор сервера */
   if(( error = ak_fiot_context_set_user_identifier( &ctx, server_role,
                                                 "serverID", 8 )) != ak_error_ok ) goto exit;
   if(( error = ak_fiot_context_set_user_identifier( &ctx, client_role,
                             "Client with long identifier", 27 )) != ak_error_ok ) goto exit;

  /* устанавливаем сокет для внешнего (шифрующего) интерфейса */
   if(( error = ak_fiot_context_set_interface_descriptor( &ctx,
                                    encryption_interface, t->sock )) != ak_error_ok ) goto exit;
  /* устанавливаем идентификатор ключа аутентификации */
   if(( error = ak_fiot_context_set_psk_identifier( &ctx,
                                          ePSK_key, "12345", 5 )) != ak_error_ok ) goto exit;
   if(( error = ak_fiot_context_set_curve( &ctx,
                              tc26_gost3410_2012_256_paramsetA )) != ak_error_ok ) goto exit;
   if(( error = ak_fiot_context_set_initial_crypto_mechanism( &ctx,
                                             magmaGOST3413ePSK )) != ak_error_ok ) goto exit;
  /* здесь реализация протокола */
   if(( error = ak_fiot_context_keys_generation_protocol( &ctx )) != ak_error_ok ) goto exit;
   printf( "echo-client: server authentication is Ok\n" );

   if(( error = ak_fiot_context_write_frame( &ctx, buf, size,
                                             encrypted_frame, application_data )) != ak_error_ok ) {
     ak_error_message( error, __func__, "write error" );
   } else {
	   printf("echo-client: send %d bytes\n", size);
   	   rc = size;
   }
  exit:
   ak_fiot_context_destroy( &ctx );

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
    t->f_config        = netsnmp_tlsbase_config;
    t->f_setup_session = netsnmp_tlsbase_session_init;
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

    if (!local) {
        /* dtls needs to bind the socket for SSL_write to work */
        if (connect(t->sock, (const struct sockaddr *)addr, sizeof(*addr)) < 0)
            snmp_log(LOG_ERR, "dtls: failed to connect\n");
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

    if (netsnmp_sockaddr_in3(&ep, str, default_target))
        t = netsnmp_fiotudp_transport(&ep, isserver);
    else
        return NULL;

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
