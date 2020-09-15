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

#define CLOSE_CONNECTION_MSG "Close connection"

oid             netsnmpFIOTUDPDomain[] = { TRANSPORT_DOMAIN_FIOT_UDP_IP };
size_t          netsnmpFIOTUDPDomain_len = OID_LENGTH(netsnmpFIOTUDPDomain);

static struct skey blom_key_;
static ak_skey blom_key = NULL;

static elliptic_curve_t elliptic_curve_type = tc26_gost3410_2012_256_paramsetA;
static crypto_mechanism_t crypto_mechanism_type = magmaGOST3413ePSK;
static crypto_mechanism_t server_policy_type = magmaCTRplusGOST3413;

static elliptic_curve_t string_to_elliptic_curve_t (char* str)
{
    if ( strcmp("tc26_gost3410_2012_256_paramsetA", str) == 0 )
	    return tc26_gost3410_2012_256_paramsetA;
    if ( strcmp("tc26_gost3410_2012_512_paramsetA", str) == 0 )
	    return tc26_gost3410_2012_512_paramsetA;
    if ( strcmp("tc26_gost3410_2012_512_paramsetB", str) == 0 )
	    return tc26_gost3410_2012_512_paramsetB;
    if ( strcmp("tc26_gost3410_2012_512_paramsetC", str) == 0 )
	    return tc26_gost3410_2012_512_paramsetC;
    if ( strcmp("rfc4357_gost3410_2001_paramsetA", str) == 0 )
	    return rfc4357_gost3410_2001_paramsetA;
    if ( strcmp("rfc4357_gost3410_2001_paramsetB", str) == 0 )
	    return rfc4357_gost3410_2001_paramsetB;
    if ( strcmp("rfc4357_gost3410_2001_paramsetC", str) == 0 )
            return rfc4357_gost3410_2001_paramsetC;
    return unknown_paramset;
}


static crypto_mechanism_t string_to_crypto_mechanism_t(char* str)
{
    
    if ( strcmp("streebog256", str) == 0 )
            return streebog256;
    if ( strcmp("streebog512", str) == 0 )
            return streebog512;
    if ( strcmp("magmaGOST3413ePSK", str) == 0 )
            return magmaGOST3413ePSK;
    if ( strcmp("kuznechikGOST3413ePSK", str) == 0 )
            return kuznechikGOST3413ePSK;
    if ( strcmp("magmaGOST3413iPSK", str) == 0 )
            return magmaGOST3413iPSK;
    if ( strcmp("kuznechikGOST3413iPSK", str) == 0 )
            return kuznechikGOST3413iPSK;
    if ( strcmp("hmac256ePSK", str) == 0 )
            return hmac256ePSK;
    if ( strcmp("hmac512ePSK", str) == 0 )
            return hmac512ePSK;
    if ( strcmp("hmac256iPSK", str) == 0 )
            return hmac256iPSK;
    if ( strcmp("hmac512iPSK", str) == 0 )
            return hmac512iPSK;
    if ( strcmp("magmaCTRplusHMAC256", str) == 0 )
            return magmaCTRplusHMAC256;
    if ( strcmp("magmaCTRplusGOST3413", str) == 0 )
            return magmaCTRplusGOST3413;
    if ( strcmp("kuznechikCTRplusHMAC256", str) == 0 )
            return kuznechikCTRplusHMAC256;
    if ( strcmp("kuznechikCTRplusGOST3413", str) == 0 )
            return kuznechikCTRplusGOST3413;
    if ( strcmp("magmaAEAD", str) == 0 )
            return magmaAEAD;
    if ( strcmp("kuznechikAEAD", str) == 0 )
            return kuznechikAEAD;

    return not_set_mechanism;
}
static netsnmp_tdomain fiotudpDomain;

typedef struct fiot_cache_s {
   struct fiot_cache_s *next;
   netsnmp_sockaddr_storage sas;
   struct fiot fctx;
   _netsnmpTLSBaseData* tlsdata;
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
    netsnmp_tlsbase_free_tlsdata(cachep->tlsdata);
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
                            struct sockaddr_in remote_addr,
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
   
   _netsnmpTLSBaseData *tlsbase;
   if (we_are_client) {
	 tlsbase = t->data;
	 netsnmp_cert *id_cert, *peer_cert;
	 

	 if (tlsbase->our_identity) {
         	DEBUGMSGTL(("sslctx_client", "looking for local id: %s\n", tlsbase->our_identity));
         id_cert = netsnmp_cert_find(NS_CERT_IDENTITY, NS_CERTKEY_MULTIPLE,
                                    tlsbase->our_identity);
         } else {
         	DEBUGMSGTL(("sslctx_client", "looking for default local id: %s\n", tlsbase->our_identity));
        	id_cert = netsnmp_cert_find(NS_CERT_IDENTITY, NS_CERTKEY_DEFAULT, NULL);
    	 }

    	 if (!id_cert)
        	return NULL;

         if (tlsbase->their_identity)
         	peer_cert = netsnmp_cert_find(NS_CERT_REMOTE_PEER,
                                      NS_CERTKEY_MULTIPLE,
                                      tlsbase->their_identity);
    	 else
         	peer_cert = netsnmp_cert_find(NS_CERT_REMOTE_PEER, NS_CERTKEY_DEFAULT,
                                      NULL);
	 if (!peer_cert)
                return NULL;

   	
	/* устанавливаем роль */
  	 if(( error = ak_fiot_context_set_role( ctx, client_role )) != ak_error_ok ) goto exit;
  	/* устанавливаем идентификатор сервера */
  	 if(( error = ak_fiot_context_set_user_identifier( ctx, server_role,
                                                 peer_cert->fingerprint, strlen(peer_cert->fingerprint) )) != ak_error_ok ) goto exit;
  	 if(( error = ak_fiot_context_set_user_identifier( ctx, client_role,
                             id_cert->fingerprint, strlen(id_cert->fingerprint) )) != ak_error_ok ) goto exit;

  	/* устанавливаем сокет для внешнего (шифрующего) интерфейса */
  	 if(( error = ak_fiot_context_set_interface_descriptor( ctx,
                                    encryption_interface, t->sock )) != ak_error_ok ) goto exit;
  	/* устанавливаем идентификатор ключа аутентификации */
  	 if(( error = ak_fiot_context_set_psk_identifier( ctx,
                                          ePSK_key, id_cert->fingerprint, strlen(id_cert->fingerprint) )) != ak_error_ok ) goto exit;
  	 if(( error = ak_fiot_context_set_blom_key_from_skey( ctx, blom_key, ak_false )) != ak_error_ok ) goto exit;
	 if(( error = ak_fiot_context_set_curve( ctx,
                              elliptic_curve_type )) != ak_error_ok ) goto exit;
  	 if(( error = ak_fiot_context_set_initial_crypto_mechanism( ctx,
                                             crypto_mechanism_type )) != ak_error_ok ) goto exit;
   } else {
	 tlsbase = calloc(1, sizeof(_netsnmpTLSBaseData));
	 netsnmp_cert *id_cert;
	 id_cert = netsnmp_cert_find(NS_CERT_IDENTITY, NS_CERTKEY_DEFAULT, NULL);
         if (!id_cert)
   		return NULL;
        /* устанавливаем роль */
   	 if(( error = ak_fiot_context_set_role( ctx, server_role )) != ak_error_ok ) goto exit;
  	/* устанавливаем идентификатор сервера */
  	 if(( error = ak_fiot_context_set_user_identifier( ctx, server_role,
                                                       id_cert->fingerprint, strlen(id_cert->fingerprint) )) != ak_error_ok ) goto exit;
  	/* устанавливаем сокет для внешнего (шифрующего) интерфейса */
  	 if(( error = ak_fiot_context_set_interface_descriptor( ctx,
                                            encryption_interface, fd )) != ak_error_ok ) goto exit;
  	 if(( error = ak_fiot_context_set_client( ctx,
                                            remote_addr )) != ak_error_ok ) goto exit;
	 if(( error = ak_fiot_context_set_blom_key_from_skey( ctx, blom_key, ak_false )) != ak_error_ok ) goto exit;
  	/* устанавливаем набор криптографических алгоритмов для обмена зашифрованной информацией */
  	 if(( error =  ak_fiot_context_set_server_policy( ctx,
                                            server_policy_type )) != ak_error_ok ) goto exit;
   }
  /* теперь выполняем протокол */
    if(( error = ak_fiot_context_keys_generation_protocol( ctx )) != ak_error_ok ) goto exit;
    


    DEBUGMSGTL(("fiotudp", "starting a new connection\n"));
    cachep->next = fiot_cache_list;
    cachep->sas.sin = remote_addr;
    cachep->tlsdata = tlsbase;
    fiot_cache_list = cachep;

    exit:

    return cachep;
}

static fiot_cache *
find_or_create_fiot_cache(netsnmp_transport *t,
                         netsnmp_sockaddr_storage *from_addr,
                         int we_are_client)
{
    fiot_cache *cachep = find_fiot_cache(from_addr);

    if (NULL == cachep) {
        /* none found; need to start a new context */
        cachep = start_new_cached_connection(t, from_addr->sin, we_are_client);
        if (NULL == cachep) {
            snmp_log(LOG_ERR, "failed to open a new fiot connection\n");
        }
    } else {
        DEBUGMSGT(("9:fiotudp:fiot_cache:found", "%p\n", cachep));
    }
    return cachep;
}



char* netsnmp_extract_security_name(fiot_cache* cachep) {
    netsnmp_container  *chain_maps;
    netsnmp_cert_map   *cert_map, *peer_cert;
    netsnmp_iterator  *itr;
    char *fp;
    char* securityName = NULL;
    int rc;

    chain_maps = netsnmp_cert_map_container();
    
    fp = malloc(cachep->fctx.epsk_id.size + 1);
    memcpy(fp, cachep->fctx.epsk_id.data, cachep->fctx.epsk_id.size);
    fp[cachep->fctx.epsk_id.size] = 0;
    peer_cert = netsnmp_cert_map_alloc(fp, NULL);
    free(fp);

    /*
     * map fingerprints to mapping entries
     */
    rc = netsnmp_cert_get_secname_maps(chain_maps);
    if ((-1 == rc) || (CONTAINER_SIZE(chain_maps) == 0)) {
        goto exit;
    }

    /*
     * change container to sorted (by clearing unsorted option), then
     * iterate over it until we find a map that returns a secname.
     */
    CONTAINER_SET_OPTIONS(chain_maps, 0, rc);
    itr = CONTAINER_ITERATOR(chain_maps);
    if (NULL == itr) {
        snmp_log(LOG_ERR, "could not get iterator for secname fingerprints\n");
        goto exit;
    }
    cert_map = ITERATOR_FIRST(itr);
    for( ; !securityName && cert_map; cert_map = ITERATOR_NEXT(itr))
        securityName =
            netsnmp_openssl_extract_secname(cert_map, peer_cert);
    ITERATOR_RELEASE(itr);

exit:
    netsnmp_cert_map_free(peer_cert);
    return securityName;
}


static int
netsnmp_fiotudp_recv(netsnmp_transport *t, void *buf, int size,
                     void **opaque, int *olength)
{
   int             rc = -1;
   netsnmp_indexed_addr_pair addr_pair;
   struct sockaddr_in cl_addr;
   char msg;
   _netsnmpTLSBaseData* tlsdata;
   int error = ak_error_ok;
   socklen_t opt = sizeof( cl_addr );
   ak_fiot ctx;
   
   if (ak_network_recvfrom(t->sock, &msg, 1, MSG_PEEK, &cl_addr, &opt) <= 0) {
                ak_error_message(ak_error_read_data, __func__, "wrong first client message receiving");
  		return rc;
   }

   addr_pair.remote_addr.sin = cl_addr;
   
	
   fiot_cache* cachep = find_or_create_fiot_cache(t, &addr_pair.remote_addr, WE_ARE_SERVER);
   ctx = &cachep->fctx;
   tlsdata = cachep->tlsdata;


   *olength=sizeof(netsnmp_tmStateReference);
   *opaque = calloc(1, sizeof(netsnmp_tmStateReference));

   netsnmp_tmStateReference* tmStateRef = *opaque;

   tmStateRef->addresses = addr_pair;
   tmStateRef->have_addresses = 1;
   
   memcpy(tmStateRef->transportDomain,
           netsnmpFIOTUDPDomain, sizeof(netsnmpFIOTUDPDomain[0]) *
           netsnmpFIOTUDPDomain_len);
   tmStateRef->transportDomainLen = netsnmpFIOTUDPDomain_len;
   
   char* secName = NULL;
   if (tlsdata && tlsdata->securityName) {
	   secName = tlsdata->securityName;
   } else {
	   secName = netsnmp_extract_security_name(cachep);
	   tlsdata->securityName = secName;
   }

   strlcpy(tmStateRef->securityName, secName, sizeof(tmStateRef->securityName));
   tmStateRef->securityNameLen = strlen(secName);

    /* RFC5953 Section 5.1.2 step 2: tmSessionID */
    /* use our TLSData pointer as the session ID */
   
   memcpy(tmStateRef->sessionID, cachep, sizeof(fiot_cache *));


   size_t length;
   message_t mtype = undefined_message;
   frame_type_t ftype;
   ak_uint8* data = ak_fiot_context_read_frame( ctx, &length, &mtype, &ftype );
   if( data != NULL ) {
     printf( "echo-server: recived length %lu\n", length );
   }

   if (ftype = encrypted_frame) {
   	tmStateRef->transportSecurityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
   } else {
   	tmStateRef->transportSecurityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
   }

   if (length == strlen(CLOSE_CONNECTION_MSG) && memcmp(data, CLOSE_CONNECTION_MSG, length) == 0) {
           remove_and_free_fiot_cache(cachep);
           return -2;
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
    _netsnmpTLSBaseData* tlsdata = t->data;

    addr_pair = _extract_addr_pair(t, opaque ? *opaque : NULL, olength ? *olength : 0); 
    netsnmp_tmStateReference* tmStateRef = *opaque;
    tmStateRef->addresses = *addr_pair;
    tmStateRef->have_addresses = 1;

    fiot_cache* cachep = find_or_create_fiot_cache(t, &addr_pair->remote_addr, WE_ARE_CLIENT);
    ctx = &cachep->fctx;

    if (tlsdata && !tlsdata->securityName && tmStateRef &&
        tmStateRef->securityNameLen > 0) {
        tlsdata->securityName = strdup(tmStateRef->securityName);
    }

    frame_type_t ftype;
    if (tmStateRef->transportSecurityLevel == SNMP_SEC_LEVEL_AUTHPRIV) {
    	ftype = encrypted_frame;
    } else {
    	ftype = plain_frame;
    }

    if(( error = ak_fiot_context_write_frame( ctx, buf, size,
                                             ftype, application_data )) != ak_error_ok ) {
     	ak_error_message( error, __func__, "write error" );
    } else {
	printf("echo-client: send %d bytes\n", size);
   	rc = size;
   }

  return rc;
}

void static free_libacrypt()
{
	ak_skey_context_destroy(blom_key);
	blom_key = NULL;
	ak_libakrypt_destroy();
}

static int
netsnmp_fiotudp_close(netsnmp_transport *t)
{
    fiot_cache *cachep = NULL;
    _netsnmpTLSBaseData *tlsbase = NULL;

    DEBUGTRACETOK("9:fiotudp");

    DEBUGMSGTL(("fiotudp:close", "closing fiotudp transport %p\n", t));

    if (NULL != t->data && t->data_length == sizeof(_netsnmpTLSBaseData)) {
        tlsbase = t->data;

        if (tlsbase->addr)
            cachep = find_fiot_cache(&tlsbase->addr->remote_addr);
    	t->data = NULL;
    }

    if (NULL != t->data && t->data_length == sizeof(netsnmp_indexed_addr_pair)) {
    	netsnmp_indexed_addr_pair* addr_pair = t->data;
	cachep = find_fiot_cache(&addr_pair->remote_addr);
	SNMP_FREE(t->data);
    }



    if (NULL == cachep) {
    	goto exit;
    }

    if (ak_fiot_context_get_role(&cachep->fctx) == client_role)
    	ak_fiot_context_write_frame( &cachep->fctx, CLOSE_CONNECTION_MSG, strlen(CLOSE_CONNECTION_MSG),
                                             encrypted_frame, application_data );

    remove_and_free_fiot_cache(cachep);
exit:
    free_libacrypt();
    return netsnmp_socketbase_close(t);
}


static netsnmp_transport *
_transport_common(netsnmp_transport *t, int local)
{
    char *tmp = NULL;
    int tmp_len;

    DEBUGTRACETOK("9:fiotudp");

    if (NULL == t)
        return NULL;

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

static void _parse_blom_key(const char* token, char* line)
{
    if (blom_key)
        return; //TODO error
    blom_key = &blom_key_;
    if ( ak_skey_context_create(blom_key, 32 * 256, 8) != ak_error_ok )
        return ; //TODO error


    ak_uint8 buf[32 * 256];
    for (int i = 0; i< 32*256; ++i )
        if (sscanf(line + i*2, "%02hhx", &buf[i]) != 1) break;

    if ( ak_skey_context_set_key(blom_key, buf, 32 * 256, ak_true ) != ak_error_ok )
        return; //TODO error
}

static void _release_blom_key()
{
    if (blom_key)
    	ak_skey_context_destroy(blom_key);
    blom_key = NULL;
}

static void _parse_elleptic_curve(const char* token, char* line)
{
	elliptic_curve_type = string_to_elliptic_curve_t(line);
}

static void _parse_crypto_mechanism(const char* token, char* line)
{
	crypto_mechanism_type = string_to_crypto_mechanism_t(line);
}

static void _parse_server_policy(const char* token, char* line)
{
        server_policy_type = string_to_crypto_mechanism_t(line);
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

    register_config_handler("snmpd", "blomKey", _parse_blom_key, _release_blom_key, NULL); 
    register_config_handler("snmpd", "ellipticCurve", _parse_elleptic_curve, NULL, NULL);
    register_config_handler("snmpd", "cryptoMechanism", _parse_crypto_mechanism, NULL, NULL);
    register_config_handler("snmpd", "serverPolicy", _parse_crypto_mechanism, NULL, NULL);

    netsnmp_tdomain_register(&fiotudpDomain);
}
