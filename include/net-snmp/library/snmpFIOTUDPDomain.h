#ifndef _SNMPFIOTUDPDOMAIN_H
#define _SNMPFIOTUDPDOMAIN_H

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

config_require(UDP)
config_require(TLSBase)

#include <net-snmp/types.h>
#include <net-snmp/library/snmp_transport.h>

#ifdef __cplusplus
extern          "C" {
#endif

#define TRANSPORT_DOMAIN_FIOT_UDP_IP	1,3,6,1,6,1,12
NETSNMP_IMPORT oid netsnmpFIOTUDPDomain[7];
NETSNMP_IMPORT size_t netsnmpFIOTUDPDomain_len;

netsnmp_transport *
netsnmp_fiotudp_transport(const struct netsnmp_ep *ep, int local);


/*
 * Register any configuration tokens specific to the agent.  
 */

void            netsnmp_fiotudp_agent_config_tokens_register(void);

/*
 * "Constructor" for transport domain object.  
 */

void            netsnmp_fiotudp_ctor(void);

#ifdef __cplusplus
}
#endif
#endif/*_SNMPFIOTUDPDOMAIN_H*/
