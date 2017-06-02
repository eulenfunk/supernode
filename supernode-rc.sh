#!/bin/bash
#DBG=echo

BASE=/opt/eulenfunk/supernode

. ${BASE}/supernode.config
. ${BASE}/supernode.vars

IPV6_PREFIX_LENGTH=${SUPERNODE_IPV6_PREFIX##*/}
IPV6_NET_ADDRESS=${SUPERNODE_IPV6_PREFIX%/*}
SUPERNODE_IPV6_TRANS_REMOTE=${IPV6_NET_ADDRESS}1
SUPERNODE_IPV6_CLIENT_PREFIX=${IPV6_NET_ADDRESS}/64

## BATMTU=$(cat /etc/fastd/client/fastd.conf|grep -i mtu.*\; |sed s/'\t'/\ /|rev|cut -d$' ' -f1|rev|sed s/\;//)
## MSSMTU=$((BATMTU - 78))

MSSMTU=1332

${DBG} BATMTU:$BATMTU   MSSMTU:$MSSMTU

${DBG} /sbin/iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${MSSMTU}
${DBG} /sbin/ip6tables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${MSSMTU}

${DBG} /sbin/ip -4 route add table 42 default via 172.31.254.254
${DBG} /sbin/ip -6 route add table 42 ${SUPERNODE_IPV6_TRANS_REMOTE} dev ${SUPERNODE_TRANS_INTERFACE}
${DBG} /sbin/ip -6 route add table 42 default via ${SUPERNODE_IPV6_TRANS_REMOTE} dev ${SUPERNODE_TRANS_INTERFACE}

${DBG} /sbin/ip -4 route add table 42 ${SUPERNODE_IPV4_CLIENT_NET} dev br0 scope link
${DBG} /sbin/ip -6 route add table 42 ${SUPERNODE_IPV6_CLIENT_PREFIX} dev br0

${DBG} /sbin/ip -4 rule add prio 1000 from ${SUPERNODE_IPV4_CLIENT_NET} lookup 42
${DBG} /sbin/ip -6 rule add prio 1000 from ${SUPERNODE_IPV6_PREFIX} lookup 42

${DBG} /sbin/ip -4 rule add prio 1001 from all iif ${SUPERNODE_TRANS_INTERFACE} lookup 42
${DBG} /sbin/ip -6 rule add prio 1001 from all iif ${SUPERNODE_TRANS_INTERFACE} lookup 42

${DBG} /sbin/ip -4 rule add prio 2000 from ${SUPERNODE_IPV4_CLIENT_NET} type unreachable
${DBG} /sbin/ip -6 rule add prio 2000 from ${SUPERNODE_IPV6_PREFIX} type unreachable

