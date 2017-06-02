#!/bin/bash

BASE=/opt/eulenfunk/supernode

exec $BASE/supernode-setup.py

. ${BASE}/supernode.config
BATMTU=$(cat /etc/fastd/client/fastd.conf|grep -i mtu.*\; |sed s/'\t'/\ /|rev|cut -d$' ' -f1|rev|sed s/\;//)
MSSMTU=$((BATMTU - 78))
DHCPMTU=$((BATMTU - 38))
RADVDMTU=$((BATMTU - 54))

echo BATMTU:$BATMTU   DHCPMTU:$DHCPMTU

SUPERNODE_IPV4_CLIENT_ADDR=${SUPERNODE_IPV4_CLIENT_NET%.0/*}.1
SUPERNODE_IPV6_CLIENT_ADDR=${SUPERNODE_IPV6_PREFIX%/*}3/64
SUPERNODE_IPV6_TRANS_ADDR=${SUPERNODE_IPV6_PREFIX%/*}2/56
SUPERNODE_IPV6_CLIENT_PREFIX=${SUPERNODE_IPV6_PREFIX%/*}/64

SUPERNODE_IPV4_CLIENT_NET_ADDR=${SUPERNODE_IPV4_CLIENT_NET%/*}
SUPERNODE_IPV4_DHCP_RANGE_START=${SUPERNODE_IPV4_CLIENT_NET%.0.0/*}.1.1
SUPERNODE_IPV4_DHCP_RANGE_END=${SUPERNODE_IPV4_CLIENT_NET%.0.0/*}.10.254
         
EXT=eulenfunk

function show_sysctl
{
cat << _EOF > 20-ff-config.conf.${EXT}
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 16777216
net.core.wmem_max=16777216
net.core.rmem_default=65536
net.core.wmem_default=65536
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mem=16777216 16777216 16777216
net.ipv4.route.flush=1
vm.swappiness=10

_EOF
}

function show_interfaces
{

cat << _EOF > interfaces.${EXT}
### >>> Start Freifunk Konfiguration nach Eulenfunk-Schema
auto br0
iface br0 inet static
        address ${SUPERNODE_IPV4_CLIENT_ADDR}
        netmask 255.255.0.0
        bridge_ports none
        bridge_stp no
	post-up ip -6 addr add ${SUPERNODE_IPV6_CLIENT_ADDR} dev br0

auto eth1
iface eth1 inet static
	address ${SUPERNODE_IPV4_TRANS_ADDR}
	netmask 255.255.255.0
	post-up ip -6 addr add ${SUPERNODE_IPV6_TRANS_ADDR} dev eth1
### <<< Ende Freifunk Konfiguration nach Eulenfunk-Schema
_EOF
}


function show_dhcpdconfig
{
cat << _EOF > dhcpd.conf.${EXT}
### >>> Start Freifunk Konfiguration nach Eulenfunk-Schema
authoritative;
subnet ${SUPERNODE_IPV4_CLIENT_NET_ADDR} netmask 255.255.0.0 {
        range ${SUPERNODE_IPV4_DHCP_RANGE_START} ${SUPERNODE_IPV4_DHCP_RANGE_END};
        default-lease-time 300;
        max-lease-time 600;
        option domain-name-servers 8.8.8.8;
        option routers ${SUPERNODE_IPV4_CLIENT_ADDR};
	# braucht man eigentlich nicht: option interface-mtu ${DHCPMTU};
        interface br0;
}
### <<< Ende Freifunk Konfiguration nach Eulenfunk-Schema
_EOF
}

function show_radvdconfig
{
cat << _EOF > radvd.conf.${EXT}
interface br0 {
  AdvSendAdvert on;
  MaxRtrAdvInterval 600;
  MinDelayBetweenRAs 10;
  AdvLinkMTU ${RADVDMTU};
  prefix ${SUPERNODE_IPV6_CLIENT_PREFIX} {
    AdvRouterAddr on;
  };
  RDNSS 2001:4860:4860::8844 2001:4860:4860::8888 {
  };
};
_EOF
}

show_interfaces
show_dhcpdconfig
show_radvdconfig
show_sysctl

echo "Ausgaben in:"
echo -e "\tinterfaces.${EXT}"
echo -e "\tdhcpd.conf.${EXT}"
echo -e "\tradvd.conf.${EXT}"
echo -e "\t20-ff-config.conf.${EXT}"

