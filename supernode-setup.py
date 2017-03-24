#!/usr/bin/env python3

import re
import ipaddress

#re.search('[A-Za-z0-9][A-Za-z0-9_]*=[^ \n]*', line).group(0)
conf_re=re.compile('[A-Za-z0-9][A-Za-z0-9_]*=[^ #\n]*')
mtu_re=re.compile('^[ \t]*mtu[ \t]+([0-9]+);', re.I)
conf={}

for line in open('supernode.config'):
    line_match=(conf_re.match(line))
    if line_match:
        name, val = line_match.group(0).split('=')
        conf[name] = \
            ipaddress.IPv4Network(val) if re.search('IPV4_[A-Z]+_NET$', name) \
	    else ipaddress.IPv4Address(val) if re.search('_IPV4_[A-Z]+_ADDR', name) \
	    else val


batmtu = None
for line in open('/etc/fastd/client/fastd.conf'):
    result=mtu_re.search(line)
    if result:
        batmtu=int(result.expand('\\1'))
if batmtu == None:
    print ('mtu not found in fastd conf, exiting')
    system.exit(1)

mssmtu=batmtu - 78
dhcpmtu=batmtu - 38
radvdmtu=batmtu - 54

ipv6_net, ipv6_prefixlen=conf['SUPERNODE_IPV6_PREFIX'].split('/')
conf['SUPERNODE_IPV6_CLIENT_NET']=ipv6_net + '/64'
conf['SUPERNODE_IPV6_CLIENT_ADDR']=ipv6_net + '3/64'
conf['SUPERNODE_IPV6_TRANS_ADDR']=ipv6_net + '2/' + ipv6_prefixlen

numhosts=2**(32-conf['SUPERNODE_IPV4_CLIENT_NET'].prefixlen)

conf['SUPERNODE_IPV4_CLIENT_ADDR']=next(conf['SUPERNODE_IPV4_CLIENT_NET'].hosts())
conf['SUPERNODE_IPV4_CLIENT_NET_ADDR']=conf['SUPERNODE_IPV4_CLIENT_NET'][0]
conf['SUPERNODE_IPV4_DHCP_RANGE_START'] = \
	str(conf['SUPERNODE_IPV4_CLIENT_NET'][int(min([256, numhosts*0.1]))])
conf['SUPERNODE_IPV4_DHCP_RANGE_END'] = \
	str(conf['SUPERNODE_IPV4_CLIENT_NET'][
		int(numhosts*2813/65536 if conf['SUPERNODE_IPV4_CLIENT_NET'].prefixlen <= 16
		else 0.8*numhosts)])

print (conf)

EXT='eulenfunk'

def write_sysctl():
    open('20-ff-config.conf.' + EXT, 'w').write("""net.ipv4.ip_forward=1
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
""")


def write_interfaces():
    open('interfaces.' + EXT, 'w').write("""### >>> Start Freifunk Konfiguration nach Eulenfunk-Schema
auto br0
iface br0 inet static
        address """ + str(conf['SUPERNODE_IPV4_CLIENT_ADDR']) + """
        netmask """ + str(conf['SUPERNODE_IPV4_CLIENT_NET'].netmask) + """
        bridge_ports none
        bridge_stp no
	post-up ip -6 addr add """ + str(conf['SUPERNODE_IPV6_CLIENT_ADDR']) + """/64 dev br0

auto eth1
iface eth1 inet static
	address """ + str(conf['SUPERNODE_IPV4_TRANS_ADDR']) + """
	netmask 255.255.255.0
	post-up ip -6 addr add """ + str(conf['SUPERNODE_IPV6_TRANS_ADDR']) + """ dev eth1
### <<< Ende Freifunk Konfiguration nach Eulenfunk-Schema
""")

def write_dhcpdconfig():
    open('dhcpd.conf.' + EXT, 'w').write(
"""### >>> Start Freifunk Konfiguration nach Eulenfunk-Schema
authoritative;
subnet """ + str(conf['SUPERNODE_IPV4_CLIENT_NET_ADDR']) + " netmask " + str(conf['SUPERNODE_IPV4_CLIENT_NET'].netmask) + """ {
        range """ + conf['SUPERNODE_IPV4_DHCP_RANGE_START'] + " " + conf['SUPERNODE_IPV4_DHCP_RANGE_END'] + """;
        default-lease-time 300;
        max-lease-time 600;
        option domain-name-servers 8.8.8.8;
        option routers """ + str(conf['SUPERNODE_IPV4_CLIENT_ADDR']) + """;
	# braucht man eigentlich nicht: option interface-mtu """ + str(dhcpmtu) + """;
        interface br0;
}
### <<< Ende Freifunk Konfiguration nach Eulenfunk-Schema
""")

def write_radvdconfig():
    open('radvd.conf.' + EXT, 'w').write("""interface br0 {
  AdvSendAdvert on;
  MaxRtrAdvInterval 600;
  MinDelayBetweenRAs 10;
  AdvLinkMTU """ + str(radvdmtu) + """;
  prefix """ + str(conf['SUPERNODE_IPV6_CLIENT_NET']) + """ {
    AdvRouterAddr on;
  };
  RDNSS 2001:4860:4860::8844 2001:4860:4860::8888 {
  };
};
""")

write_interfaces()
write_dhcpdconfig()
write_radvdconfig()
write_sysctl()

print ("Ausgaben in:")
print ("\tinterfaces."+EXT)
print ("\tdhcpd.conf."+EXT)
print ("\tradvd.conf."+EXT)
print ("\t20-ff-config.conf."+EXT)
