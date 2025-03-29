from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import arp, ethernet
from pox.lib.packet.ipv4 import ipv4 as ipv4_pkt

log = core.getLogger()

class LoadBalancer(object):
        def __init__(self):
                core.openflow.addListeners(self) #Initialize OpenFlow listener and network config
                self.V_IP = IPAddr("10.0.0.10") # Virtual IP config
                self.V_MAC = EthAddr("00:00:00:00:10:10") # Virtual MAC config

                # "Backend" servers (h5 and h6)
                self.servers = [
                        {'ip': IPAddr("10.0.0.5"), 'mac': EthAddr("00:00:00:00:00:05"), 'port': 5},
                        {'ip': IPAddr("10.0.0.6"), 'mac': EthAddr("00:00:00:00:00:06"), 'port': 6}
                ]

                # Round robin selection state
                self.curr_server = 0

                # Client port to IP/MAC mapping (h1-h4)
                self.client_info = {
                        1: {'ip': IPAddr("10.0.0.1"), 'mac': EthAddr("00:00:00:00:00:01")},
                        2: {'ip': IPAddr("10.0.0.2"), 'mac': EthAddr("00:00:00:00:00:02")},
                        3: {'ip': IPAddr("10.0.0.3"), 'mac': EthAddr("00:00:00:00:00:03")},
                        4: {'ip': IPAddr("10.0.0.4"), 'mac': EthAddr("00:00:00:00:00:04")}
                }
        def _handle_ConnectionUp(self, event):
                """Handle new switch connection"""
                log.debug("Switch connected: %s:", event.dpid)

        def _handle_PacketIn(self, event):
                """Main packet processing entry point"""
                try:
                        pkt = event.parsed
                        if not pkt.parsed:
                                return
                        if pkt.type == 0x86dd: return # Mute IPV6 packets

                        # Process ARP packets
                        if pkt.type == ethernet.ARP_TYPE:
                                self.handle_arp(event, pkt)

                        # Process ICMP packets
                        if pkt.type == ethernet.IP_TYPE:
                                ip_pkt = pkt.payload
                                if ip_pkt.protocol == ipv4_pkt.ICMP_PROTOCOL:
                                        self.handle_icmp(event, pkt, ip_pkt)

                except Exception as e:
                        log.error("Packet parsing failed: %s", str(e))
                        return

        def handle_icmp(self, event, eth_pkt, ip_pkt):
                """ Handle ICMP traffic and perform NAT routing"""
                # Client -> Virtual IP traffic
                if ip_pkt.dstip == self.V_IP:
                        server = self.servers[self.curr_server]

                        # Rewrite dst MAC/IP to selected server
                        eth_pkt.dst = server['mac']
                        ip_pkt.dstip = server['ip']
                        ip_pkt.hdr_checksum = None # Checksum recalc

                        # Forward to server
                        msg = of.ofp_packet_out()
                        msg.data = eth_pkt.pack()
                        msg.actions.append(of.ofp_action_output(port=server['port']))
                        event.connection.send(msg)

                # Server -> Client return traffic
                elif ip_pkt.srcip in [s['ip'] for s in self.servers]:
                        # Rewrite source MAC/IP to virtual addresses
                        eth_pkt.src = self.V_MAC
                        ip_pkt.srcip = self.V_IP
                        ip_pkt.hdr_checksum = None # Checksum recalc

                        # Get client port and forward it to server
                        client_port = next((p for p, info in self.client_info.items() if info['ip'] == ip_pkt.dstip), None)
                        if client_port:
                                msg = of.ofp_packet_out()
                                msg.data = eth_pkt.pack()
                                msg.actions.append(of.ofp_action_output(port=client_port))
                                event.connection.send(msg)

        def handle_arp(self, event, pkt):
                """Main ARP request handler"""
                try:
                        if not isinstance(pkt.payload, arp):
                                return

                        # Make the ARP packet
                        arp_pkt = pkt.payload

                        # Handle server originated ARP requests for Virtual IP
                        if event.port in [5,6] and arp_pkt.protodst == self.V_IP:
                                self.handle_virtual_arp_for_servers(event, arp_pkt, pkt.src)
                                return

                        # Validate ARP packet format
                        if (arp_pkt.hwtype != arp.HW_TYPE_ETHERNET or
                                arp_pkt.prototype != arp.PROTO_TYPE_IP or
                                arp_pkt.opcode != arp.REQUEST):
                                return

                        # Route ARP requests to appropriate handler
                        if arp_pkt.protodst == self.V_IP:
                                self.handle_virtual_arp(event, arp_pkt, pkt.src)
                        else:
                                self.handle_client_arp(event, arp_pkt, pkt.src)

                except Exception as e:
                        log.error("ARP handling failed: %s", e)

        def handle_virtual_arp_for_servers(self, event, arp_pkt, eth_src):
                """Respond to server ARP requests for Virtual IP"""
                # Initialize basic reply
                reply = ethernet(
                        src = self.V_MAC,
                        dst = eth_src,
                        type = ethernet.ARP_TYPE
                )
                # Make ARP reply for server message
                arp_reply = arp(
                        hwtype=arp.HW_TYPE_ETHERNET,
                        prototype = arp.PROTO_TYPE_IP,
                        hwlen = 6,
                        protolen = 4,
                        opcode = arp.REPLY,
                        hwsrc = self.V_MAC,
                        protosrc = self.V_IP,
                        hwdst = arp_pkt.hwsrc,
                        protodst = arp_pkt.protosrc
                )
                # Forward to server
                reply.payload = arp_reply
                msg = of.ofp_packet_out()
                msg.data = reply.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                event.connection.send(msg)

        def handle_virtual_arp(self, event, arp_pkt, eth_src):
                """Handle ARP requests for Virtual IP from clients"""
                if arp_pkt.hwsrc != eth_src.toStr():
                        return

                # Only process requests from client ports
                if event.port not in self.client_info:
                        return

                # Select server with round robin
                server = self.servers[self.curr_server]
		self.curr_server = (self.curr_server + 1) % len(self.servers)

                # Make ARP reply with server MAC
                reply = ethernet(
                        src=server['mac'],
                        dst=eth_src,
                        type=ethernet.ARP_TYPE
                )
                arp_reply = arp(
                        hwtype=arp.HW_TYPE_ETHERNET,
                        prototype=arp.PROTO_TYPE_IP,
                        hwlen=6,
                        protolen=4,
                        opcode=arp.REPLY,
                        hwsrc=server['mac'],
                        protosrc=self.V_IP,
                        hwdst=arp_pkt.hwsrc,
                        protodst=arp_pkt.protosrc
                )
                # Forward reply to server
                reply.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = reply.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                event.connection.send(msg)

                # Install forwarding rules
                self.install_forward_flow(event, server)

        def handle_client_arp(self, event, arp_pkt, eth_src):
                """Handle ARP requests for client IPs"""
                client_ip = arp_pkt.protodst
                client = next((c for c in self.client_info.values() if c['ip'] == client_ip), None)
                if not client: return

                # Make ARP reply with client's MAC
                reply = ethernet(
                        src = client['mac'],
                        dst = eth_src,
                        type = ethernet.ARP_TYPE
                )
                arp_reply = arp(
                        hwtype = arp.HW_TYPE_ETHERNET,
                        prototype = arp.PROTO_TYPE_IP,
                        hwlen = 6,
                        protolen = 4,
                        opcode = arp.REPLY,
                        hwsrc = client['mac'],
                        protosrc = client_ip,
                        hwdst = arp_pkt.hwsrc,
                        protodst = arp_pkt.protosrc
                )
                # Forward reply to server
                reply.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = reply.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                event.connection.send(msg)

        def install_forward_flow(self, event, server):
                """Install flow rule from client to server"""
                msg = of.ofp_flow_mod()
                msg.priority = 3

                # Match client traffic to Virtual IP
                msg.match.in_port = event.port
                msg.match.dl_type = ethernet.IP_TYPE
                msg.match.nw_dst = self.V_IP
                msg.match.nw_src = self.client_info[event.port]['ip']

                # Rewrite MAC addresses and forward
                msg.actions.append(of.ofp_action_dl_addr.set_src(self.V_MAC))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(server['mac']))
                msg.actions.append(of.ofp_action_output(port=server['port']))

                # Expiration timers
                msg.hard_timeout = 60
                msg.idle_timeout = 30

                event.connection.send(msg)

def launch():
        """Start the load balancer"""
        log.info("Starting Virtual IP load balancer")
        core.registerNew(LoadBalancer)
