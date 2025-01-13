from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
import ipaddress

class SimpleSDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SimpleSDNController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # Stores MAC-to-port mappings
        self.port_packet_count = {}  # Initialize port packet count dictionary
        self.host_packet_count = {}  # Initialize host packet count dictionary
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handles initial connection with a switch."""
        datapath = ev.msg.datapath
        self._install_table_miss_flow(datapath)
    
    def _install_table_miss_flow(self, datapath):
        """Install a table-miss flow entry to handle unmatched packets."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Match all packets
        match = parser.OFPMatch()
        # Send unmatched packets to the controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        # Create a flow mod message
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_mod = parser.OFPFlowMod(
            datapath=datapath, priority=0, match=match, instructions=inst
        )
        # Send the flow mod message to the switch
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handles packets that are sent to the controller."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Parse the packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Update port packet count in a nested dictionary for each switch
        dpid = datapath.id
        if dpid not in self.port_packet_count:
            self.port_packet_count[dpid] = {}
        if in_port not in self.port_packet_count[dpid]:
            self.port_packet_count[dpid][in_port] = 0
        self.port_packet_count[dpid][in_port] += 1

        # Update host packet count
        source_mac = eth.src
        if source_mac not in self.host_packet_count:
            self.host_packet_count[source_mac] = 0
        self.host_packet_count[source_mac] += 1

        # Log packet count info
        self.logger.info(f"Packets received from host {source_mac}: {self.host_packet_count[source_mac]}")
        self.logger.info(f"Packets received on port {in_port} of switch {dpid}: {self.port_packet_count[dpid][in_port]}")

        # Ignore non-IP packets
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        # Parse the packet and extract the IPv4 protocol layer
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return
        
        source_ip = ip_pkt.src
        destination_ip = ip_pkt.dst

        # Define the subnet
        subnet = ipaddress.ip_network("10.0.0.0/24")

        # Check if both source and destination IPs are in the subnet
        if ipaddress.ip_address(source_ip) in subnet and ipaddress.ip_address(destination_ip) in subnet:
            self.logger.info(f"Forwarding packet from {source_ip} to {destination_ip}")
            # Forward packet
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        else:
            self.logger.info(f"Dropping packet from {source_ip} to {destination_ip} (not in subnet)")
            # Drop packet
            actions = []

        # Send the packet (or drop it)
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
