#!/usr/bin/env python3
"""
Python implementation of NetFound data preprocessing workflow.
This module provides Python equivalents of the C++ preprocessing tools:
- 1_filter: Filter packets to keep only TCP/UDP/ICMP
- 2_pcap_splitting: Split pcaps by flows
- 3_extract_fields: Extract fields in the same binary format as C++

Usage:
    python python_preprocess.py --input_folder /path/to/input --output_folder /path/to/output
"""

import os
import sys
import traceback
import argparse
import struct
import socket
from pathlib import Path
from typing import Dict, List, Tuple, Optional, BinaryIO
import logging

# Try to import scapy, fallback to pyshark if not available
try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    try:
        import pyshark
        SCAPY_AVAILABLE = False
    except ImportError:
        print("Error: Neither scapy nor pyshark is available. Please install one:")
        print("  pip install scapy")
        print("  pip install pyshark")
        sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants matching the C++ implementation
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17
PROTOCOL_ICMP = 1

class PacketProcessor:
    """Process packets and extract fields in the same format as the C++ implementation."""
    
    def __init__(self):
        self.packet_count = 0
        self.global_protocol = None
        self.absolute_seq_src_ip = 0
        self.tcp_absolute_seq = 0
        self.tcp_absolute_ack = 0
    
    def ip_to_int_little_endian(self, ip_str: str) -> int:
        """Convert IP address to little-endian integer (matching C++ implementation)."""
        # Convert IP string to integer
        ip_int = int.from_bytes(socket.inet_aton(ip_str), byteorder='big')
        # Convert to little-endian (swap bytes)
        return ((ip_int & 0xff000000) >> 24) | ((ip_int & 0x00ff0000) >> 8) | \
               ((ip_int & 0x0000ff00) << 8) | ((ip_int & 0x000000ff) << 24)
    
    def uint16_to_little_endian(self, value: int) -> int:
        """Convert 16-bit value to little-endian."""
        return ((value & 0xff00) >> 8) | ((value & 0x00ff) << 8)
    
    def uint32_to_little_endian(self, value: int) -> int:
        """Convert 32-bit value to little-endian."""
        return ((value & 0xff000000) >> 24) | ((value & 0x00ff0000) >> 8) | \
               ((value & 0x0000ff00) << 8) | ((value & 0x000000ff) << 24)
    
    def get_tcp_flags(self, tcp_packet) -> int:
        """Extract TCP flags as a single byte (matching C++ implementation)."""
        flags = 0
        if hasattr(tcp_packet, 'flags'):
            # Map TCP flags to bit positions
            if hasattr(tcp_packet.flags, 'C') and tcp_packet.flags.C:  # CWR
                flags |= 1 << 7
            if hasattr(tcp_packet.flags, 'E') and tcp_packet.flags.E:  # ECE
                flags |= 1 << 6
            if hasattr(tcp_packet.flags, 'U') and tcp_packet.flags.U:  # URG
                flags |= 1 << 5
            if hasattr(tcp_packet.flags, 'A') and tcp_packet.flags.A:  # ACK
                flags |= 1 << 4
            if hasattr(tcp_packet.flags, 'P') and tcp_packet.flags.P:  # PSH
                flags |= 1 << 3
            if hasattr(tcp_packet.flags, 'R') and tcp_packet.flags.R:  # RST
                flags |= 1 << 2
            if hasattr(tcp_packet.flags, 'S') and tcp_packet.flags.S:  # SYN
                flags |= 1 << 1
            if hasattr(tcp_packet.flags, 'F') and tcp_packet.flags.F:  # FIN
                flags |= 1
        return flags
    
    def extract_packet_fields(self, packet) -> Optional[bytes]:
        """Extract packet fields in the same binary format as C++ implementation."""
        try:
            # Get IP layer
            if IP not in packet:
                return None
            
            ip_layer = packet[IP]
            protocol = ip_layer.proto
            
            # Check if this is a supported protocol
            if protocol not in [PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP]:
                return None
            
            # Initialize protocol tracking
            if self.packet_count == 0:
                self.global_protocol = protocol
            elif protocol != self.global_protocol:
                logger.warning(f"Mixed protocols in flow: expected {self.global_protocol}, got {protocol}")
                return None
            
            # Extract common fields
            # Timestamp (nanoseconds since epoch)
            epoch_ns = int(packet.time * 1_000_000_000)  # Convert to nanoseconds
            
            # IP header length
            ip_hdr_len = ip_layer.ihl * 4  # IHL is in 32-bit words
            
            # Type of service
            type_of_service = ip_layer.tos
            
            # Total length (convert to little-endian)
            total_length = self.uint16_to_little_endian(ip_layer.len)
            
            # IP flags (extract fragment flags)
            flags = 0
            if hasattr(ip_layer, 'flags'):
                flags = int(ip_layer.flags) >> 5  # Align 3-bit flags
            
            # TTL
            ttl = ip_layer.ttl
            
            # Source and destination IPs (convert to little-endian)
            src_ip = self.ip_to_int_little_endian(ip_layer.src)
            dst_ip = self.ip_to_int_little_endian(ip_layer.dst)
            
            # Track source IP for sequence number normalization
            if self.packet_count == 0:
                self.absolute_seq_src_ip = src_ip
            
            # Build the binary packet representation
            packet_data = struct.pack('<QBBHHBBII',  # Format: uint64, uint8, uint8, uint16, uint16, uint8, uint8, uint32, uint32
                                    epoch_ns, ip_hdr_len, type_of_service, 
                                    total_length, 0, flags, ttl, src_ip, dst_ip)
            
            # Protocol-specific fields
            if protocol == PROTOCOL_TCP and TCP in packet:
                tcp_layer = packet[TCP]
                
                # Ports (convert to little-endian)
                src_port = self.uint16_to_little_endian(tcp_layer.sport)
                dst_port = self.uint16_to_little_endian(tcp_layer.dport)
                
                # TCP flags
                tcp_flags = self.get_tcp_flags(tcp_layer)
                
                # Window size (convert to little-endian)
                window_size = self.uint16_to_little_endian(tcp_layer.window)
                
                # Sequence and acknowledgment numbers (convert to little-endian)
                seq_num = self.uint32_to_little_endian(tcp_layer.seq)
                ack_num = self.uint32_to_little_endian(tcp_layer.ack)
                
                # Urgent pointer (convert to little-endian)
                urg_ptr = self.uint16_to_little_endian(tcp_layer.urgptr)
                
                # Normalize sequence numbers (matching C++ logic)
                if self.packet_count == 0:
                    self.tcp_absolute_seq = seq_num
                if self.packet_count == 0 and ack_num != 0:
                    self.tcp_absolute_ack = ack_num
                elif self.packet_count == 1 and self.tcp_absolute_ack == 0:
                    self.tcp_absolute_ack = seq_num
                
                # Apply sequence number normalization
                if src_ip == self.absolute_seq_src_ip:
                    seq_num -= self.tcp_absolute_seq
                else:
                    seq_num -= self.tcp_absolute_ack
                
                if src_ip == self.absolute_seq_src_ip:
                    if self.tcp_absolute_ack == 0:
                        ack_num = 0
                    else:
                        ack_num -= self.tcp_absolute_ack
                else:
                    ack_num -= self.tcp_absolute_seq
                
                # TCP-specific fields
                seq_num = seq_num & 0xFFFFFFFF
                ack_num = ack_num & 0xFFFFFFFF
                src_port = src_port & 0xFFFF
                dst_port = dst_port & 0xFFFF
                window_size = window_size & 0xFFFF
                urg_ptr = urg_ptr & 0xFFFF
                tcp_flags = tcp_flags & 0xFF

                tcp_data = struct.pack('<HHBHIIH', src_port, dst_port, tcp_flags, window_size, seq_num, ack_num, urg_ptr)
                
                packet_data += tcp_data
                
            elif protocol == PROTOCOL_UDP and UDP in packet:
                udp_layer = packet[UDP]
                
                # Ports (convert to little-endian)
                src_port = self.uint16_to_little_endian(udp_layer.sport)
                dst_port = self.uint16_to_little_endian(udp_layer.dport)
                
                # UDP length (convert to little-endian)
                udp_len = self.uint16_to_little_endian(udp_layer.len)
                
                # UDP-specific fields
                udp_data = struct.pack('<HHH',  # Format: uint16, uint16, uint16
                                     src_port, dst_port, udp_len)
                
                packet_data += udp_data
                
            elif protocol == PROTOCOL_ICMP and ICMP in packet:
                icmp_layer = packet[ICMP]
                
                # ICMP type and code
                icmp_type = icmp_layer.type
                icmp_code = icmp_layer.code
                
                # ICMP-specific fields
                icmp_data = struct.pack('<BB',  # Format: uint8, uint8
                                      icmp_type, icmp_code)
                
                packet_data += icmp_data
            
            # Add 12 bytes of payload padding (matching C++ implementation)
            payload_padding = b'\x00' * 12
            packet_data += payload_padding
            
            self.packet_count += 1
            return packet_data
            
        except Exception as e:
            logger.error(f"Error extracting fields from packet: {e}\n{traceback.format_exc()}")
            return None

def filter_packets(input_file: str, output_file: str) -> bool:
    """Filter packets to keep only TCP/UDP/ICMP (equivalent to 1_filter.cpp)."""
    try:
        if SCAPY_AVAILABLE:
            packets = rdpcap(input_file)
            filtered_packets = []
            
            for packet in packets:
                if IP in packet:
                    protocol = packet[IP].proto
                    if protocol in [PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP]:
                        filtered_packets.append(packet)
            
            # Write filtered packets to output file
            from scapy.all import wrpcap
            wrpcap(output_file, filtered_packets)
            logger.info(f"Filtered {len(filtered_packets)} packets from {len(packets)} total")
            return True
        else:
            # Fallback to pyshark
            import pyshark
            cap = pyshark.FileCapture(input_file)
            filtered_packets = []
            
            for packet in cap:
                if hasattr(packet, 'ip'):
                    protocol = int(packet.ip.proto)
                    if protocol in [PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP]:
                        filtered_packets.append(packet)
            
            cap.close()
            # Note: pyshark doesn't easily support writing, so this is a limitation
            logger.warning("pyshark doesn't support writing pcap files easily")
            return False
            
    except Exception as e:
        logger.error(f"Error filtering packets: {e}")
        return False

def get_flow_key(ip_src, ip_dst, port_src, port_dst, protocol):
    """Return a direction-agnostic flow key (same for both directions)."""
    if (ip_src, port_src) <= (ip_dst, port_dst):
        return (ip_src, ip_dst, port_src, port_dst, protocol)
    else:
        return (ip_dst, ip_src, port_dst, port_src, protocol)

def split_pcap_by_flows(input_file: str, output_dir: str) -> bool:
    """Split pcap file by flows (equivalent to 2_pcap_splitting.sh)."""
    try:
        if not SCAPY_AVAILABLE:
            logger.error("Scapy required for flow splitting")
            return False
        
        packets = rdpcap(input_file)
        flows = {}
        
        for packet in packets:
            if IP not in packet:
                continue
                
            # Create direction-agnostic flow key (5-tuple)
            ip_layer = packet[IP]
            protocol = ip_layer.proto
            
            if TCP in packet:
                flow_key = get_flow_key(ip_layer.src, ip_layer.dst, packet[TCP].sport, packet[TCP].dport, protocol)
            elif UDP in packet:
                flow_key = get_flow_key(ip_layer.src, ip_layer.dst, packet[UDP].sport, packet[UDP].dport, protocol)
            elif ICMP in packet:
                flow_key = get_flow_key(ip_layer.src, ip_layer.dst, 0, 0, protocol)
            else:
                continue
            
            if flow_key not in flows:
                flows[flow_key] = []
            flows[flow_key].append(packet)
        
        # Write each flow to a separate file
        base_name = Path(input_file).stem
        for i, (flow_key, flow_packets) in enumerate(flows.items()):
            flow_filename = f"{base_name}_flow_{i}.pcap"
            flow_path = os.path.join(output_dir, flow_filename)
            
            from scapy.all import wrpcap
            wrpcap(flow_path, flow_packets)
        
        logger.info(f"Split {len(packets)} packets into {len(flows)} flows")
        return True
        
    except Exception as e:
        logger.error(f"Error splitting pcap by flows: {e}")
        return False

def extract_fields_from_flow(input_file: str, output_file: str, tcp_options: bool = False) -> bool:
    """Extract fields from a flow file (equivalent to 3_field_extraction.cpp)."""
    try:
        if not SCAPY_AVAILABLE:
            logger.error("Scapy required for field extraction")
            return False
        
        packets = rdpcap(input_file)
        if not packets:
            logger.warning(f"No packets found in {input_file}")
            return False
        
        processor = PacketProcessor()
        
        # Determine protocol from first packet
        if IP not in packets[0]:
            logger.error("First packet doesn't have IP layer")
            return False
        
        protocol = packets[0][IP].proto
        if protocol not in [PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP]:
            logger.error(f"Unsupported protocol: {protocol}")
            return False
        
        # Create output filename with protocol extension
        output_filename = f"{output_file}.{protocol}"
        if tcp_options and protocol == PROTOCOL_TCP:
            output_filename += ".tcpoptions"
        
        with open(output_filename, 'wb') as f:
            # Write protocol byte
            f.write(struct.pack('B', protocol))
            
            # Process each packet
            for packet in packets:
                packet_data = processor.extract_packet_fields(packet)
                if packet_data:
                    f.write(packet_data)
        
        logger.info(f"Extracted fields from {len(packets)} packets to {output_filename}")
        return True
        
    except Exception as e:
        logger.error(f"Error extracting fields: {e}")
        return False

def process_directory(input_folder: str, tcp_options: bool = False, finetune: bool = False):
    """Process all pcap files in a directory through the complete pipeline, aligned with preprocess_data.py."""
    input_path = Path(input_folder)
    raw_dir = input_path / "raw"
    filtered_dir = input_path / "filtered"
    split_dir = input_path / "split"
    extracted_dir = input_path / "extracted"

    filtered_dir.mkdir(parents=True, exist_ok=True)
    split_dir.mkdir(parents=True, exist_ok=True)
    extracted_dir.mkdir(parents=True, exist_ok=True)

    if finetune:
        # Each label is a subfolder in raw
        labels = [d for d in raw_dir.iterdir() if d.is_dir()]
        for label_dir in labels:
            label = label_dir.name
            logger.info(f"Processing label: {label}")
            filtered_label_dir = filtered_dir / label
            split_label_dir = split_dir / label
            extracted_label_dir = extracted_dir / label
            filtered_label_dir.mkdir(parents=True, exist_ok=True)
            split_label_dir.mkdir(parents=True, exist_ok=True)
            extracted_label_dir.mkdir(parents=True, exist_ok=True)

            pcap_files = list(label_dir.glob("*.pcap")) + list(label_dir.glob("*.pcapng"))
            logger.info(f"Found {len(pcap_files)} pcap files for label {label}")
            for pcap_file in pcap_files:
                logger.info(f"Processing {pcap_file}")
                filtered_file = filtered_label_dir / pcap_file.name
                if not filter_packets(str(pcap_file), str(filtered_file)):
                    logger.error(f"Failed to filter {pcap_file}")
                    continue
                flow_dir = split_label_dir / pcap_file.stem
                flow_dir.mkdir(exist_ok=True)
                if not split_pcap_by_flows(str(filtered_file), str(flow_dir)):
                    logger.error(f"Failed to split flows for {pcap_file}")
                    continue
                extracted_flow_dir = extracted_label_dir / pcap_file.stem
                extracted_flow_dir.mkdir(exist_ok=True)
                for flow_file in flow_dir.glob("*.pcap"):
                    flow_name = flow_file.stem
                    output_base = extracted_flow_dir / flow_name
                    if not extract_fields_from_flow(str(flow_file), str(output_base), tcp_options):
                        logger.error(f"Failed to extract fields for {flow_file}")
    else:
        # Pretraining: process all pcaps in raw
        pcap_files = list(raw_dir.glob("*.pcap")) + list(raw_dir.glob("*.pcapng"))
        logger.info(f"Found {len(pcap_files)} pcap files to process")
        for pcap_file in pcap_files:
            logger.info(f"Processing {pcap_file}")
            filtered_file = filtered_dir / pcap_file.name
            if not filter_packets(str(pcap_file), str(filtered_file)):
                logger.error(f"Failed to filter {pcap_file}")
                continue
            flow_dir = split_dir / pcap_file.stem
            flow_dir.mkdir(exist_ok=True)
            if not split_pcap_by_flows(str(filtered_file), str(flow_dir)):
                logger.error(f"Failed to split flows for {pcap_file}")
                continue
            extracted_flow_dir = extracted_dir / pcap_file.stem
            extracted_flow_dir.mkdir(exist_ok=True)
            for flow_file in flow_dir.glob("*.pcap"):
                flow_name = flow_file.stem
                output_base = extracted_flow_dir / flow_name
                if not extract_fields_from_flow(str(flow_file), str(output_base), tcp_options):
                    logger.error(f"Failed to extract fields for {flow_file}")

def main():
    parser = argparse.ArgumentParser(description="Python implementation of NetFound preprocessing")
    parser.add_argument("--input_folder", required=True, help="Input folder containing pcap files")
    parser.add_argument("--tcp_options", action="store_true", help="Include TCP options in extraction")
    parser.add_argument("--step", choices=["filter", "split", "extract", "all"], 
                       default="all", help="Which step to run")
    parser.add_argument("--finetune", action="store_true", help="Enable finetuning mode (label subfolders)")
    args = parser.parse_args()

    if args.step == "all":
        process_directory(args.input_folder, tcp_options=args.tcp_options, finetune=args.finetune)
    elif args.step == "filter":
        # Process individual files for filtering
        input_path = Path(args.input_folder)
        output_path = input_path / "filtered"
        output_path.mkdir(parents=True, exist_ok=True)
        raw_dir = input_path / "raw"
        pcap_files = list(raw_dir.glob("*.pcap")) + list(raw_dir.glob("*.pcapng"))
        for pcap_file in pcap_files:
            output_file = output_path / pcap_file.name
            filter_packets(str(pcap_file), str(output_file))
    else:
        logger.error(f"Step '{args.step}' not yet implemented for individual processing")

if __name__ == "__main__":
    main() 