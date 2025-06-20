import os
import sys
import django
from pathlib import Path

# Set up Django environment (add this at the top)
DJANGO_PROJECT_PATH = Path(__file__).parent.parent
sys.path.append(str(DJANGO_PROJECT_PATH))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ciphernet.settings')
django.setup()

from scapy.all import *
from collections import deque
from datetime import datetime
from decouple import config
from storer import Storer
from metrics import Metrics
import pandas as pd
import json 
import ast


class PacketReceiver:
    def __init__(self, window_size=20):
        """
        Initialize PacketReceiver with sliding window functionality
        
        Args:
            window_size (int): Size of the sliding window for metrics calculation
        """
        self.window_size = window_size
        self.packet_window = deque(maxlen=window_size)
        
        # Updated calls to work with Django ORM Storer
        self.window_id = Storer.get_max_window_id() + 1
        self.packet_id = Storer.get_max_packet_id() + 1
        
        # Initialize metrics and storer (no mysql_config needed for Django ORM)
        self.metrics = Metrics()
        self.storer = Storer()
        
        print(f"Initialized PacketReceiver with {window_size}-packet sliding window")

    def safe_parse_payload(self, payload_str):
        """
        Safely parse payload string into dictionary and skip if malformed
        """
        try:
            # Decode bytes to string
            decoded_payload = payload_str.decode('utf-8')
            
            # Find opening and closing braces for proper JSON
            if '{' in decoded_payload and '}' in decoded_payload:
                start_idx = decoded_payload.find('{')
                end_idx = decoded_payload.rfind('}') + 1
                if start_idx < end_idx:
                    try:
                        payload_dict = json.loads(decoded_payload[start_idx:end_idx])
                        
                        # Fix column name mappings
                        name_mappings = {
                            'Flow Packets/s': 'flow_packets_per_sec',
                            'flow_packets_per_s': 'flow_packets_per_sec',
                            'Flow Bytes/s': 'flow_bytes_per_sec',
                            'flow_bytes_per_s': 'flow_bytes_per_sec',
                            'Packet Length Mean': 'packet_length_mean',
                            'Destination Port': 'destination_port',
                            'Flow Duration': 'flow_duration',
                            'Flow IAT Mean': 'flow_iat_mean',
                            'SYN Flag Count': 'syn_flag_count'
                        }
                        
                        # Apply mappings
                        for old_name, new_name in name_mappings.items():
                            if old_name in payload_dict:
                                payload_dict[new_name] = payload_dict.pop(old_name)
                                
                        return payload_dict
                        
                    except json.JSONDecodeError:
                        print(f"Malformed JSON, skipping packet")
                        return {}
                else:
                    print(f"Invalid JSON structure, skipping packet")
                    return {}
            else:
                print(f"No valid JSON found, skipping packet")
                return {}
                
        except UnicodeDecodeError:
            print(f"Unable to decode payload, skipping packet")
            return {}

    def process_packet(self, packet):
        """Process each incoming packet"""
        if not (IP in packet and TCP in packet and Raw in packet):
            return

        try:
            # Extract packet data
            parsed_payload = self.safe_parse_payload(packet[Raw].load)
            flags = {
                'syn_flag_count': packet[TCP].flags.S,
                'ack_flag_count': packet[TCP].flags.A,
                'psh_flag_count': packet[TCP].flags.P,
                'urg_flag_count': packet[TCP].flags.U,
            }
            if len(parsed_payload) > 0:
                # Combine all fields in one flat dict
                packet_data = {
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'destination_port': parsed_payload.get('destination_port'),
                    'total_fwd_packets_length': parsed_payload.get('total_length_of_fwd_packets'),
                    'total_bwd_packets_length': parsed_payload.get('total_length_of_bwd_packets'),
                    'syn_flag_count': flags['syn_flag_count'],
                    'ack_flag_count': flags['ack_flag_count'],
                    'psh_flag_count': flags['psh_flag_count'],
                    'urg_flag_count': flags['urg_flag_count'],
                    'fwd_packet_length_mean': parsed_payload.get('fwd_packet_length_mean'),
                    'bwd_packet_length_mean': parsed_payload.get('bwd_packet_length_mean'),
                    'packet_length_mean': parsed_payload.get('packet_length_mean'),
                    'flow_packets_per_sec': parsed_payload.get('flow_packets_per_sec'),
                    'flow_bytes_per_sec': parsed_payload.get('flow_bytes_per_sec'),
                    'flow_duration': parsed_payload.get('flow_duration'),
                    'flow_iat_mean': parsed_payload.get('flow_iat_mean'),
                    'flow_iat_std': parsed_payload.get('flow_iat_std'),
                    'flow_iat_min': parsed_payload.get('flow_iat_min'),
                    'flow_iat_max': parsed_payload.get('flow_iat_max'),
                    'label': parsed_payload.get('label', 'unknown'),  # Default to 'unknown' if not present
                }

                # Store individual packet data
                stored_packet = self.storer.store_networkpacket(packet_data)
                
                # Get AI prediction for this single packet
                ai_prediction = self.metrics.calculate_aiprediction(packet_data)
                data = {'packet_id': stored_packet.id, **ai_prediction}
                
                # Store AI prediction
                self.storer.store_aiprediction(data)

                # Update sliding window
                if len(self.packet_window) == self.window_size:
                    self.packet_window.popleft()
                self.packet_window.append(packet_data)

                # Process window if full
                if len(self.packet_window) == self.window_size:
                    self.process_window()

        except Exception as e:
            print(f"Error processing packet: {str(e)}")
            # No need for rollback with Django ORM - it handles transactions automatically

    def process_window(self):
        """Calculate and store window-based metrics"""
        try:
            # Store window metadata
            window_data = {
                'min_packet_id': self.window_id, 
                'max_packet_id': self.window_id + self.window_size - 1
            }
            self.storer.store_window(window_data)
            
            # Calculate window metrics
            df = pd.DataFrame(list(self.packet_window))
            
            # Calculate and store entropy values
            entropyvalue = self.metrics.calculate_entropyvalue(df)
            self.storer.store_entropyvalue(entropyvalue, self.window_id)
            
            # Calculate and store Huffman stats
            huffman_stats = self.metrics.calculate_huffmanstat(df)
            self.storer.store_huffmanstat(huffman_stats, self.window_id)
            
            print(f"Window {self.window_id} processed successfully")
            
        except Exception as e:
            print(f"Error processing window: {str(e)}")
            
        # Increment window ID for next window
        self.window_id += 1

    def start_capture(self, interface, filter_exp="tcp"):
        """Start packet capture on specified interface"""
        print(f"Starting capture on {interface} with filter '{filter_exp}'")
        sniff(
            iface=interface,
            filter=filter_exp,
            prn=self.process_packet,
            store=False
        )

    def __del__(self):
        """Cleanup resources - Django handles database connections automatically"""
        pass  # No manual cleanup needed with Django ORM


# Example Usage
if __name__ == "__main__":
    print(f"==============================Current working directory: {os.getcwd()}")
    # No database config needed - Django handles this through settings
    receiver = PacketReceiver(window_size=20)
    
    try:
        receiver.start_capture(interface='Ethernet 4')
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
    finally:
        del receiver