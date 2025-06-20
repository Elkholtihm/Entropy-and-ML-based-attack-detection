import os
import sys
import django
from pathlib import Path


DJANGO_PROJECT_PATH = Path(__file__).parent.parent
sys.path.append(str(DJANGO_PROJECT_PATH))

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ciphernet.settings')
django.setup()


from django.db import transaction
from django.db.models import Max
from django.db.utils import ProgrammingError
from netpulse.models import NetworkPacket, EntropyValue, AIPrediction, HuffmanStat, Window, AttackType

class Storer:
    """Django ORM version of the Storer class"""
    
    def __init__(self):
        # No need for database connection setup - Django handles this
        self.attack_type_map = {
            'ddos': 1,
            'portscan': 2,
            'hulk': 3,
            'slowhttptest': 4
        }
        self._ensure_attack_types()
    
    def _ensure_attack_types(self):
        """Ensure attack types exist in the database"""
        try:
            attack_names = ['ddos', 'portscan', 'hulk', 'slowhttptest']
            for name in attack_names:
                AttackType.objects.get_or_create(name=name)
        except ProgrammingError as e:
            print(f"Warning: Could not create attack types - database tables may not exist yet: {e}")
    
    def store_networkpacket(self, data):
        """Store network packet data using Django ORM"""
        try:
            # Map your data fields to the actual model fields
            packet_data = {}
            
            # Direct mappings for fields that match
            direct_fields = [
                'src_ip', 'dst_ip', 'destination_port', 'syn_flag_count', 
                'ack_flag_count', 'psh_flag_count', 'urg_flag_count',
                'fwd_packet_length_mean', 'bwd_packet_length_mean', 
                'packet_length_mean', 'flow_packets_per_sec', 'flow_iat_mean',
                'flow_iat_std', 'flow_iat_min', 'flow_iat_max', 'label',
                'total_fwd_packets_length', 'total_bwd_packets_length'
            ]
            
            for field in direct_fields:
                if field in data and data[field] is not None:
                    packet_data[field] = data[field]
            
            packet = NetworkPacket.objects.create(**packet_data)
            print(f"Network packet stored successfully with ID: {packet.id}")
            return packet
            
        except Exception as e:
            print(f"Error storing network packet: {e}")
            print(f"Available fields in NetworkPacket model:")
            print([f.name for f in NetworkPacket._meta.get_fields()])
            raise
    
    def store_entropyvalue(self, data, window_id):
        """Store entropy values using Django ORM"""
        try:
            window = Window.objects.get(id=window_id)
            
            with transaction.atomic():  # Ensure all operations succeed or fail together
                for attack_name, values in data.items():
                    attack_type = AttackType.objects.get(name=attack_name)
                    
                    EntropyValue.objects.create(
                        entropy_value=values,  # Django JSONField handles JSON serialization
                        attack_type=attack_type,
                        window=window
                    )
            
            print("Entropy value data inserted successfully.")
        except Window.DoesNotExist:
            print(f"Window with ID {window_id} does not exist")
            raise
        except AttackType.DoesNotExist as e:
            print(f"Attack type not found: {e}")
            raise
        except Exception as e:
            print(f"Error storing entropy values: {e}")
            raise
    
    def store_aiprediction(self, data):
        """Store AI prediction using Django ORM"""
        try:
            packet = NetworkPacket.objects.get(id=data['packet_id'])
            
            prediction = AIPrediction.objects.create(
                packet=packet,
                predicted_label=data['predicted_label'],
                confidence_score=data['confidence_score'],
                model_version=data.get('model_version', 'v1.0')
            )
            print(f"AI Prediction stored successfully with ID: {prediction.id}")
            return prediction
        except NetworkPacket.DoesNotExist:
            print(f"Packet with ID {data['packet_id']} does not exist")
            raise
        except Exception as e:
            print(f"Error storing AI prediction: {e}")
            raise
    
    def store_huffmanstat(self, data, window_id):
        """Store Huffman statistics using Django ORM"""
        try:
            window = Window.objects.get(id=window_id)
            
            huffman_stat = HuffmanStat.objects.create(
                window=window,
                average_code_length=data["average_code_length"],
                compression_rate=data["compression_rate"],
                entropy_value=data["entropy_value"],
                redundancy=data["redundancy"]
            )
            print(f"Huffman stats stored successfully with ID: {huffman_stat.id}")
            return huffman_stat
        except Window.DoesNotExist:
            print(f"Window with ID {window_id} does not exist")
            raise
        except Exception as e:
            print(f"Error storing Huffman stats: {e}")
            raise
    
    def store_window(self, data):
        """Store window data using Django ORM"""
        try:
            window = Window.objects.create(
                min_packet_id=data['min_packet_id'],
                max_packet_id=data['max_packet_id']
            )
            print(f"Window data stored successfully with ID: {window.id}")
            return window
        except Exception as e:
            print(f"Error storing window data: {e}")
            raise
    
    @staticmethod
    def get_max_packet_id():
        """Get the maximum packet ID using Django ORM"""
        try:
            max_id = NetworkPacket.objects.aggregate(Max('id'))['id__max']
            return max_id if max_id is not None else 0
        except ProgrammingError:
            print("Warning: NetworkPacket table doesn't exist yet. Returning 0.")
            return 0
    
    @staticmethod
    def get_max_window_id():
        """Get the maximum window ID using Django ORM"""
        try:
            max_id = Window.objects.aggregate(Max('id'))['id__max']
            return max_id if max_id is not None else 0
        except ProgrammingError:
            print("Warning: Window table doesn't exist yet. Returning 0.")
            return 0