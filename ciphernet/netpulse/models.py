from django.db import models

# Create your models here.


class NetworkPacket(models.Model):
    id = models.AutoField(primary_key=True)  # Explicitly adding an id field as primary key
    timestamp = models.DateTimeField(auto_now_add=True)
    src_ip = models.GenericIPAddressField()  # Changed to GenericIPAddressField for IP addresses
    dst_ip = models.GenericIPAddressField()  # Changed to GenericIPAddressField for IP addresses
    destination_port = models.IntegerField()
    total_fwd_packets_length = models.FloatField(default=0)
    total_bwd_packets_length = models.FloatField(default=0)
    syn_flag_count = models.IntegerField(default=0)
    ack_flag_count = models.IntegerField(default=0)
    psh_flag_count = models.IntegerField(default=0)
    urg_flag_count = models.IntegerField(default=0)
    fwd_packet_length_mean = models.FloatField(default=0)
    bwd_packet_length_mean = models.FloatField(default=0)
    packet_length_mean = models.FloatField(default=0)
    flow_packets_per_sec = models.FloatField(default=0)
    fwd_packets_per_sec = models.FloatField(default=0)
    bwd_packets_per_sec = models.FloatField(default=0)
    flow_iat_mean = models.FloatField(default=0)
    flow_iat_std = models.FloatField(default=0)
    flow_iat_min = models.FloatField(default=0)
    flow_iat_max = models.FloatField(default=0)
    label = models.CharField(max_length=50, default='unknown')  # e.g. "normal", "DDoS", etc.
    def __str__(self):
        return f"Packet {self.id}"



class AttackType(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class Window(models.Model):
    min_packet = models.ForeignKey(
        NetworkPacket, on_delete=models.CASCADE, related_name='window_min_packet'
    )
    max_packet = models.ForeignKey(
        NetworkPacket, on_delete=models.CASCADE, related_name='window_max_packet'
    )

    def __str__(self):
        return f"Window from {self.min_packet.timestamp} to {self.max_packet.timestamp} for {self.attack_type.name}"
    


class EntropyValue(models.Model):
    attack_type = models.ForeignKey(AttackType, on_delete=models.SET_NULL, null=True)
    entropy_value = models.JSONField(default=dict)
    timestamp = models.DateTimeField(auto_now_add=True)
    window = models.ForeignKey(Window, on_delete=models.CASCADE, related_name='entropy_values', default=0)

    def __str__(self):
        return f"Entropy Value for {self.attack_type.name if self.attack_type else 'Unknown'} at {self.timestamp}"
    

class HuffmanStat(models.Model):
    window = models.OneToOneField(
        Window, on_delete=models.CASCADE, related_name='huffman_stat'
    )
    average_code_length = models.FloatField(default=0)
    compression_rate = models.FloatField(default=0)
    entropy_value = models.FloatField(default=0)
    redundancy = models.FloatField(default=0)

    def __str__(self):
        return f"Huffman Stat for {self.window.attack_type.name} from {self.window.min_packet.timestamp} to {self.window.max_packet.timestamp}"
    

class AIPrediction(models.Model):
    packet = models.OneToOneField(
        NetworkPacket, on_delete=models.SET_NULL, null=True, related_name='ai_prediction'
    )
    predicted_label = models.CharField(max_length=50)  # e.g. "normal", "DDoS", etc.
    confidence_score = models.FloatField(default=0)    # e.g. 0.85
    model_version = models.CharField(max_length=30, default="v1.0")
    prediction_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Prediction for {self.packet.id}: {self.predicted_label} with confidence {self.confidence_score}"