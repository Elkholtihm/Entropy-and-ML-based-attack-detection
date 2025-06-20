import pandas as pd
import numpy as np
from collections import Counter
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ai_component import ai_detector
from collections import deque
import heapq
import random
import string





class Metrics():
    def __init__(self):
        
        self.attack_distributions = {
            'ddos': {
                'benign_median': 2.959737029113381,
                'attack_median': 2.715957320949175
            },
            'portscan': {
                'benign_median': 2.539185952823221,
                'attack_median': 3.041446071165522
            },
            'hulk': {
                'benign_median': 3.116848445430279,
                'attack_median': 3.216446071165522
            },
            'slowhttptest': {
                'benign_median': 4.271928094887363,
                'attack_median': 2.8393538721672007
            }
        }
        
    
    def calculate_entropy(self,values):
        """Calculate Shannon entropy for a list of values."""
        try:
            counts = Counter(values)  # Count occurrences of each unique value
            total = sum(counts.values())  # Total number of elements
            if total == 0:
                return 0.0
            probabilities = [count / total for count in counts.values()]  # Probabilities of each unique value
            entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)  # Shannon entropy formula
            return entropy
        except:
            return 0.0

    def compute_entropy_for_attack_detection(self,df):
        """
        Compute entropy values for detecting different types of attacks.
        
        Parameters:
        -----------
        df : pandas DataFrame
            DataFrame containing network packet features with at least the columns needed
            for each attack type detection.
            
        Returns:
        --------
        dict
            Dictionary containing entropy values for each attack type.
        """
        # Feature columns for different attack types
        feature_columns = {
            'ddos': ["flow_packets_per_sec", "flow_bytes_per_sec", "packet_length_mean", "syn_flag_count"],
            'portscan': ["destination_port", "flow_duration", "flow_packets_per_sec", "syn_flag_count"],
            'hulk': ["flow_packets_per_sec", "flow_bytes_per_sec", "packet_length_mean", "syn_flag_count"],
            'slowhttptest': ["flow_duration", "flow_bytes_per_sec", "flow_packets_per_sec", "flow_iat_mean"]
        }
    
        
        # Convert columns to string for entropy calculation
        for columns in feature_columns.values():
            for col in columns:
                if col in df.columns:
                    df[col] = df[col].astype(str)
        
        # Calculate entropy for each attack type
        entropy_results = {}
        
        for attack_type, columns in feature_columns.items():
            # Verify all required columns exist
            missing_columns = [col for col in columns if col not in df.columns]
            if missing_columns:
                print(f"Warning: Missing columns for {attack_type} detection: {missing_columns}")
                entropy_results[f"{attack_type}_entropy"] = None
                continue
                
            # Calculate entropy for each column
            entropies = []
            for col in columns:
                entropy = self.calculate_entropy(df[col].values)
                entropies.append(entropy)
                
            # Average entropy across all features for this attack type
            avg_entropy = np.mean(entropies) if entropies else 0.0
            entropy_results[f"{attack_type}_entropy"] = avg_entropy
        
        return entropy_results


    def calculate_entropyvalue(self, df):
        """
        Detect potential attacks based on entropy values and research-based distribution medians.
        
        Args:
            entropy_values (dict): Dictionary of entropy values per attack type
            
        Returns:
            dict: Dictionary of attack detection results
        """
        entropy_values = self.compute_entropy_for_attack_detection(df)
        attack_detection = {}
        
        # Determine if attacks are detected based on proximity to distribution medians
        for attack_type in ['ddos', 'portscan', 'hulk', 'slowhttptest']:
            entropy_key = f"{attack_type}_entropy"
            current_entropy = entropy_values.get(entropy_key)
            
            # Skip if entropy calculation failed
            if current_entropy is None:
                attack_detection[attack_type] = {
                    'detected': 0,
                    'confidence': 0.0,
                    'reason': 'Missing data'
                }
                continue
            
            benign_median = self.attack_distributions[attack_type]['benign_median']
            attack_median = self.attack_distributions[attack_type]['attack_median']
            
            # Calculate distances to benign and attack medians
            distance_to_benign = abs(current_entropy - benign_median)
            distance_to_attack = abs(current_entropy - attack_median)
            
            # Determine if attack is detected based on closest median
            is_attack = 1 if distance_to_attack < distance_to_benign else 0
            
            # Calculate confidence score (0-1 range)
            total_distance = distance_to_benign + distance_to_attack
            confidence = 0.5 if total_distance == 0 else distance_to_benign / total_distance
            
            attack_detection[attack_type] = {
                'detected': is_attack,
                'confidence': round(confidence, 4),
                'entropy_value': current_entropy
            }
        
        return attack_detection


    def calculate_aiprediction(self, packet_data):
        return ai_detector.AI_Detector.calculate_aiprediction(packet_data)
    


    @staticmethod
    def calculate_huffmanstat(input_deque):
        """
        Perform Huffman encoding on a deque of dictionaries and calculate various metrics.

        Args:
            input_deque (deque): A deque containing dictionaries with symbol frequencies.

        Returns:
            dict: A dictionary containing codelength, avg_codelength, entropy, redundancy, and compression rate.
        """
        # Combine all dictionaries into a single frequency dictionary
        frequency = Counter()
        for d in input_deque:
            frequency.update(d)

        # Build the Huffman tree
        heap = [[weight, [symbol, ""]] for symbol, weight in frequency.items()]
        heapq.heapify(heap)
        while len(heap) > 1:
            lo = heapq.heappop(heap)
            hi = heapq.heappop(heap)
            for pair in lo[1:]:
                pair[1] = "0" + pair[1]
            for pair in hi[1:]:
                pair[1] = "1" + pair[1]
            heapq.heappush(heap, [lo[0] + hi[0]] + lo[1:] + hi[1:])

        # Extract the Huffman codes
        huffman_codes = sorted(heapq.heappop(heap)[1:], key=lambda p: (len(p[-1]), p))
        codelength = {symbol: len(code) for symbol, code in huffman_codes}

        # Calculate probabilities
        total_frequency = sum(frequency.values())
        probabilities = {symbol: freq / total_frequency for symbol, freq in frequency.items()}

        # Calculate average code length
        avg_codelength = sum(probabilities[symbol] * codelength[symbol] for symbol in codelength)

        # Calculate entropy
        entropy = -sum(p * np.log2(p) for p in probabilities.values() if p > 0)

        # Calculate redundancy
        redundancy = avg_codelength - entropy

        # Calculate compression rate
        compression_rate = entropy / avg_codelength if avg_codelength > 0 else 0

        return {
            "average_code_length": float(avg_codelength),
            "entropy_value": float(entropy),
            "redundancy": float(redundancy),
            "compression_rate": float(compression_rate)
        }


