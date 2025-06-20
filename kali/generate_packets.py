import pandas as pd

import random

import time

from scapy.all import *

import json



class PacketSender:

    def __init__(self, dataset_path):

        self.dataset_path = dataset_path



        self.packet_sending_columns = [

            # Include Label first

            'Label',

            

            # Timing and Flow Metrics

            'Flow IAT Mean',

            'Flow IAT Std',

            'Flow IAT Min',

            'Flow IAT Max',

            'Flow Duration',

            'Flow Packets/s',

            'Flow Bytes/s',

            'Fwd IAT Max',

            'Fwd IAT Total',

            'Fwd IAT Std',

            

            # Packet Characteristics

            'Destination Port',

            'Total Length of Fwd Packets',

            'Total Length of Bwd Packets',

            'Min Packet Length',

            'Max Packet Length',

            'Average Packet Size',

            

            # Idle Times

            'Idle Mean',

            'Idle Min',

            'Idle Max',

            

            # Flag Counts

            'SYN Flag Count',

            'ACK Flag Count',

            'PSH Flag Count',

            'URG Flag Count',

            

            # Packet Length Metrics

            'Fwd Packet Length Mean',

            'Packet Length Mean',

            'Packet Length Std',

            'Packet Length Variance',

            'Avg Bwd Segment Size',

            

            # Backward Packet Metrics

            'Bwd Packet Length Min',

            'Bwd Packet Length Max',

            'Bwd Packet Length Mean',

            'Bwd Packet Length Std'

        ]



        self.critical_columns = ['Destination Port', 'Flow IAT Mean', 'Flow IAT Std']



    def random_ip(self):

        return "192.168.56.1"



    def has_null_values(self, row):

        for column in self.critical_columns:

            if pd.isna(row[column]):

                return True

        null_count = row[self.packet_sending_columns].isna().sum()

        return null_count > len(self.packet_sending_columns) * 0.3



    def create_custom_payload(self, row):

        payload_dict = {}

        for column in self.packet_sending_columns:

            try:

                payload_key = column.replace(' ', '_').replace('/', '_per_').lower()

                if pd.isna(row[column]):

                    payload_dict[payload_key] = 0

                else:

                    if column == 'Destination Port':

                        payload_dict[payload_key] = int(row[column])

                    else:

                        payload_dict[payload_key] = float(row[column])

            except Exception:

                payload_dict[payload_key] = str(row[column])

        return json.dumps(payload_dict).encode('utf-8')



    def simulate_realistic_timing(self, row):

        base_wait_time = row['Flow IAT Mean']

        std_dev = row['Flow IAT Std']

        wait_time = max(0, random.gauss(base_wait_time, std_dev))

        return 0.3 # override timing simulation to disable sleep if desired



    def send_all_packets(self):

        print("[*] Reading entire dataset into memory...")

        try:

            df = pd.read_csv(self.dataset_path)

        except Exception as e:

            print(f"[!] Failed to read dataset: {e}")

            return



        df.columns = df.columns.str.strip()



        try:

            df = df[self.packet_sending_columns]

        except KeyError as e:

            print(f"[!] Column error: {e}. Make sure all required columns exist in the CSV.")

            print(f"[!] Available columns: {', '.join(df.columns)}")

            return



        packets_sent = 0

        rows_skipped = 0



        for _, row in df.iterrows():

            try:

                if self.has_null_values(row):

                    rows_skipped += 1

                    if rows_skipped % 10 == 0:

                        print(f"[!] Skipped {rows_skipped} rows due to null values")

                    continue



                src_ip = self.random_ip()

                dst_ip = self.random_ip()

                payload = self.create_custom_payload(row)



                packet = IP(src=src_ip, dst=dst_ip) / TCP(

                    dport=int(row['Destination Port']),

                    flags="S"

                ) / Raw(load=payload)



                send(packet, verbose=False)

                packets_sent += 1



                if packets_sent % 10 == 0:

                    print(f"[+] Sent {packets_sent} packets so far")



                time.sleep(self.simulate_realistic_timing(row))



                if packets_sent % 50 == 0:

                    import gc

                    gc.collect()



            except Exception as e:

                print(f"[!] Skipped a row due to error: {e}")

                rows_skipped += 1



        print(f"[+] Finished sending packets: {packets_sent} sent, {rows_skipped} skipped")



if __name__ == "__main__":

    while True:

        sender = PacketSender("data.csv")

        sender.send_all_packets()

