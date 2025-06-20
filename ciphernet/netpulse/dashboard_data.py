
import mysql.connector
from datetime import datetime
from decouple import Config, RepositoryEnv
import json

config = Config(RepositoryEnv(r"C:\Users\dell\Desktop\ciphernet\.env"))

# Access MySQL credentials from the .env file using decouple
MYSQL_HOST = config('MYSQL_HOST')
MYSQL_PORT = config('MYSQL_PORT', cast=int)
MYSQL_USER = config('MYSQL_USER')
MYSQL_PASSWORD = config('MYSQL_PASSWORD')
MYSQL_DATABASE = config('MYSQL_DATABASE')

class DashboardData:
    def __init__(self):
        self.last_entropy_timestamp = None
        self.last_prediction_time = None
        self.last_huffman_timestamp = None
        
    def strvaluehandler(self,var):
        import json
        if isinstance(var, str):
            try:
                var = json.loads(var)  # Parse JSON string to dictionary
            except json.JSONDecodeError:
                pass
        return var
    def get_cards_data(self):
        from netpulse.models import AttackType, EntropyValue

        attack_types = AttackType.objects.all()
        cards_data = {}

        for attack_type in attack_types:
            query = EntropyValue.objects.filter(attack_type_id=attack_type.id)
            last_record = query.order_by('-timestamp').first()

            if last_record:
                cards_data[attack_type.name] = {
                    "entropy_value": self.strvaluehandler(last_record.entropy_value)["entropy_value"],
                    "timestamp": last_record.timestamp.strftime("%H:%M:%S")
                }
                # Update the last processed timestamp
                self.last_entropy_timestamp = last_record.timestamp
        return cards_data
    #================================================================================================

    @staticmethod
    def get_cards():
        # Connect to your MySQL DB
        connection = mysql.connector.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE
            )

        cursor = connection.cursor()

        sql = """
            SELECT
                ev.entropy_value,
                ev.timestamp AS entropy_timestamp,
                at.name AS attack_type,
                np.label AS packet_label,
                w.id AS window_id
            FROM
                netpulse_entropyvalue ev
            JOIN
                netpulse_window w ON ev.window_id = w.id
            JOIN
                netpulse_attacktype at ON ev.attack_type_id = at.id
            JOIN
                netpulse_networkpacket np ON w.max_packet_id = np.id
            ORDER BY
                ev.timestamp DESC
            LIMIT 4;
        """
        cursor.execute(sql)
        rows = cursor.fetchall()

        result = {}

        for row in rows:
            entropy_value_raw, entropy_timestamp, attack_type, packet_label, window_id = row

            # If JSON is returned as string, parse it
            if isinstance(entropy_value_raw, str):
                entropy_value = json.loads(entropy_value_raw)
            else:
                entropy_value = entropy_value_raw

            # Ensure the timestamp is formatted correctly and include it in the dictionary
            if isinstance(entropy_timestamp, datetime):
                entropy_value['timestamp'] = entropy_timestamp.strftime("%H:%M:%S")

            entropy_value['label'] = 1 if attack_type.lower() == packet_label.lower() else 0
            result[attack_type.lower()] = entropy_value

        cursor.close()
        connection.close()
        return result

    #================================================================================================
    def get_aiprediction_data(self):
        from netpulse.models import AIPrediction

        query = AIPrediction.objects.order_by('-prediction_time')
        last_prediction = query.first()

        if last_prediction:
            self.last_prediction_time = last_prediction.prediction_time
            return {
                "packet_id": last_prediction.packet.id,
                "predicted_label": last_prediction.predicted_label,
                "confidence_score": last_prediction.confidence_score,
                "model_version": last_prediction.model_version,
                "prediction_time": last_prediction.prediction_time
            }
        return {}
    @staticmethod
    def get_huffman_data():
        try:
            # Connect to the MySQL database
            connection = mysql.connector.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE
            )

            cursor = connection.cursor(dictionary=True)

            # SQL query to get the latest huffman statistics based on the max timestamp
            query = """
                SELECT
                    hs.average_code_length,
                    hs.compression_rate,
                    hs.entropy_value,
                    hs.redundancy,
                    np.timestamp AS max_packet_timestamp
                FROM
                    netpulse_huffmanstat hs
                JOIN
                    netpulse_window w ON hs.window_id = w.id
                JOIN
                    netpulse_networkpacket np ON w.max_packet_id = np.id
                ORDER BY np.timestamp DESC 
                LIMIT 1;
            """

            # Execute the query
            cursor.execute(query)

            # Fetch the result
            result = cursor.fetchone()
            # If a record is found, return it in the desired format
            if result:
                return {
                    "average_code_length": float(result['average_code_length']) if result['average_code_length'] is not None else 0.0,
                    "compression_rate": float(result['compression_rate']) if result['compression_rate'] is not None else 0.0,
                    "entropy_value": float(result['entropy_value']) if result['entropy_value'] is not None else 0.0,
                    "redundancy": float(result['redundancy']) if result['redundancy'] is not None else 0.0,
                    "time_range": result['max_packet_timestamp'].strftime("%H:%M:%S") if result['max_packet_timestamp'] else ""
                }
            else:
                return None

        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return None
        finally:
            # Close the cursor and connection
            if cursor:
                cursor.close()
            if connection:
                connection.close()






