import pandas as pd
import numpy as np
import pickle
from sklearn.preprocessing import LabelEncoder


class AI_Detector:
    selected_columns = [
        ' Flow Duration', 'Bwd Packet Length Max', ' Bwd Packet Length Min',
        ' Bwd Packet Length Mean', ' Bwd Packet Length Std', ' Flow IAT Std',
        ' Flow IAT Max', 'Fwd IAT Total', ' Fwd IAT Std', ' Fwd IAT Max',
        ' Min Packet Length', ' Max Packet Length', ' Packet Length Mean',
        ' Packet Length Std', ' Packet Length Variance', ' Average Packet Size',
        ' Avg Bwd Segment Size', 'Idle Mean', ' Idle Max', ' Idle Min'
    ]

    @classmethod
    def process_data(cls,packet_data):
        def from_dict_to_features(data_dict):
            """
            Extracts features from a dictionary based on selected columns.

            Args:
            data_dict (dict): Dictionary containing the data.

            Returns:
            numpy.ndarray: Extracted features as a NumPy array.
            """
            features = []
            for column in cls.selected_columns:
                features.append(data_dict.get(column, 0))  # Default to 0 if key is missing
            return np.array(features).reshape(1, -1)

        X_features = from_dict_to_features(packet_data)
        return X_features
    @classmethod
    def load_model_and_scaler(cls,model_path, scaler_path):
        from tensorflow.keras.models import load_model
        """
        Charge le modèle entraîné et le scaler.
        
        Args:
            model_path (str): Chemin vers le fichier du modèle sauvegardé
            scaler_path (str): Chemin vers le fichier du scaler sauvegardé
            
        Returns:
            tuple: (model, scaler) - Le modèle chargé et le scaler
        """
        model = load_model(model_path)
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
        return model, scaler
    @classmethod
    def predict(cls, model, scaler, X_features):
        """
        Retourne la classe prédite (indice max) et sa probabilité.
        """
        X_scaled = scaler.transform(X_features)
        y_pred_proba = model.predict(X_scaled)

        # On suppose ici une sortie softmax : y_pred_proba.shape = (1, n_classes)
        class_index = np.argmax(y_pred_proba, axis=1)[0]  # ex: 1
        class_proba = y_pred_proba[0][class_index]        # ex: 0.987
        
        return class_index, class_proba
    @classmethod
    def calculate_aiprediction(cls,packet_data):
        model_path = "ai_component/model_v2.h5"
        scaler_path = "ai_component/scaler_detection_intrusion_v2.pkl"
        X_features=cls.process_data(packet_data)
        model, scaler = cls.load_model_and_scaler(model_path, scaler_path)
        y_pred, y_pred_proba = cls.predict(model, scaler, X_features)

        return {
            "predicted_label": int(y_pred),  # Convert to int for better readability
            "confidence_score": float(y_pred_proba),  # Convert to float for better readability
            "model_version": "v2.0",
            "timestamp": pd.Timestamp.now().isoformat()  # Use ISO format for timestamp
        }
    

    

# import random
# fake_packet_data = {
#     ' Flow Duration': random.randint(10000, 200000),
#     'Bwd Packet Length Max': random.randint(500, 1500),
#     ' Bwd Packet Length Min': random.randint(50, 500),
#     ' Bwd Packet Length Mean': random.uniform(100, 1000),
#     ' Bwd Packet Length Std': random.uniform(10, 500),
#     ' Flow IAT Std': random.uniform(5, 50),
#     ' Flow IAT Max': random.randint(500, 2000),
#     'Fwd IAT Total': random.randint(1000, 5000),
#     ' Fwd IAT Std': random.uniform(10, 100),
#     ' Fwd IAT Max': random.randint(200, 1000),
#     ' Min Packet Length': random.randint(20, 100),
#     ' Max Packet Length': random.randint(500, 1500),
#     ' Packet Length Mean': random.uniform(100, 1000),
#     ' Packet Length Std': random.uniform(10, 300),
#     ' Packet Length Variance': random.uniform(1000, 50000),
#     ' Average Packet Size': random.uniform(100, 800),
#     ' Avg Bwd Segment Size': random.uniform(100, 600),
#     'Idle Mean': random.randint(1000, 10000),
#     ' Idle Max': random.randint(2000, 15000),
#     ' Idle Min': random.randint(500, 5000)
# }

# # Lancer la prédiction
# result = AI_Detector.calculate_aiprediction(fake_packet_data)

# # Afficher le résultat
# print("Résultat de la prédiction AI :")
# print(result)
