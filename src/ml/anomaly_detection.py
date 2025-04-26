import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

class AnomalyDetector:
    def __init__(self, algorithm='isolation_forest'):
        self.scaler = StandardScaler()
        self.algorithm = algorithm
        
        if algorithm == 'isolation_forest':
            self.model = IsolationForest(n_estimators=100, contamination=0.05)
        else:  # one-class SVM
            self.model = OneClassSVM(nu=0.05, kernel="rbf")

    def preprocess_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Prepare log features for anomaly detection"""
        features = pd.DataFrame()
        
        # Numerical features
        if 'status' in df.columns:
            features['status'] = df['status']
        if 'bytes' in df.columns:
            features['bytes'] = df['bytes']
        
        # Categorical features (one-hot encoded)
        if 'protocol' in df.columns:
            protocols = pd.get_dummies(df['protocol'], prefix='proto')
            features = pd.concat([features, protocols], axis=1)
            
        # Temporal features
        time_col = 'timestamp' if 'timestamp' in df.columns else 'time'
        if time_col in df.columns:
            features['hour'] = df[time_col].dt.hour
            features['day_of_week'] = df[time_col].dt.dayofweek
            
        return features.fillna(0)

    def detect(self, df: pd.DataFrame) -> pd.DataFrame:
        """Run anomaly detection on logs"""
        features = self.preprocess_features(df)
        scaled_features = self.scaler.fit_transform(features)
        
        predictions = self.model.fit_predict(scaled_features)
        df['anomaly_score'] = -self.model.decision_function(scaled_features)  # Higher = more anomalous
        df['is_anomaly'] = predictions == -1
        
        return df