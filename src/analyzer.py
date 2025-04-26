import pandas as pd
from collections import Counter
from typing import List, Dict, Any, Optional
import numpy as np
from .nlp.entity_extractor import LogEntityExtractor
from .nlp.text_classifier import LogClassifier
from .ml.anomaly_detection import AnomalyDetector
from .ml.log_clustering import LogClusterer

class LogAnalyzer:
    def __init__(self, df: Optional[pd.DataFrame] = None):
        self.df = df
        self.entity_extractor = LogEntityExtractor()
        self.classifier = LogClassifier()
        self.anomaly_detector = AnomalyDetector(algorithm='isolation_forest')
        self.clusterer = LogClusterer(n_clusters=5, algorithm='kmeans')
        
        if not hasattr(self.classifier.pipeline, 'classes_'):
            self._train_sample_classifier()

    def _train_sample_classifier(self):
        """Train classifier with comprehensive sample data"""
        sample_data = {
            'message': [
                # Authentication (25%)
                "Authentication failed", "Login successful", 
                "Invalid credentials", "Password changed",
                "User logged out", "SSH auth failed",
                "LDAP bind failed", "Kerberos ticket expired",
                
                # Network (25%)
                "Connection timeout", "TCP connection established",
                "UDP packet dropped", "Port 443 accessed",
                "Network interface down", "DNS resolution failed",
                "VPN connected", "Bandwidth exceeded",
                
                # Security (25%)
                "Port scan detected", "Brute force attempt",
                "Firewall blocked IP", "SQL injection attempt",
                "Malware detected", "XSS attack prevented",
                "Unauthorized access", "Certificate expired",
                
                # System/Error (25%)
                "Disk usage at 90%", "High CPU load",
                "Memory allocation failed", "Service restarted",
                "File not found", "Permission denied",
                "Configuration error", "Backup completed"
            ],
            'category': (
                ['authentication'] * 8 + 
                ['network'] * 8 + 
                ['security'] * 8 + 
                ['system'] * 4 + ['error'] * 4
            )
        }
        self.classifier.train(pd.DataFrame(sample_data))

    def detect_ml_anomalies(self) -> pd.DataFrame:
        """Machine learning based anomaly detection"""
        if self.df is None or len(self.df) < 10:
            return pd.DataFrame()
            
        try:
            features = self._prepare_ml_features()
            if features.empty:
                return pd.DataFrame()
                
            scaled = self.anomaly_detector.scaler.fit_transform(features)
            self.anomaly_detector.model.fit(scaled)  # Explicit fitting
            scores = -self.anomaly_detector.model.decision_function(scaled)
            
            result = self.df.copy()
            result['anomaly_score'] = scores
            result['is_anomaly'] = scores > 1.0  # Threshold
            
            return result[result['is_anomaly']].sort_values('anomaly_score', ascending=False)
        except Exception as e:
            print(f"ML anomaly detection failed: {str(e)}")
            return pd.DataFrame()

    def _prepare_ml_features(self) -> pd.DataFrame:
        """Prepare features for ML analysis"""
        features = pd.DataFrame()
        
        # Numerical features
        if 'status' in self.df.columns:
            features['status'] = pd.to_numeric(self.df['status'], errors='coerce').fillna(0)
        if 'bytes' in self.df.columns:
            features['bytes'] = pd.to_numeric(self.df['bytes'], errors='coerce').fillna(0)
            
        # Categorical features
        if 'protocol' in self.df.columns:
            protocols = pd.get_dummies(self.df['protocol'].fillna('unknown'), prefix='proto')
            features = pd.concat([features, protocols], axis=1)
            
        # Temporal features
        time_col = next((col for col in ['timestamp', 'time'] if col in self.df.columns), None)
        if time_col and pd.api.types.is_datetime64_any_dtype(self.df[time_col]):
            features['hour'] = self.df[time_col].dt.hour
            features['day_of_week'] = self.df[time_col].dt.dayofweek
            
        return features.fillna(0)
    
    def detect_anomalies(self, method: str = 'hybrid') -> List[Dict[str, Any]]:
        """Detect anomalies using specified method
        
        Args:
            method: 'rules' (rule-based), 'ml' (machine learning), or 'hybrid'
            
        Returns:
            List of anomaly dictionaries with details
        """
        if self.df is None:
            return []
            
        if method == 'rules':
            return self._detect_rule_based_anomalies()
        elif method == 'ml':
            ml_results = self.detect_ml_anomalies()
            return ml_results.to_dict('records')
        else:  # hybrid
            rule_based = self._detect_rule_based_anomalies()
            ml_based = self.detect_ml_anomalies()
            return rule_based + (
                ml_based.to_dict('records') 
                if not ml_based.empty 
                else []
            )

    def _detect_rule_based_anomalies(self) -> List[Dict[str, Any]]:
        """Rule-based anomaly detection"""
        anomalies = []
        
        # 1. Failed authentication attempts
        if {'message', 'source_ip'}.issubset(self.df.columns):
            failed_auth = self.df[
                self.df['message'].str.contains(
                    r'fail|deny|invalid', 
                    case=False, 
                    na=False
                )
            ]
            for ip, count in failed_auth['source_ip'].value_counts().items():
                if count > 3:  # Threshold
                    related = failed_auth[failed_auth['source_ip'] == ip]
                    anomalies.append({
                        'type': 'Failed Auth Attempts',
                        'source_ip': ip,
                        'count': count,
                        'sample_messages': related['message'].tolist()[:3]
                    })
        
        # 2. Port scanning patterns
        if {'source_ip', 'port'}.issubset(self.df.columns):
            port_attempts = self.df.groupby(['source_ip', 'port']).size()
            for ip in port_attempts.index.get_level_values(0).unique():
                if len(port_attempts.loc[ip]) > 5:  # Unique ports threshold
                    anomalies.append({
                        'type': 'Port Scanning',
                        'source_ip': ip,
                        'ports_scanned': len(port_attempts.loc[ip])
                    })
        
        return anomalies

    def analyze_message(self, message: str) -> Dict[str, Any]:
        """Perform comprehensive analysis of a log message
        
        Args:
            message: The log message to analyze
            
        Returns:
            Dictionary containing:
            - category: predicted log category
            - confidence: prediction confidence (0-1)
            - risk_level: security risk assessment
            - entities: extracted entities
            - features: message characteristics
        """
        if not isinstance(message, str) or not message.strip():
            return {'error': 'Invalid message'}
            
        try:
            # NLP Analysis
            entities = self.entity_extractor.extract_entities(message)
            category, confidence = self.classifier.predict(message)
            
            return {
                'message': message,
                'category': category,
                'confidence': round(float(confidence), 2),
                'risk_level': self._assess_security_risk(category, entities),
                'entities': entities,
                'features': {
                    'length': len(message),
                    'word_count': len(message.split()),
                    'has_ip': any(
                        e[1] == 'IP' 
                        for e in entities.get('spacy_entities', [])
                    )
                }
            }
        except Exception as e:
            return {
                'error': str(e),
                'message': message
            }

    def _assess_security_risk(self, category: str, entities: Dict[str, Any]) -> str:
        """Determine security risk level (low/medium/high/critical)"""
        security_terms = [e[1] for e in entities.get('security_entities', [])]
        
        if (category == 'security' or 
            'ATTACK' in security_terms or 
            'EXPLOIT' in security_terms):
            return 'critical'
        elif ('AUTH' in security_terms or 
              'MALICIOUS' in security_terms or 
              category in ['authentication', 'error']):
            return 'high'
        elif 'SUSPICIOUS' in security_terms:
            return 'medium'
        return 'low'

    def analyze_all_messages(self) -> pd.DataFrame:
        """Analyze all messages in the DataFrame
        
        Returns:
            DataFrame with original logs + analysis columns
        """
        if self.df is None or 'message' not in self.df.columns:
            return pd.DataFrame()
            
        results = []
        for message in self.df['message']:
            results.append(self.analyze_message(message))
            
        return pd.concat([
            self.df.reset_index(drop=True),
            pd.DataFrame(results)
        ], axis=1)

    def cluster_logs(self) -> pd.DataFrame:
        """Cluster similar log messages
        
        Returns:
            DataFrame with cluster assignments and statistics
        """
        if self.df is None or 'message' not in self.df.columns:
            return pd.DataFrame()
            
        try:
            # Cluster messages
            self.df['cluster'] = self.clusterer.cluster(self.df['message'])
            
            # Generate cluster summaries
            cluster_stats = (
                self.df.groupby('cluster')
                .agg({
                    'message': ['count', lambda x: x.iloc[0]],
                    'level': lambda x: x.mode()[0] if not x.empty else None
                })
                .reset_index()
            )
            cluster_stats.columns = [
                'cluster', 'count', 'example_message', 'common_level'
            ]
            
            return cluster_stats.sort_values('count', ascending=False)
        except Exception as e:
            print(f"Clustering failed: {str(e)}")
            return pd.DataFrame()