from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import pandas as pd
import numpy as np

class LogClusterer:
    def __init__(self, n_clusters=5, algorithm='kmeans'):
        self.vectorizer = TfidfVectorizer(
            max_features=500,  # Reduced from 1000
            stop_words='english',
            ngram_range=(1, 2)
        )
        self.model = KMeans(n_clusters=n_clusters)
        self.n_components = 20  # Reduced from 50

    def cluster(self, log_messages: pd.Series) -> np.ndarray:
        """Cluster similar log messages"""
        if len(log_messages) < 2:
            return np.zeros(len(log_messages), dtype=int)
            
        try:
            tfidf = self.vectorizer.fit_transform(log_messages)
            n_components = min(self.n_components, tfidf.shape[1]-1)
            if n_components <= 0:
                return np.zeros(len(log_messages), dtype=int)
                
            # Dimensionality reduction adapted to actual feature count
            from sklearn.decomposition import TruncatedSVD
            reducer = TruncatedSVD(n_components=n_components)
            reduced = reducer.fit_transform(tfidf)
            
            return self.model.fit_predict(reduced)
        except Exception as e:
            print(f"Clustering failed: {str(e)}")
            return np.zeros(len(log_messages), dtype=int)