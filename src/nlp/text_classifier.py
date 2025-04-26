from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
import pandas as pd

class LogClassifier:
    def __init__(self):
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                stop_words='english',
                ngram_range=(1, 2))),
            ('clf', LogisticRegression(
                solver='lbfgs',
                max_iter=1000)  # Remove multi_class parameter
            )
        ])
        self.classes = [
            'authentication', 
            'network', 
            'system', 
            'error',
            'security'
        ]
    
    def train(self, logs: pd.DataFrame, text_col='message', label_col='category'):
        """Train classifier on labeled log data"""
        self.pipeline.fit(logs[text_col], logs[label_col])
    
    def predict(self, message: str) -> tuple[str, float]:
        """Predict log category and confidence"""
        probas = self.pipeline.predict_proba([message])[0]
        return self.classes[probas.argmax()], max(probas)