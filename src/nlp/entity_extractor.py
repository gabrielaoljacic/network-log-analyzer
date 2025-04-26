import spacy
from typing import List, Dict

class LogEntityExtractor:
    def __init__(self):
        self.nlp = spacy.load("en_core_web_sm")
        self.security_terms = {
            'ATTACK': ['brute force', 'port scan', 'ddos', 'injection'],
            'AUTH': ['login', 'logout', 'authentication', 'credentials'],
            'NETWORK': ['connection', 'packet', 'port', 'protocol']
        }
        
    def extract_entities(self, message: str) -> Dict[str, List[str]]:
        """Extract both standard and custom entities"""
        doc = self.nlp(message)
        
        results = {
            'spacy_entities': [(ent.text, ent.label_) for ent in doc.ents],
            'security_entities': []
        }
        
        # Check for security terms
        for category, terms in self.security_terms.items():
            for term in terms:
                if term in message.lower():
                    results['security_entities'].append((term, category))
        
        return results