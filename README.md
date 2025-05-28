# AI Network Log Analyzer
An automated log analysis tool that detects security threats and patterns in server logs using machine learning and NLP.

## Features 
- Real-time log analysis
- Automatic threat detection
- Interactive visualizations
- No external data needed (self-generates sample logs)

## Tech Stack
- **Language**: Python 3.10+
- **ML/NLP**: scikit-learn, spaCy
- **Dashboard**: Streamlit
- **Data Processing**: Pandas
- **Visualization**: Plotly

## Setup
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/gabrielaoljacic/network-log-analyzer.git
   cd network-log-analyzer

2. **Set up Environment**:
    ```bash
   python -m venv venv
   # Linux/Mac:
   source venv/bin/activate
   # Windows:
   venv\Scripts\activate

3. **Install Dependencies**:
    ```bash
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm

4. **Run the Dashboard**:
    ```bash
   streamlit run dashboard.py
