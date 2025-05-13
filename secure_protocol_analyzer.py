import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS
from scapy.all import get_if_list
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import sqlite3
import streamlit as st
from streamlit_autorefresh import st_autorefresh
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import time
import threading
import os
from datetime import datetime

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('traffic_logs.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    protocol TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    packet_size INTEGER,
                    entropy REAL,
                    is_malicious INTEGER
                 )''')
    conn.commit()
    conn.close()

# Calculate packet entropy
def calculate_entropy(data):
    if len(data) == 0:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * np.log2(p_x)
    return entropy

# Load real dataset
def load_dataset(dataset_path='network_traffic.csv'):
    try:
        df = pd.read_csv(dataset_path)
        # Assuming dataset has columns: packet_size, entropy, is_malicious
        required_columns = ['packet_size', 'entropy', 'is_malicious']
        if not all(col in df.columns for col in required_columns):
            raise ValueError("Dataset must contain 'packet_size', 'entropy', and 'is_malicious' columns")
        return df[required_columns]
    except FileNotFoundError:
        st.error(f"Dataset file {dataset_path} not found. Please provide a valid CSV file.")
        return None
    except Exception as e:
        st.error(f"Error loading dataset: {str(e)}")
        return None

# Packet capture and feature extraction
class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.features = []
        self.stop_sniffing = False
        init_db()

    def process_packet(self, packet):
        if self.stop_sniffing:
            return
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        protocol = None
        src_ip = packet[scapy.IP].src if scapy.IP in packet else None
        dst_ip = packet[scapy.IP].dst if scapy.IP in packet else None
        packet_size = len(packet)
        entropy = calculate_entropy(bytes(packet))

        if packet.haslayer(HTTPRequest):
            protocol = 'HTTP'
        elif packet.haslayer(DNS):
            protocol = 'DNS'

        if protocol:
            self.packets.append({
                'timestamp': timestamp,
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'packet_size': packet_size,
                'entropy': entropy
            })

            self.features.append([packet_size, entropy])
            
            # Store in database
            conn = sqlite3.connect('traffic_logs.db')
            c = conn.cursor()
            c.execute('''INSERT INTO traffic (timestamp, protocol, src_ip, dst_ip, packet_size, entropy, is_malicious)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (timestamp, protocol, src_ip, dst_ip, packet_size, entropy, 0))
            conn.commit()
            conn.close()

    def start_sniffing(self):
        self.stop_sniffing = False
        scapy.sniff(prn=self.process_packet, store=False, stop_filter=lambda x: self.stop_sniffing)

# Machine Learning Classifier
class TrafficClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.trained = False

    def train(self, dataset_path='network_traffic.csv'):
        data = load_dataset(dataset_path)
        if data is None:
            return 0.0

        X = data[['packet_size', 'entropy']].values
        y = data['is_malicious'].values

        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split and train
        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
        self.model.fit(X_train, y_train)
        self.trained = True
        
        # Calculate accuracy
        accuracy = self.model.score(X_test, y_test)
        return accuracy

    def predict(self, features):
        if not self.trained:
            return [0] * len(features)
        
        # Scale input features
        features_scaled = self.scaler.transform(features)
        predictions = self.model.predict(features_scaled)
        
        # Add probability threshold to reduce false positives
        probabilities = self.model.predict_proba(features_scaled)[:, 1]
        return [1 if prob > 0.7 else 0 for prob in probabilities]

    def suggest_mitigation(self, prediction, packet_info):
        if prediction == 1:
            return f"Block IP: {packet_info['src_ip']}, Update firewall rules"
        return "No action needed"

# Report Generation
def generate_pdf_report(packets, predictions):
    filename = "traffic_report.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, "Network Traffic Analysis Report")
    c.drawString(100, 730, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y = 700
    for i, (packet, pred) in enumerate(zip(packets, predictions)):
        if y < 100:
            c.showPage()
            y = 750
        c.drawString(100, y, f"Packet {i+1}: {packet['protocol']} from {packet['src_ip']} to {packet['dst_ip']}")
        c.drawString(100, y-20, f"Size: {packet['packet_size']}, Entropy: {packet['entropy']:.2f}, Malicious: {bool(pred)}")
        y -= 40
    c.save()
    return filename

def generate_json_report(packets, predictions):
    report = []
    for packet, pred in zip(packets, predictions):
        report.append({
            'timestamp': packet['timestamp'],
            'protocol': packet['protocol'],
            'src_ip': packet['src_ip'],
            'dst_ip': packet['dst_ip'],
            'packet_size': packet['packet_size'],
            'entropy': packet['entropy'],
            'is_malicious': bool(pred)
        })
    with open('traffic_report.json', 'w') as f:
        json.dump(report, f, indent=4)
    return 'traffic_report.json'

# Streamlit GUI
def run_gui(analyzer, classifier):
    st.title("Secure Protocol Analyzer")

    st_autorefresh(interval=5000, key='autorefresh')
    
    # Dataset upload
    st.subheader("Upload Training Dataset")
    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    if uploaded_file is not None:
        with open("network_traffic.csv", "wb") as f:
            f.write(uploaded_file.getbuffer())
        accuracy = classifier.train("network_traffic.csv")
        st.success(f"Classifier trained with accuracy: {accuracy:.2f}")

    if st.button("Start Packet Capture"):
        threading.Thread(target=analyzer.start_sniffing, daemon=True).start()
        st.write("Started packet capture...")

    if st.button("Stop Packet Capture"):
        analyzer.stop_sniffing = True
        st.write("Stopped packet capture.")

    if analyzer.packets:
        st.subheader("Captured Packets")
        df = pd.DataFrame(analyzer.packets)
        st.dataframe(df)

        # Classify traffic
        predictions = classifier.predict(analyzer.features)
        df['is_malicious'] = predictions
        st.subheader("Traffic Analysis")
        malicious_df = df[df['is_malicious'] == 1][['timestamp', 'protocol', 'src_ip', 'dst_ip', 'is_malicious']]
        if not malicious_df.empty:
            st.dataframe(malicious_df)
        else:
            st.write("No malicious packets detected.")

        # Mitigation Suggestions
        st.subheader("Mitigation Suggestions")
        for i, (packet, pred) in enumerate(zip(analyzer.packets, predictions)):
            if pred == 1:
                st.write(f"Packet {i+1}: {classifier.suggest_mitigation(pred, packet)}")

        # Visualize protocol usage
        st.subheader("Protocol Usage")
        protocol_counts = df['protocol'].value_counts()
        st.bar_chart(protocol_counts)

        # Report generation
        st.subheader("Generate Reports")
        if st.button("Generate PDF Report"):
            pdf_file = generate_pdf_report(analyzer.packets, predictions)
            with open(pdf_file, "rb") as f:
                st.download_button("Download PDF Report", f, file_name=pdf_file)
        
        if st.button("Generate JSON Report"):
            json_file = generate_json_report(analyzer.packets, predictions)
            with open(json_file, "r") as f:
                st.download_button("Download JSON Report", f, file_name=json_file)

# Main execution
if __name__ == "__main__":
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = PacketAnalyzer()

    if 'classifier' not in st.session_state:
        st.session_state.classifier = TrafficClassifier()

    # Run Streamlit GUI
    run_gui(st.session_state.analyzer, st.session_state.classifier)