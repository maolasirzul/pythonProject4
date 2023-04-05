import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split


def load_data():
    url = 'http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz'
    col_names = [...]  # List of column names
    df = pd.read_csv(url, header=None, names=col_names)

    # Preprocess the dataset
    for col in df.columns:
        if df[col].dtype == 'object':
            encoder = LabelEncoder()
            df[col] = encoder.fit_transform(df[col])

    # Scale the dataset
    scaler = MinMaxScaler()
    df = pd.DataFrame(scaler.fit_transform(df), columns=df.columns)

    # Split the dataset into features and labels
    X = df.drop('label', axis=1)
    y = df['label']

    # Split the dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    return X_train, X_test, y_train, y_test


from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report


def train_model(X_train, y_train):
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    return clf

def evaluate_model(clf, X_test, y_test):
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))

#================
def extract_features(packet):
    features = []

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        features.extend([
            ip_layer.src,  # Source IP address
            ip_layer.dst,  # Destination IP address
        ])

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        features.extend([
            tcp_layer.sport,  # Source port
            tcp_layer.dport,  # Destination port
            tcp_layer.flags,  # TCP flags
        ])

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        features.extend([
            udp_layer.sport,  # Source port
            udp_layer.dport,  # Destination port
        ])

    # Add other relevant features specific to your healthcare IoT system

    return features



from sklearn.preprocessing import LabelEncoder, MinMaxScaler

# Initialize encoders and scalers
ip_encoder = LabelEncoder()
port_scaler = MinMaxScaler()
flags_scaler = MinMaxScaler()

def preprocess_features(features):
    preprocessed_features = []

    # Convert IP addresses to numerical values
    preprocessed_features.extend(ip_encoder.fit_transform(features[:2]))

    # Scale numerical features
    preprocessed_features.extend(port_scaler.fit_transform(np.array(features[2:4]).reshape(-1, 1)).flatten())
    preprocessed_features.append(flags_scaler.fit_transform(np.array(features[4]).reshape(-1, 1)).flatten()[0])

    return preprocessed_features

#=======================
def intrusion_detection(packet, clf):
    # Extract features from the packet and preprocess it
    features = extract_features(packet)
    features = preprocess_features(features)

    # Predict the intrusion class
    pred_class = clf.predict(features.reshape(1, -1))

    # Return True if an intrusion is detected
    return pred_class != 0

def intrusion_prevention(packet, clf):
    if intrusion_detection(packet, clf):
        print("Intrusion detected and prevented from IP:", packet[IP].src)
    else:
        print("Packet forwarded:", packet.summary())


#===========
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

# Initialize encoders and scalers
ip_encoder = LabelEncoder()
port_scaler = MinMaxScaler()
flags_scaler = MinMaxScaler()

def preprocess_features(features):
    preprocessed_features = []

    # Convert IP addresses to numerical values
    preprocessed_features.extend(ip_encoder.fit_transform(features[:2]))

    # Scale numerical features
    preprocessed_features.extend(port_scaler.fit_transform(np.array(features[2:4]).reshape(-1, 1)).flatten())
    preprocessed_features.append(flags_scaler.fit_transform(np.array(features[4]).reshape(-1, 1)).flatten()[0])

    return preprocessed_features


#===================
import pandas as pd
import numpy as np
from scapy.all import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder, MinMaxScaler


#'''====================

'''X_train, X_test, y_train, y_test = load_data()
clf = train_model(X_train, y_train)
evaluate_model(clf, X_test, y_test)
sniff(prn=lambda packet: intrusion_prevention(packet, clf), filter="ip", store=0)'''
