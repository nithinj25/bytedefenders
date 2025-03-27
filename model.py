import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns

# Load the CIC-IDS 2017 dataset
def load_dataset(file_path):
    """
    Load the dataset and perform initial preprocessing
    
    Args:
        file_path (str): Path to the dataset CSV file
    
    Returns:
        pd.DataFrame: Preprocessed dataset
    """
    try:
        # Load the dataset
        print(f"\nLoading dataset from: {file_path}")
        df = pd.read_csv(file_path)
        
        # Clean column names
        df.columns = df.columns.str.strip()
        
        print(f"Total records in dataset: {len(df):,}")
        print("\nDataset columns:")
        for col in df.columns:
            print(f"- {col}")
        
        # Basic preprocessing steps
        # Remove any rows with missing values
        initial_rows = len(df)
        df.dropna(inplace=True)
        print(f"\nRecords after removing missing values: {len(df):,}")
        print(f"Removed {initial_rows - len(df):,} records with missing values")
        
        # Remove duplicate rows
        initial_rows = len(df)
        df.drop_duplicates(inplace=True)
        print(f"Records after removing duplicates: {len(df):,}")
        print(f"Removed {initial_rows - len(df):,} duplicate records")
        
        # Print label distribution
        print("\nLabel Distribution:")
        print(df['Label'].value_counts())
        
        return df
    except Exception as e:
        print(f"Error loading dataset: {e}")
        print("\nDataset structure:")
        print(df.head())
        print("\nColumn names:")
        print(df.columns.tolist())
        return None

# Preprocess the data
def preprocess_data(df):
    """
    Preprocess the dataset for machine learning
    
    Args:
        df (pd.DataFrame): Input dataframe
    
    Returns:
        tuple: Preprocessed features (X) and labels (y)
    """
    # Clean column names by removing leading/trailing whitespace
    df.columns = df.columns.str.strip()
    
    # For this dataset, we'll use network flow features to detect anomalies
    # We'll consider high packet rates and unusual patterns as potential threats
    feature_columns = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
        'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Mean', 'Packet Length Std',
        'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
        'ACK Flag Count', 'URG Flag Count'
    ]
    
    # Create labels based on network flow characteristics
    # Consider high packet rates and unusual patterns as threats
    df['is_threat'] = (
        (df['Flow Packets/s'] > 1000) |  # High packet rate
        (df['Flow Bytes/s'] > 10000) |   # High byte rate
        (df['Total Fwd Packets'] > 1000) |  # Large number of forward packets
        (df['SYN Flag Count'] > 100) |    # High number of SYN flags
        (df['RST Flag Count'] > 50)       # High number of RST flags
    ).astype(int)
    
    # Select features for training
    X = df[feature_columns]
    y = df['is_threat']
    
    # Replace infinite values with maximum finite value
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.max())
    
    return X, y

# Train Random Forest Classifier
def train_random_forest(X_train, y_train, n_estimators=100, random_state=42):
    """
    Train a Random Forest Classifier
    
    Args:
        X_train (pd.DataFrame): Training features
        y_train (pd.Series): Training labels
        n_estimators (int): Number of trees in the forest
        random_state (int): Random seed for reproducibility
    
    Returns:
        RandomForestClassifier: Trained model
    """
    # Scale the features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Initialize and train the Random Forest Classifier
    rf_classifier = RandomForestClassifier(
        n_estimators=n_estimators, 
        random_state=random_state, 
        n_jobs=-1,  # Use all available cores
        class_weight='balanced'  # Handle imbalanced classes
    )
    rf_classifier.fit(X_train_scaled, y_train)
    
    return rf_classifier, scaler

def format_threat_report(prediction, prediction_proba, features, timestamp=None):
    """
    Format detailed threat detection results
    
    Args:
        prediction: Model prediction
        prediction_proba: Prediction probability scores
        features: Feature values for the prediction
        timestamp: Optional timestamp of the activity
    
    Returns:
        dict: Formatted threat report
    """
    # Get the maximum probability score
    threat_score = float(max(prediction_proba))
    
    # Define severity levels based on threat score
    if threat_score < 0.3:
        severity = "Low"
    elif threat_score < 0.6:
        severity = "Medium"
    elif threat_score < 0.8:
        severity = "High"
    else:
        severity = "Critical"
    
    # Create the threat report
    threat_report = {
        "1. Threat Detection Results": {
            "Boolean Flag": bool(prediction == 1),
            "Threat Score": round(threat_score, 3)
        },
        "2. Threat Classification": {
            "Attack Type": "Suspicious Network Activity" if prediction == 1 else "Normal Traffic",
            "Malware Family": "Unknown",  # Would need additional data for this
            "Severity Level": severity
        },
        "3. Anomaly Detection Insights": {
            "List of Anomalies": [],
            "Flow Duration": features.get("Flow Duration", "Not Available"),
            "Flow Bytes/s": features.get("Flow Bytes/s", "Not Available"),
            "Flow Packets/s": features.get("Flow Packets/s", "Not Available"),
            "SYN Flags": features.get("SYN Flag Count", "Not Available"),
            "RST Flags": features.get("RST Flag Count", "Not Available")
        },
        "4. Suggested Actions": {
            "Block Traffic": "Yes" if threat_score > 0.7 else "No",
            "Isolation Recommendation": "Yes" if threat_score > 0.8 else "No"
        }
    }
    
    # Add anomalies based on feature values
    anomalies = []
    if features.get("Flow Packets/s", 0) > 1000:
        anomalies.append(f"High packet rate: {features.get('Flow Packets/s', 0):.2f} packets/s")
    if features.get("Flow Bytes/s", 0) > 10000:
        anomalies.append(f"High byte rate: {features.get('Flow Bytes/s', 0):.2f} bytes/s")
    if features.get("Total Fwd Packets", 0) > 1000:
        anomalies.append(f"Large number of forward packets: {features.get('Total Fwd Packets', 0)}")
    if features.get("SYN Flag Count", 0) > 100:
        anomalies.append(f"High number of SYN flags: {features.get('SYN Flag Count', 0)}")
    if features.get("RST Flag Count", 0) > 50:
        anomalies.append(f"High number of RST flags: {features.get('RST Flag Count', 0)}")
    
    threat_report["3. Anomaly Detection Insights"]["List of Anomalies"] = anomalies
    
    return threat_report

def evaluate_model(model, scaler, X_test, y_test):
    """
    Evaluate the trained model
    
    Args:
        model (RandomForestClassifier): Trained model
        scaler (StandardScaler): Feature scaler
        X_test (pd.DataFrame): Test features
        y_test (pd.Series): Test labels
    
    Returns:
        dict: Model evaluation metrics
    """
    # Scale the test features
    X_test_scaled = scaler.transform(X_test)
    
    # Make predictions
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    conf_matrix = confusion_matrix(y_test, y_pred)
    class_report = classification_report(y_test, y_pred)
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X_test.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    # Find threats
    threats = []
    for i in range(len(y_pred)):
        if y_pred[i] == 1:
            threat_report = format_threat_report(
                y_pred[i],
                y_pred_proba[i],
                dict(zip(X_test.columns, X_test.iloc[i]))
            )
            threats.append(threat_report)
    
    # Visualize confusion matrix
    plt.figure(figsize=(10, 8))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.tight_layout()
    plt.savefig('confusion_matrix.png')
    plt.close()
    
    # Visualize feature importance
    plt.figure(figsize=(10, 8))
    feature_importance.head(20).plot(x='feature', y='importance', kind='bar')
    plt.title('Top 20 Most Important Features')
    plt.xlabel('Features')
    plt.ylabel('Importance')
    plt.tight_layout()
    plt.savefig('feature_importance.png')
    plt.close()
    
    return {
        'accuracy': accuracy,
        'confusion_matrix': conf_matrix,
        'classification_report': class_report,
        'feature_importance': feature_importance,
        'threats': threats
    }

# Main execution function
def main(dataset_path):
    """
    Main function to run the RaaS detection pipeline
    
    Args:
        dataset_path (str): Path to the CIC-IDS 2017 dataset
    """
    # Load the dataset
    df = load_dataset(dataset_path)
    if df is None:
        print("Failed to load dataset")
        return
    
    # Preprocess the data
    print("\nPreprocessing data...")
    X, y = preprocess_data(df)
    print(f"Number of features after preprocessing: {X.shape[1]}")
    
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTraining set size: {len(X_train):,} records")
    print(f"Testing set size: {len(X_test):,} records")
    
    # Train the Random Forest Classifier
    print("\nTraining Random Forest model...")
    model, scaler = train_random_forest(X_train, y_train)
    
    # Evaluate the model
    print("\nEvaluating model...")
    results = evaluate_model(model, scaler, X_test, y_test)
    
    # Print results
    print("\n=== Model Performance ===")
    print("Model Accuracy:", results['accuracy'])
    print("\nClassification Report:")
    print(results['classification_report'])
    
    print("\n=== Top 10 Most Important Features ===")
    print(results['feature_importance'].head(10))
    
    print(f"\n=== Detected Threats (showing first 10 out of {len(results['threats']):,} total threats) ===")
    for i, threat in enumerate(results['threats'][:10], 1):  # Show first 10 threats
        print(f"\nThreat {i}:")
        for section, details in threat.items():
            print(f"\n{section}")
            if isinstance(details, dict):
                for key, value in details.items():
                    print(f"  {key}: {value}")
            else:
                print(f"  {details}")
        print("-" * 80)  # Add separator between threats

# Example usage
if __name__ == "__main__":
    try:
        # Use the Friday morning dataset
        dataset_path = "Friday-WorkingHours-Morning.pcap_ISCX.csv"
        print(f"Loading dataset from: {dataset_path}")
        main(dataset_path)
    except Exception as e:
        print(f"An error occurred while running the model: {e}")
        print("Please make sure:")
        print("1. The dataset file exists in the correct location")
        print("2. The dataset has the expected format with a 'Label' column")
        print("3. You have all required Python packages installed (pandas, numpy, scikit-learn, matplotlib, seaborn)")

# Additional utility functions for anomaly detection
def detect_anomalies(model, scaler, X_new_data):
    """
    Detect anomalies in new data using the trained model
    
    Args:
        model (RandomForestClassifier): Trained model
        scaler (StandardScaler): Feature scaler
        X_new_data (pd.DataFrame): New data to check for anomalies
    
    Returns:
        pd.DataFrame: Dataframe with anomaly predictions
    """
    # Scale the new data
    X_new_scaled = scaler.transform(X_new_data)
    
    # Predict probabilities
    anomaly_scores = model.predict_proba(X_new_scaled)
    
    # Add anomaly scores to the original dataframe
    X_new_data['anomaly_score'] = anomaly_scores.max(axis=1)
    
    # Flag potential anomalies (you can adjust the threshold)
    X_new_data['is_anomaly'] = X_new_data['anomaly_score'] > 0.7
    
    return X_new_data