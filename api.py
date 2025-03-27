from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any
import numpy as np
import pandas as pd
import joblib
import os

# Initialize FastAPI app
app = FastAPI(
    title="Network Threat Detection API",
    description="Detect network threats using ML model"
)

# Define the input data model
class NetworkFlow(BaseModel):
    flow_duration: float = Field(alias="Flow Duration")
    total_fwd_packets: int = Field(alias="Total Fwd Packets")
    total_backward_packets: int = Field(alias="Total Backward Packets")
    flow_bytes_per_sec: float = Field(alias="Flow Bytes/s")
    flow_packets_per_sec: float = Field(alias="Flow Packets/s")
    flow_iat_mean: float = Field(alias="Flow IAT Mean")
    flow_iat_std: float = Field(alias="Flow IAT Std")
    fwd_packets_per_sec: float = Field(alias="Fwd Packets/s")
    bwd_packets_per_sec: float = Field(alias="Bwd Packets/s")
    packet_length_mean: float = Field(alias="Packet Length Mean")
    packet_length_std: float = Field(alias="Packet Length Std")
    fin_flag_count: int = Field(alias="FIN Flag Count")
    syn_flag_count: int = Field(alias="SYN Flag Count")
    rst_flag_count: int = Field(alias="RST Flag Count")
    psh_flag_count: int = Field(alias="PSH Flag Count")
    ack_flag_count: int = Field(alias="ACK Flag Count")
    urg_flag_count: int = Field(alias="URG Flag Count")

    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "Flow Duration": 100.0,
                "Total Fwd Packets": 50,
                "Total Backward Packets": 40,
                "Flow Bytes/s": 5000.0,
                "Flow Packets/s": 500.0,
                "Flow IAT Mean": 0.05,
                "Flow IAT Std": 0.02,
                "Fwd Packets/s": 250.0,
                "Bwd Packets/s": 250.0,
                "Packet Length Mean": 80.0,
                "Packet Length Std": 20.0,
                "FIN Flag Count": 1,
                "SYN Flag Count": 1,
                "RST Flag Count": 0,
                "PSH Flag Count": 2,
                "ACK Flag Count": 3,
                "URG Flag Count": 0
            }
        }

# Load the trained model with error handling
MODEL_PATH = 'trained_model.joblib'
SCALER_PATH = 'scaler.joblib'

try:
    if not os.path.exists(MODEL_PATH):
        print(f"Error: Model file not found at {MODEL_PATH}")
        model = None
    else:
        model = joblib.load(MODEL_PATH)
        print("Model loaded successfully")

    if not os.path.exists(SCALER_PATH):
        print(f"Error: Scaler file not found at {SCALER_PATH}")
        scaler = None
    else:
        scaler = joblib.load(SCALER_PATH)
        print("Scaler loaded successfully")

except Exception as e:
    print(f"Error loading model/scaler: {e}")
    model = None
    scaler = None

@app.get("/")
async def root():
    return {
        "message": "Network Threat Detection API",
        "status": "active",
        "model_loaded": model is not None and scaler is not None
    }

@app.post("/predict")
async def predict_threat(flow: NetworkFlow) -> Dict[str, Any]:
    if model is None or scaler is None:
        raise HTTPException(
            status_code=500,
            detail="Model not loaded. Please ensure model files exist."
        )
    
    try:
        # Convert input to DataFrame with correct column names
        flow_data = pd.DataFrame([flow.dict(by_alias=True)])
        
        # Verify features match
        print("Input features:", flow_data.columns.tolist())
        
        # Scale the features
        X_scaled = scaler.transform(flow_data)
        
        # Make prediction
        prediction = model.predict(X_scaled)[0]
        prediction_proba = model.predict_proba(X_scaled)[0]
        
        # Determine threat level
        threat_score = float(max(prediction_proba))
        severity = "Critical" if threat_score > 0.8 else \
                  "High" if threat_score > 0.6 else \
                  "Medium" if threat_score > 0.4 else "Low"
        
        # Generate anomaly list
        anomalies = []
        if flow.flow_packets_per_sec > 1000:
            anomalies.append("High packet rate detected")
        if flow.syn_flag_count > 100:
            anomalies.append("Possible SYN flood attack")
        if flow.rst_flag_count > 50:
            anomalies.append("High number of RST flags")
        
        return {
            "threat_detected": bool(prediction),
            "threat_score": threat_score,
            "severity": severity,
            "suggested_actions": {
                "block_traffic": "Yes" if threat_score > 0.7 else "No",
                "isolation_recommended": "Yes" if threat_score > 0.8 else "No"
            },
            "anomalies": anomalies,
            "full_report": {
                "flow_metrics": flow.dict(by_alias=True),
                "prediction_confidence": float(max(prediction_proba))
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error processing request: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)