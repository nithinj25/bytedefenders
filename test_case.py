import requests
import json

# API endpoint
API_URL = "http://localhost:8000/predict"

# Test cases with correct field names
test_cases = [
    {
        "name": "Normal Traffic",
        "data": {
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
    },
    {
        "name": "SYN Flood Attack",
        "data": {
            "Flow Duration": 50.0,
            "Total Fwd Packets": 2000,
            "Total Backward Packets": 100,
            "Flow Bytes/s": 15000.0,
            "Flow Packets/s": 1500.0,
            "Flow IAT Mean": 0.01,
            "Flow IAT Std": 0.005,
            "Fwd Packets/s": 1400.0,
            "Bwd Packets/s": 100.0,
            "Packet Length Mean": 60.0,
            "Packet Length Std": 10.0,
            "FIN Flag Count": 0,
            "SYN Flag Count": 150,
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,
            "URG Flag Count": 0
        }
    }
]

def run_tests():
    print("Running Network Threat Detection Tests\n")
    print("=" * 50)
    
    for test_case in test_cases:
        print(f"\nTesting: {test_case['name']}")
        print("-" * 30)
        
        try:
            response = requests.post(API_URL, json=test_case['data'])
            
            if response.status_code != 200:
                print(f"Error: API returned status code {response.status_code}")
                print(f"Response: {response.text}")
                continue
                
            result = response.json()
            
            print(f"Status Code: {response.status_code}")
            print(f"Response Data:")
            print(f"- Threat Score: {result.get('threat_score', 'N/A'):.3f}")
            print(f"- Severity: {result.get('severity', 'N/A')}")
            
            print("\nSuggested Actions:")
            actions = result.get('suggested_actions', {})
            print(f"- Block Traffic: {actions.get('block_traffic', 'N/A')}")
            print(f"- Isolation: {actions.get('isolation_recommended', 'N/A')}")
            
            print("\nAnomalies:")
            for anomaly in result.get('anomalies', []):
                print(f"- {anomaly}")
            
        except Exception as e:
            print(f"Error testing {test_case['name']}: {str(e)}")
        
        print("=" * 50)

if __name__ == "__main__":
    run_tests()