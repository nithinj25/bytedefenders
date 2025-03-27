from flask import Flask, render_template, request, jsonify, url_for
import requests
import json
import os

app = Flask(__name__, static_folder='static')
API_URL = "http://localhost:8000/predict"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        # Get form data and convert to correct types
        flow_data = {
            key: float(value) if '.' in value else int(value)
            for key, value in request.form.items()
        }
        
        # Send to API and get results
        response = requests.post(API_URL, json=flow_data)
        result = response.json()
        return render_template('result.html', result=result)
    
    except Exception as e:
        return f"Error: {str(e)}", 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)