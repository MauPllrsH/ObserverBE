from flask import Flask, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

app = Flask(__name__)
CORS(app)

# MongoDB connection setup
load_dotenv()
mongo_user = quote_plus(os.getenv('MONGO_USER', ''))
mongo_password = quote_plus(os.getenv('MONGO_PASSWORD', ''))
mongo_port = os.getenv('MONGO_PORT', '27017')
mongo_database = os.getenv('MONGO_DATABASE', '')

# Debug prints to verify environment variables
print(f"Mongo Port: {mongo_port}")
print(f"Mongo Database: {mongo_database}")
print(f"Mongo User exists: {'Yes' if mongo_user else 'No'}")
print(f"Mongo Password exists: {'Yes' if mongo_password else 'No'}")

mongo_url = f"mongodb://{mongo_user}:{mongo_password}@mongodb:{mongo_port}/{mongo_database}?authSource=admin"
print(f"Attempting to connect with URL: {mongo_url}")

try:
    client = MongoClient(mongo_url)
    db = client[mongo_database]
    print("Successfully connected to MongoDB")
except Exception as e:
    print(f"Error connecting to MongoDB: {str(e)}")
    raise e

@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        # Get the 100 most recent logs
        logs = list(db.logs.find(
            {},
            {'_id': False}  # Exclude MongoDB ID
        ).sort('timestamp', -1).limit(100))
        
        return jsonify(logs)
    except Exception as e:
        print(f"Error fetching logs: {str(e)}")
        return jsonify([])

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        # Get basic statistics
        total_logs = db.logs.count_documents({})
        attacks_detected = db.logs.count_documents({"analysis_result.injection_detected": True})
        
        # Get counts for the last 24 hours
        yesterday = datetime.now() - timedelta(days=1)
        recent_attacks = db.logs.count_documents({
            "analysis_result.injection_detected": True,
            "timestamp": {"$gte": yesterday.isoformat()}
        })
        
        return jsonify({
            "total_logs": total_logs,
            "total_attacks": attacks_detected,
            "recent_attacks": recent_attacks
        })
    except Exception as e:
        print(f"Error fetching stats: {str(e)}")
        return jsonify({
            "total_logs": 0,
            "total_attacks": 0,
            "recent_attacks": 0
        })

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)