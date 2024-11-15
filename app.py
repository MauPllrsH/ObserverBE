from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from urllib.parse import quote_plus
import time

app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": ["http://157.245.249.219:3000"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Accept", "Cache-Control"],
        "expose_headers": ["Content-Type", "Content-Length"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# MongoDB connection setup
load_dotenv()
mongo_user = quote_plus(os.getenv('MONGO_USER', ''))
mongo_password = quote_plus(os.getenv('MONGO_PASSWORD', ''))
mongo_port = os.getenv('MONGO_PORT', '27017')
mongo_database = os.getenv('MONGO_DATABASE', '')

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
    collections = db.list_collection_names()
    print(f"Available collections: {collections}")
    logs_count = db.logs.count_documents({})
    print(f"Number of documents in logs collection: {logs_count}")
except Exception as e:
    print(f"Error connecting to MongoDB: {str(e)}")
    raise e

def with_retry(func, max_retries=3, delay=0.5):
    """Wrapper to retry MongoDB operations with exponential backoff"""
    def wrapper(*args, **kwargs):
        retries = 0
        while retries < max_retries:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                retries += 1
                if retries == max_retries:
                    raise e
                time.sleep(delay * (2 ** (retries - 1)))
    return wrapper

@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        since = request.args.get('since')
        
        @with_retry
        def fetch_logs():
            # Build query with optional timestamp filter
            query = {}
            if since:
                try:
                    # Parse the ISO timestamp and create MongoDB query
                    query['timestamp'] = {'$gt': since}
                except ValueError as e:
                    print(f"Invalid timestamp format: {e}")
                    # If timestamp parsing fails, ignore the filter
                    pass

            logs = list(db.logs.find(
                query,
                {'_id': False}
            ).sort('timestamp', -1).limit(100))
            
            # Process logs to ensure they're JSON serializable
            for log in logs:
                if isinstance(log.get('timestamp'), datetime):
                    log['timestamp'] = log['timestamp'].isoformat()
                
                # Handle any ObjectId or other non-serializable types
                for key, value in log.items():
                    if not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                        log[key] = str(value)
            
            return logs

        logs = fetch_logs()
        
        if not logs:
            return jsonify([])
            
        response = jsonify(logs)
        response.headers.update({
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Content-Type': 'application/json'
        })
        
        # Add the latest timestamp in response headers for clients to use
        if logs:
            latest_timestamp = max(log['timestamp'] for log in logs)
            response.headers['X-Latest-Timestamp'] = latest_timestamp

        return response

    except Exception as e:
        print(f"Error in get_logs: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": "Failed to fetch logs", 
            "details": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/attack-timeline', methods=['GET'])
def get_attack_timeline():
    try:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)

        pipeline = [
            {
                "$match": {
                    "timestamp": {
                        "$gte": start_time.isoformat(),
                        "$lte": end_time.isoformat()
                    }
                }
            },
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d %H:00",
                            "date": {
                                "$dateFromString": {
                                    "dateString": "$timestamp"
                                }
                            }
                        }
                    },
                    "total_requests": {"$sum": 1},
                    "attacks": {
                        "$sum": {
                            "$cond": [{"$eq": ["$analysis_result.injection_detected", True]}, 1, 0]
                        }
                    }
                }
            },
            {
                "$sort": {"_id": 1}
            },
            {
                "$project": {
                    "_id": 0,
                    "timestamp": "$_id",
                    "total_requests": 1,
                    "attacks": 1
                }
            }
        ]

        results = list(db.logs.aggregate(pipeline))
        return jsonify(results)
    except Exception as e:
        print(f"Error fetching attack timeline: {str(e)}")
        return jsonify([])

@app.route('/api/anomalous-ips', methods=['GET'])
def get_anomalous_ips():
    try:
        pipeline = [
            {
                "$group": {
                    "_id": "$ip",
                    "total_requests": {"$sum": 1},
                    "anomalous_requests": {
                        "$sum": {
                            "$cond": [{"$eq": ["$analysis_result.injection_detected", True]}, 1, 0]
                        }
                    },
                    "last_detected": {"$max": "$timestamp"},
                    "matched_rules": {
                        "$addToSet": {
                            "$cond": [
                                {"$eq": ["$analysis_result.injection_detected", True]},
                                "$analysis_result.matched_rules",
                                []
                            ]
                        }
                    }
                }
            },
            {
                "$match": {
                    "anomalous_requests": {"$gt": 0}
                }
            },
            {
                "$project": {
                    "ip": "$_id",
                    "total_requests": 1,
                    "anomalous_requests": 1,
                    "last_detected": 1,
                    "threat_level": {
                        "$multiply": [
                            {"$divide": ["$anomalous_requests", "$total_requests"]},
                            100
                        ]
                    },
                    "matched_rules": {
                        "$reduce": {
                            "input": "$matched_rules",
                            "initialValue": [],
                            "in": {"$setUnion": ["$$value", "$$this"]}
                        }
                    }
                }
            },
            {
                "$sort": {"threat_level": -1}
            }
        ]

        results = list(db.logs.aggregate(pipeline))
        return jsonify(results)
    except Exception as e:
        print(f"Error fetching anomalous IPs: {str(e)}")
        return jsonify([])

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    app.config['TIMEOUT'] = 300
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)