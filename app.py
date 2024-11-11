from flask import Flask, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": ["http://157.245.249.219:3000"],
        "methods": ["GET", "POST"],
        "allow_headers": ["Content-Type"]
    }
})

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
    
    # List all collections
    collections = db.list_collection_names()
    print(f"Available collections: {collections}")
    
    # Try to access logs collection
    logs_count = db.logs.count_documents({})
    print(f"Number of documents in logs collection: {logs_count}")
    
except Exception as e:
    print(f"Error connecting to MongoDB: {str(e)}")
    raise e

@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        # List all collections for debugging
        collections = db.list_collection_names()
        print(f"Available collections: {collections}")
        
        # Try to count documents
        count = db.logs.count_documents({})
        print(f"Number of documents in logs collection: {count}")
        
        # Get the 100 most recent logs with debug info
        logs = list(db.logs.find(
            {},
            {'_id': False}
        ).sort('timestamp', -1).limit(100))
        
        print(f"Retrieved {len(logs)} logs")
        if logs:
            print("Sample log entry:", logs[0])
            
        return jsonify(logs)
    except Exception as e:
        print(f"Error fetching logs: {str(e)}")
        import traceback
        traceback.print_exc()
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


@app.route('/api/attack-timeline', methods=['GET'])
def get_attack_timeline():
    try:
        # Get attacks grouped by hour for the last 24 hours
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
        # Aggregate pipeline to get unique IPs with counts of normal and anomalous requests
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
    app.run(debug=True, host='0.0.0.0', port=5000)