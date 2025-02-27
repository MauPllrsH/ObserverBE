from collections import defaultdict

from geoip2.database import Reader
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from urllib.parse import quote_plus
import time
import requests

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

mongo_url = f"mongodb://{mongo_user}:{mongo_password}@mongodb:{mongo_port}/{mongo_database}?authSource=admin"
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), 'data/geoip/GeoLite2-City.mmdb')

reader = Reader(GEOIP_DB_PATH)

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
@app.route('/api/waf/prevention', methods=['GET'])
def get_prevention_mode():
    try:
        # Get prevention mode status from MongoDB config collection
        config = db.config.find_one({'key': 'prevention_mode'})
        if config:
            return jsonify({'enabled': config['enabled']})
        return jsonify({'enabled': False})
    except Exception as e:
        print(f"Error getting prevention mode: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/waf/prevention', methods=['POST'])
def set_prevention_mode():
    try:
        data = request.get_json()
        if data is None or 'enabled' not in data:
            return jsonify({'error': 'Missing enabled parameter'}), 400

        enabled = bool(data['enabled'])

        # Update MongoDB config
        db.config.update_one(
            {'key': 'prevention_mode'},
            {'$set': {'enabled': enabled}},
            upsert=True
        )

        # Forward the request to the WAF server
        try:
            response = requests.post(
                f"{WAF_API_URL}/api/waf/prevention",
                json={'enabled': enabled},
                timeout=5
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error forwarding prevention mode to WAF: {str(e)}")
            # Even if WAF server is unreachable, we keep the MongoDB state updated

        return jsonify({
            'enabled': enabled,
            'status': 'success'
        })

    except Exception as e:
        print(f"Error setting prevention mode: {str(e)}")
        return jsonify({'error': str(e)}), 500


# Add prevention mode status to the existing logs endpoint
@app.route('/api/status', methods=['GET'])
def get_status():
    try:
        # Get basic stats
        total_requests = db.logs.count_documents({})
        attacks_detected = db.logs.count_documents({"analysis_result.injection_detected": True})

        # Get prevention mode status
        config = db.config.find_one({'key': 'prevention_mode'})
        prevention_enabled = config['enabled'] if config else False

        # Get latest logs for timeline
        latest_logs = list(db.logs.find(
            {},
            {'timestamp': 1, 'analysis_result.injection_detected': 1}
        ).sort('timestamp', -1).limit(10))

        return jsonify({
            'total_requests': total_requests,
            'attacks_detected': attacks_detected,
            'prevention_mode': prevention_enabled,
            'latest_activity': latest_logs
        })
    except Exception as e:
        print(f"Error getting status: {str(e)}")
        return jsonify({'error': str(e)}), 500

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
                                    "dateString": "$timestamp",
                                    "timezone": "America/Chicago"
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
            },
            {
                "$limit": 15
            }
        ]

        results = list(db.logs.aggregate(pipeline))
        return jsonify(results)
    except Exception as e:
        print(f"Error fetching anomalous IPs: {str(e)}")
        return jsonify([])


@app.route('/api/attack-origins', methods=['GET'])
def get_attack_origins():
    try:
        # Get time range parameter (default 24 hours)
        hours = request.args.get('hours', default=24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)

        # Aggregate pipeline to get attacks by IP
        pipeline = [
            {
                "$match": {
                    "analysis_result.injection_detected": True,
                    "timestamp": {"$gte": since.isoformat()}
                }
            },
            {
                "$group": {
                    "_id": "$ip",
                    "attack_count": {"$sum": 1},
                    "last_attack": {"$max": "$timestamp"},
                    "matched_rules": {"$addToSet": "$analysis_result.matched_rules"}
                }
            }
        ]

        results = list(db.logs.aggregate(pipeline))

        # Process geolocation data
        countries = defaultdict(lambda: {
            "attack_count": 0,
            "unique_ips": set(),
            "last_attack": None,
            "common_rules": defaultdict(int)
        })

        for result in results:
            try:
                ip = result['_id']
                geo = reader.city(ip)
                country = geo.country.name or 'Unknown'

                # Update country statistics
                country_stats = countries[country]
                country_stats["attack_count"] += result["attack_count"]
                country_stats["unique_ips"].add(ip)

                # Update last attack time
                attack_time = datetime.fromisoformat(result["last_attack"].replace('Z', '+00:00'))
                if not country_stats["last_attack"] or attack_time > country_stats["last_attack"]:
                    country_stats["last_attack"] = attack_time

                # Count rule occurrences
                for rule_list in result["matched_rules"]:
                    for rule in rule_list:
                        country_stats["common_rules"][rule] += 1

            except Exception as e:
                print(f"Error processing IP {ip}: {str(e)}")
                continue

        # Format the response
        response_data = []
        for country, stats in countries.items():
            # Get top 5 most common rules
            top_rules = sorted(
                stats["common_rules"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]

            response_data.append({
                "country": country,
                "attack_count": stats["attack_count"],
                "unique_ips": len(stats["unique_ips"]),
                "last_attack": stats["last_attack"].isoformat() if stats["last_attack"] else None,
                "latitude": reader.city(list(stats["unique_ips"])[0]).location.latitude,
                "longitude": reader.city(list(stats["unique_ips"])[0]).location.longitude,
                "top_attack_types": [{"rule": rule, "count": count} for rule, count in top_rules]
            })

        # Sort by attack count
        response_data.sort(key=lambda x: x["attack_count"], reverse=True)

        return jsonify(response_data)
    except Exception as e:
        print(f"Error processing attack origins: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    app.config['TIMEOUT'] = 300
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)