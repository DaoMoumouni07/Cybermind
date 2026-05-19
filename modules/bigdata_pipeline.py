def send_to_kafka(topic, data):
    print(f"[STUB] Kafka non connecte : {data}")

def get_stats():
    return {"total": 0, "malwares": 0, "benign": 0, "rate": 0}

def get_recent_analyses(size=10):
    return []