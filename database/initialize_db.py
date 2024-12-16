from pymongo import MongoClient

def initialize_database():
    client = MongoClient("mongodb://localhost:27017/")
    db = client["messenger_db"]

    # Create collections
    users_collection = db["users"]
    messages_collection = db["messages"]
    nodes_collection = db["nodes"]

    # Add indexes
    users_collection.create_index("username", unique=True)
    nodes_collection.create_index("node_name", unique=True)

    print("MongoDB initialized with 'users', 'messages', and 'nodes' collections.")
    client.close()

if __name__ == "__main__":
    initialize_database()
