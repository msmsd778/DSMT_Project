from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["messenger_db"]
nodes_collection = db["nodes"]
users_collection = db["users"]

# Print all nodes in the collection
for node in users_collection.find():
    print(node)

result = nodes_collection.delete_many({"node_name": "nonode@nohost" })  # Corrected method name
print(f"{result.deleted_count} document(s) removed.")