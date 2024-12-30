from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["messenger_db"]
users_collection = db["users"]
messages_collection = db["messages"]
nodes_collection = db["nodes"]
sessions_collection = db["sessions"]
groups_collection = db["groups"]
group_messages_collection = db["group_messages"]



# Print all nodes in the collection
for node in users_collection.find():
    print(node)

# result = nodes_collection.delete_many({})  # Corrected method name
# print(f"{result.deleted_count} document(s) removed.")