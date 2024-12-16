import os
import datetime
import logging
import secrets
from flask import Flask, request, jsonify
from pymongo import MongoClient
from urllib.parse import unquote
import bcrypt

app = Flask(__name__)

NODE_NAME = os.environ.get("NODE_NAME", "default_node_name")

client = MongoClient("mongodb://localhost:27017/")
db = client["messenger_db"]
users_collection = db["users"]
messages_collection = db["messages"]
nodes_collection = db["nodes"]
sessions_collection = db["sessions"]
groups_collection = db["groups"]
group_messages_collection = db["group_messages"]

# Indexes
users_collection.create_index("username", unique=True)
nodes_collection.create_index("node_name", unique=True)
sessions_collection.create_index("token", unique=True)
groups_collection.create_index("group_name", unique=True)

def validate_token(token):
    """Check if the provided session token is valid and return the username if so."""
    if not token:
        return None
    session = sessions_collection.find_one({"token": token, "node_name": NODE_NAME})
    if session:
        return session["username"]
    return None

# User Registration (Hashing passwords)
@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        users_collection.insert_one({
            "username": username,
            "password": hashed_password.decode('utf-8'),
            "current_node": None
        })
        return jsonify({"message": "User registered successfully."}), 201
    except Exception as e:
        if "E11000 duplicate key error" in str(e):
            return jsonify({"error": "Username already exists."}), 400
        return jsonify({"error": str(e)}), 500

# User Login (Generate session token)
@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    user = users_collection.find_one({"username": username})
    if user is None:
        return jsonify({"error": "Invalid credentials."}), 401

    stored_hash = user["password"].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        # User authenticated, create a session token
        token = secrets.token_urlsafe(32)
        
        # Insert or update session
        sessions_collection.insert_one({
            "username": username,
            "token": token,
            "node_name": NODE_NAME,
            "created_at": datetime.datetime.utcnow()
        })

        # Update user's current_node
        users_collection.update_one({"username": username}, {"$set": {"current_node": NODE_NAME}})
        
        return jsonify({"message": "Login successful.", "token": token}), 200
    else:
        return jsonify({"error": "Invalid credentials."}), 401

@app.route('/logout', methods=['POST'])
def logout():
    data = request.json
    token = data.get('token')
    if not token:
        return jsonify({"error": "Token is required."}), 400

    result = sessions_collection.delete_one({"token": token})
    if result.deleted_count > 0:
        return jsonify({"message": "Logged out successfully."}), 200
    else:
        return jsonify({"error": "Invalid token or already logged out."}), 401

# Send Message (Requires token)
@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    token = data.get('token')
    receiver = data.get('receiver')
    message = data.get('message')

    sender = validate_token(token)
    if not sender:
        return jsonify({"error": "Invalid or missing token."}), 401

    if not receiver or not message:
        return jsonify({"error": "Receiver and message are required."}), 400

    # Check if the receiver exists
    receiver_user = users_collection.find_one({"username": receiver})
    if not receiver_user:
        return jsonify({"error": f"Receiver user '{receiver}' does not exist."}), 400

    try:
        messages_collection.insert_one({
            "sender": sender,
            "receiver": receiver,
            "message": message,
            "timestamp": datetime.datetime.utcnow()
        })
        return jsonify({"message": "Message sent successfully."}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Retrieve Messages (Requires token)
@app.route('/get_messages', methods=['GET'])
def get_messages():
    token = request.args.get('token')
    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    messages = list(messages_collection.find({"receiver": username}))
    for msg in messages:
        msg["_id"] = str(msg["_id"])
    return jsonify(messages), 200

@app.route('/register_node', methods=['POST'])
def register_node():
    data = request.json
    node_name = data.get("node_name")
    try:
        nodes_collection.update_one(
            {"node_name": node_name},
            {"$set": {"status": "connected"}},
            upsert=True
        )
        return jsonify({"message": f"Node {node_name} registered successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_active_nodes', methods=['GET'])
def get_active_nodes():
    try:
        nodes = nodes_collection.find({"status": "connected"})
        node_list = [{"node_name": node["node_name"]} for node in nodes]
        return jsonify({"nodes": node_list}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/remove_node/<path:node_name>', methods=['DELETE'])
def remove_node(node_name):
    node_name = unquote(node_name)
    logging.info(f"Received DELETE request for node_name: {node_name}")

    node = nodes_collection.find_one({"node_name": node_name})
    if not node:
        return jsonify({"error": f"Node {node_name} not found."}), 404

    result = nodes_collection.delete_one({"node_name": node_name})
    if result.deleted_count > 0:
        logging.info(f"Node {node_name} removed successfully.")
        return jsonify({"message": f"Node {node_name} removed successfully."}), 200
    else:
        logging.info(f"Failed to remove node {node_name}.")
        return jsonify({"error": f"Failed to remove node {node_name}."}), 500


@app.route('/create_group', methods=['POST'])
def create_group():
    data = request.json
    token = data.get('token')
    group_name = data.get('group_name')
    members = data.get('members', [])

    sender = validate_token(token)
    if not sender:
        return jsonify({"error": "Invalid or missing token."}), 401

    if not group_name or not isinstance(members, list):
        return jsonify({"error": "Group name and members array are required."}), 400

    # Validate members existence
    for member in members:
        if users_collection.find_one({"username": member}) is None:
            return jsonify({"error": f"User '{member}' does not exist."}), 400

    # Also check if group_name is unique
    if groups_collection.find_one({"group_name": group_name}):
        return jsonify({"error": "Group name already exists."}), 400

    # Add the creator to the group if not already included
    if sender not in members:
        members.append(sender)

    groups_collection.insert_one({
        "group_name": group_name,
        "members": members
    })

    return jsonify({"message": f"Group '{group_name}' created successfully.", "group_name": group_name}), 201



@app.route('/add_user_to_group', methods=['POST'])
def add_user_to_group():
    data = request.json
    token = data.get('token')
    group_name = data.get('group_name')
    username = data.get('username')

    sender = validate_token(token)
    if not sender:
        return jsonify({"error": "Invalid or missing token."}), 401

    if not group_name or not username:
        return jsonify({"error": "Group name and username are required."}), 400

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": f"Group '{group_name}' does not exist."}), 400

    # Check user existence
    if users_collection.find_one({"username": username}) is None:
        return jsonify({"error": f"User '{username}' does not exist."}), 400

    # Add user if not already a member
    if username in group["members"]:
        return jsonify({"error": f"User '{username}' is already a member of '{group_name}'."}), 400

    groups_collection.update_one(
        {"group_name": group_name},
        {"$push": {"members": username}}
    )
    return jsonify({"message": f"User '{username}' added to group '{group_name}'."}), 200


@app.route('/group_message', methods=['POST'])
def group_message():
    data = request.json
    token = data.get('token')
    group_name = data.get('group_name')
    message = data.get('message')

    sender = validate_token(token)
    if not sender:
        return jsonify({"error": "Invalid or missing token."}), 401

    if not group_name or not message:
        return jsonify({"error": "Group name and message are required."}), 400

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": f"Group '{group_name}' does not exist."}), 400

    # Check if sender is a member
    if sender not in group["members"]:
        return jsonify({"error": "You are not a member of this group."}), 403

    # Insert into group_messages
    group_messages_collection.insert_one({
        "group_name": group_name,
        "sender": sender,
        "message": message,
        "timestamp": datetime.datetime.utcnow()
    })

    return jsonify({"message": f"Message sent to group '{group_name}' successfully."}), 201



@app.route('/get_group_messages', methods=['GET'])
def get_group_messages():
    token = request.args.get('token')
    group_name = request.args.get('group_name')

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    if not group_name:
        return jsonify({"error": "group_name query param is required."}), 400

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": f"Group '{group_name}' does not exist."}), 400

    if username not in group["members"]:
        return jsonify({"error": "You are not a member of this group."}), 403

    msgs = list(group_messages_collection.find({"group_name": group_name}))
    for msg in msgs:
        msg["_id"] = str(msg["_id"])

    return jsonify(msgs), 200


if __name__ == "__main__":
    app.run(port=5000, debug=True)
