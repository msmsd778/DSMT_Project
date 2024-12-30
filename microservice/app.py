import os
import datetime
import logging
import secrets
from flask import Flask, request, jsonify, g, send_from_directory, render_template
from pymongo import MongoClient
from urllib.parse import unquote
import bcrypt
from bson.objectid import ObjectId
from bson.errors import InvalidId
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import base64
import subprocess


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
group_messages_collection.create_index("deleted_by")
messages_collection.create_index("read_by")
group_messages_collection.create_index("read_by")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[]
)

def validate_token(token):
    """Check if the provided session token is valid and return the username if so."""
    if not token:
        return None
    session = sessions_collection.find_one({"token": token, "node_name": NODE_NAME})
    if session and session["expires_at"] > datetime.datetime.utcnow():
        return session["username"]
    return None


@app.route('/refresh_token', methods=['POST'])
@limiter.limit("50 per hour")
def refresh_token():
    data = request.json
    token = data.get('token')

    if not token:
        return jsonify({"error": "Token is required."}), 400

    session = sessions_collection.find_one({"token": token, "node_name": NODE_NAME})
    if not session:
        return jsonify({"error": "Invalid or expired token."}), 401

    # Generate a new token
    new_token = secrets.token_urlsafe(32)

    # Update the session with the new token and reset expiry
    sessions_collection.update_one(
        {"_id": session["_id"]},
        {"$set": {
            "token": new_token,
            "expires_at": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }}
    )

    logger.info(f"Token refreshed for user '{session['username']}'. New token: {new_token}")

    return jsonify({"message": "Token refreshed successfully.", "token": new_token}), 200


# User Registration (Hashing passwords)
@app.route('/register', methods=['POST'])
# @limiter.limit("3 per hour")
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
        logger.info(f"User '{username}' registered successfully.")
        return jsonify({"message": "User registered successfully."}), 201
    except Exception as e:
        if "E11000 duplicate key error" in str(e):
            return jsonify({"error": "Username already exists."}), 400
        logger.error(f"Error registering user '{username}': {str(e)}")
        return jsonify({"error": str(e)}), 500


# User Login (Generate session token)
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
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
            "created_at": datetime.datetime.utcnow(),
            "expires_at": datetime.datetime.utcnow() + datetime.timedelta(hours=2)  # Token valid for 2 hours
        })


        # Update user's current_node
        users_collection.update_one({"username": username}, {"$set": {"current_node": NODE_NAME}})
        
        return jsonify({"message": "Login successful.", "token": token}), 200
    else:
        return jsonify({"error": "Invalid credentials."}), 401

@app.route('/logout', methods=['POST'])
@limiter.limit("100 per hour")
def logout():
    data = request.json
    token = data.get('token')
    if not token:
        return jsonify({"error": "Token is required."}), 400

    session = sessions_collection.find_one({"token": token})
    if session:
        username = session['username']
        # Remove the session
        sessions_collection.delete_one({"token": token})
        
        # Update the user's last_online timestamp
        users_collection.update_one(
            {"username": username},
            {"$set": {"last_online": datetime.datetime.utcnow()}}
        )
        
        logger.info(f"User '{username}' logged out successfully.")
        return jsonify({"message": "Logged out successfully."}), 200
    else:
        return jsonify({"error": "Invalid token or already logged out."}), 401

@app.route('/get_user_status', methods=['GET'])
@limiter.limit("100 per hour")
def get_user_status():
    token = request.args.get('token')
    username = request.args.get('username')
    
    if not token or not username:
        return jsonify({"error": "Token and username are required."}), 400
    
    requester = validate_token(token)
    if not requester:
        return jsonify({"error": "Invalid or missing token."}), 401
    
    try:
        # Check if the target user exists
        user = users_collection.find_one({"username": username})
        if not user:
            return jsonify({"error": "User does not exist."}), 404
        
        # Check if the target user has any active sessions
        active_session = sessions_collection.find_one({"username": username, "expires_at": {"$gt": datetime.datetime.utcnow()}})
        
        if active_session:
            status = "online"
            last_online = None
        else:
            status = "offline"
            last_online = user.get("last_online", "Never")
        
        response = {"status": status}
        if status == "offline":
            if isinstance(last_online, datetime.datetime):
                response["last_online"] = last_online.isoformat() + "Z"
            else:
                response["last_online"] = last_online
       
        return jsonify(response), 200
    except Exception as e:
        logger.error(f"Error fetching status for user '{username}': {str(e)}")
        return jsonify({"error": "Failed to retrieve user status."}), 500
    
# Define the function to update last_online
def update_last_online():
    current_time = datetime.datetime.utcnow()
    expired_sessions = sessions_collection.find({"expires_at": {"$lte": current_time}})
    for session in expired_sessions:
        username = session['username']
        users_collection.update_one(
            {"username": username},
            {"$set": {"last_online": current_time}}
        )
        sessions_collection.delete_one({"_id": session['_id']})
        logger.info(f"Session expired for user '{username}'. Updated last_online.")


# Initialize the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(update_last_online, 'interval', minutes=5)
scheduler.start()

# Ensure the scheduler is shut down when the app stops
atexit.register(lambda: scheduler.shutdown())

# Send Message (Requires token)
@app.route('/send_message', methods=['POST'])
@limiter.limit("1000 per day; 50 per minute")
def send_message():
    data = request.json
    token = data.get('token')
    receiver = data.get('receiver')
    message = data.get('message')

    if not token or not receiver or not message:
        return jsonify({"error": "Token, receiver, and message are required."}), 400

    sender = validate_token(token)
    if not sender:
        return jsonify({"error": "Invalid or missing token."}), 401

    # Check if receiver exists
    if not db['users'].find_one({"username": receiver}):
        return jsonify({"error": "Receiver does not exist."}), 400

    # Create message document
    msg = {
        "sender": sender,
        "receiver": receiver,
        "message": message,
        "timestamp": datetime.datetime.utcnow(),
        "read_by": [],  # Initially unread
        "deleted_globally": False
    }

    messages_collection.insert_one(msg)
    logger.info(f"Message sent from '{sender}' to '{receiver}': {message}")
    return jsonify({"message": "Message sent successfully."}), 201


# Retrieve Messages (Requires token)
@app.route('/get_messages', methods=['GET'])
@limiter.limit("1000 per day")
def get_messages():
    token = request.args.get('token')
    other_user = request.args.get('other_user')

    if not token or not other_user:
        return jsonify({"error": "Token and other_user are required."}), 400

    sender = validate_token(token)
    if not sender:
        return jsonify({"error": "Invalid or missing token."}), 401

    # Fetch messages between sender and other_user
    messages = list(messages_collection.find({
        "$or": [
            {"sender": sender, "receiver": other_user},
            {"sender": other_user, "receiver": sender}
        ],
        "deleted_globally": False
    }).sort("timestamp", 1))

    # Mark messages as read if the recipient is viewing them
    for msg in messages:
        if msg['receiver'] == sender and sender not in msg.get('read_by', []):
            messages_collection.update_one(
                {"_id": msg['_id']},
                {"$push": {"read_by": sender}}
            )
    
    # Prepare response
    response = []
    for msg in messages:
        response.append({
            "sender": msg['sender'],
            "receiver": msg['receiver'],
            "message": msg['message'],
            "timestamp": msg['timestamp'].isoformat(),
            "read_by": msg.get('read_by', [])
        })

    logger.info(f"Messages fetched between '{sender}' and '{other_user}'.")
    return jsonify({"messages": response}), 200


@app.route('/delete_message', methods=['POST'])
@limiter.limit("100 per day")
def delete_message():
    data = request.json
    token = data.get('token')
    message_id = data.get('message_id')
    delete_for_both = data.get('delete_for_both', False)  # Boolean flag

    if not token or not message_id:
        return jsonify({"error": "Token and message_id are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    try:
        msg = messages_collection.find_one({"_id": ObjectId(message_id)})
        if not msg:
            return jsonify({"error": "Message not found."}), 404

        if username not in [msg.get("sender"), msg.get("receiver")]:
            return jsonify({"error": "You are not authorized to delete this message."}), 403

        if delete_for_both:
            # Add both users to 'deleted_by'
            updated_deleted_by = msg.get("deleted_by", [])
            if "deleted_by" not in msg:
                updated_deleted_by = []
            if msg["sender"] not in updated_deleted_by:
                updated_deleted_by.append(msg["sender"])
            if msg["receiver"] not in updated_deleted_by:
                updated_deleted_by.append(msg["receiver"])
            messages_collection.update_one(
                {"_id": ObjectId(message_id)},
                {"$set": {"deleted_by": updated_deleted_by}}
            )
            return jsonify({"message": "Message deleted for both users."}), 200
        else:
            # Add only the current user to 'deleted_by'
            if username in msg.get("deleted_by", []):
                return jsonify({"error": "Message already deleted for you."}), 400
            messages_collection.update_one(
                {"_id": ObjectId(message_id)},
                {"$push": {"deleted_by": username}}
            )
            return jsonify({"message": "Message deleted for you."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/get_chat_partners', methods=['GET'])
@limiter.limit("100 per hour")
def get_chat_partners():
    token = request.args.get('token')
    
    if not token:
        return jsonify({"error": "Token is required."}), 400
    
    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401
    
    try:
        # Find all unique users the current user has sent messages to or received messages from
        sent_messages = messages_collection.find({"sender": username, "deleted_globally": False})
        received_messages = messages_collection.find({"receiver": username, "deleted_globally": False})
        
        sent_partners = set(msg['receiver'] for msg in sent_messages)
        received_partners = set(msg['sender'] for msg in received_messages)
        
        chat_partners = list(sent_partners.union(received_partners))
        
        return jsonify({"chat_partners": chat_partners}), 200
    except Exception as e:
        logger.error(f"Error fetching chat partners for user '{username}': {str(e)}")
        return jsonify({"error": "Failed to retrieve chat partners."}), 500

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
@limiter.limit("10 per day")
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

    # Check if group_name is unique
    if groups_collection.find_one({"group_name": group_name}):
        return jsonify({"error": "Group name already exists."}), 400

    # Add the creator to the group if not already included
    if sender not in members:
        members.append(sender)

    groups_collection.insert_one({
        "group_name": group_name,
        "members": members,
        "owner": sender  # Set the creator as the owner
    })

    return jsonify({"message": f"Group '{group_name}' created successfully.", "group_name": group_name}), 201


@app.route('/delete_group', methods=['DELETE'])
@limiter.limit("10 per day")
def delete_group():
    data = request.json
    token = data.get('token')
    group_name = data.get('group_name')

    if not token or not group_name:
        return jsonify({"error": "Token and group_name are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    # Find the group
    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": "Group does not exist."}), 400

    # Check if the requester is the owner
    if group.get("owner") != username:
        return jsonify({"error": "Only the group owner can delete the group."}), 403

    try:
        # Delete all group messages
        group_messages_collection.delete_many({"group_name": group_name})

        # Delete the group
        groups_collection.delete_one({"group_name": group_name})

        logger.info(f"Group '{group_name}' deleted by owner '{username}'.")

        # Optionally, notify other nodes about the group deletion
        # This can be implemented as needed

        return jsonify({"message": f"Group '{group_name}' deleted successfully."}), 200

    except Exception as e:
        logger.error(f"Error deleting group '{group_name}': {str(e)}")
        return jsonify({"error": "Failed to delete group."}), 500


@app.route('/get_user_groups', methods=['GET'])
@limiter.limit("100 per hour")
def get_user_groups():
    token = request.args.get('token')
    
    if not token:
        return jsonify({"error": "Token is required."}), 400
    
    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401
    
    try:
        # Find all groups where the user is a member
        groups = groups_collection.find({"members": username})
        group_names = [group["group_name"] for group in groups]
        
        return jsonify({"group_names": group_names}), 200
    except Exception as e:
        logger.error(f"Error fetching groups for user '{username}': {str(e)}")
        return jsonify({"error": "Failed to retrieve user groups."}), 500
    

@app.route('/add_user_to_group', methods=['POST'])
@limiter.limit("50 per day")
def add_user_to_group():
    data = request.json
    token = data.get('token')
    group_name = data.get('group_name')
    username_to_add = data.get('username')

    if not token or not group_name or not username_to_add:
        return jsonify({"error": "Token, group_name, and username are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    # Find the group
    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        # Return a generic error message without specifying that the group doesn't exist
        return jsonify({"error": "Failed to add user to the group."}), 400

    # Check if the requester is a member
    if username not in group.get("members", []):
        return jsonify({"error": "Failed to add user to the group."}), 403

    # Check if the user to add already exists in the group
    if username_to_add in group.get("members", []):
        return jsonify({"error": "Failed to add user to the group."}), 400

    # Check if the user to add exists in the system
    if not users_collection.find_one({"username": username_to_add}):
        return jsonify({"error": "Failed to add user to the group."}), 400

    try:
        # Add the user to the group
        groups_collection.update_one(
            {"group_name": group_name},
            {"$push": {"members": username_to_add}}
        )
        logger.info(f"User '{username_to_add}' added to group '{group_name}' by '{username}'.")
        return jsonify({"message": f"User '{username_to_add}' added to group '{group_name}' successfully."}), 200
    except Exception as e:
        logger.error(f"Error adding user '{username_to_add}' to group '{group_name}': {str(e)}")
        return jsonify({"error": "Failed to add user to the group."}), 500



@app.route('/remove_user_from_group', methods=['POST'])
@limiter.limit("50 per day")
def remove_user_from_group():
    data = request.json
    token = data.get('token')
    group_name = data.get('group_name')
    username_to_remove = data.get('username')

    if not token or not group_name or not username_to_remove:
        return jsonify({"error": "Token, group_name, and username are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    # Find the group
    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        # Return a generic error message without specifying that the group doesn't exist
        return jsonify({"error": "Failed to remove user from the group."}), 400

    # Check if the requester is the owner
    if group.get("owner") != username:
        return jsonify({"error": "Failed to remove user from the group."}), 403

    # Check if the user to remove is a member
    if username_to_remove not in group.get("members", []):
        return jsonify({"error": "Failed to remove user from the group."}), 400

    # Prevent the owner from removing themselves
    if username_to_remove == username:
        return jsonify({"error": "Failed to remove user from the group."}), 400

    try:
        # Remove the user from the group
        groups_collection.update_one(
            {"group_name": group_name},
            {"$pull": {"members": username_to_remove}}
        )
        logger.info(f"User '{username_to_remove}' removed from group '{group_name}' by owner '{username}'.")
        return jsonify({"message": f"User '{username_to_remove}' removed from group '{group_name}' successfully."}), 200
    except Exception as e:
        logger.error(f"Error removing user '{username_to_remove}' from group '{group_name}': {str(e)}")
        return jsonify({"error": "Failed to remove user from the group."}), 500



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

    # Insert into group_messages with 'deleted_globally' field
    group_messages_collection.insert_one({
        "group_name": group_name,
        "sender": sender,
        "message": message,
        "timestamp": datetime.datetime.utcnow(),
        "deleted_globally": False  # Initialize as False
    })

    return jsonify({"message": f"Message sent to group '{group_name}' successfully."}), 201


@app.route('/send_group_message', methods=['POST'])
@limiter.limit("1000 per day")
def send_group_message():
    data = request.json
    token = data.get('token')
    group_name = data.get('group_name')
    message = data.get('message')

    if not token or not group_name or not message:
        return jsonify({"error": "Token, group_name, and message are required."}), 400

    sender = validate_token(token)
    if not sender:
        return jsonify({"error": "Invalid or missing token."}), 401

    # Check if group exists and sender is a member
    group = db['groups'].find_one({"group_name": group_name, "members": sender})
    if not group:
        return jsonify({"error": "Access denied or group does not exist."}), 403

    # Create group message document
    group_msg = {
        "group_name": group_name,
        "sender": sender,
        "message": message,
        "timestamp": datetime.datetime.utcnow(),
        "read_by": [],  # Initially unread by all members
        "deleted_globally": False
    }

    db['group_messages'].insert_one(group_msg)
    logger.info(f"Group message sent to '{group_name}' by '{sender}': {message}")
    return jsonify({"message": "Group message sent successfully."}), 201


@app.route('/get_group_messages', methods=['GET'])
@limiter.limit("5000 per day")
def get_group_messages():
    token = request.args.get('token')
    group_name = request.args.get('group_name')

    if not token or not group_name:
        return jsonify({"error": "Token and group_name are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    # Check if user is a member of the group
    group = db['groups'].find_one({"group_name": group_name, "members": username})
    if not group:
        return jsonify({"error": "Access denied or group does not exist."}), 403

    # Fetch group messages
    group_messages = list(db['group_messages'].find({
        "group_name": group_name,
        "deleted_globally": False
    }).sort("timestamp", 1))

    # Mark messages as read for this user
    for msg in group_messages:
        if username not in msg.get('read_by', []):
            db['group_messages'].update_one(
                {"_id": msg['_id']},
                {"$push": {"read_by": username}}
            )

    # Prepare response
    response = []
    for msg in group_messages:
        response.append({
            "sender": msg['sender'],
            "message": msg['message'],
            "timestamp": msg['timestamp'].isoformat(),
            "read_by": msg.get('read_by', [])
        })

    logger.info(f"Group messages fetched for group '{group_name}' by '{username}'.")
    return jsonify({"group_messages": response}), 200


@app.route('/delete_group_message', methods=['POST'])
@limiter.limit("100 per day")
def delete_group_message():
    data = request.json
    token = data.get('token')
    group_name = data.get('group_name')
    message_id = data.get('message_id')

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info(f"User with token {token} is attempting to delete message {message_id} from group {group_name}.")


    if not token or not group_name or not message_id:
        return jsonify({"error": "Token, group_name, and message_id are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    # Find the group
    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": f"Group '{group_name}' does not exist."}), 400

    if username not in group["members"]:
        return jsonify({"error": "You are not a member of this group."}), 403

    try:
        # Convert message_id to ObjectId
        obj_id = ObjectId(message_id)
    except InvalidId:
        return jsonify({"error": "Invalid message_id format."}), 400

    try:
        # Find the specific group message
        msg = group_messages_collection.find_one({"_id": obj_id, "group_name": group_name})
        if not msg:
            return jsonify({"error": "Message not found."}), 404

        # Check if the user is the sender of the message
        if msg["sender"] != username:
            return jsonify({"error": "You can only delete your own messages."}), 403

        # Check if the message is already deleted globally
        if msg.get("deleted_globally", False):
            return jsonify({"error": "Message already deleted."}), 400

        # Set 'deleted_globally' to True
        group_messages_collection.update_one(
            {"_id": obj_id},
            {"$set": {"deleted_globally": True}}
        )

        return jsonify({"message": "Message deleted from the group successfully."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Serve profile pictures
@app.route('/profile_pictures/<filename>', methods=['GET'])
def serve_profile_picture(filename):
    try:
        return send_from_directory('profile_pictures', filename)
    except Exception as e:
        logger.error(f"Error serving profile picture '{filename}': {str(e)}")
        return jsonify({"error": "Profile picture not found."}), 404

@app.route('/set_profile_picture', methods=['POST'])
def set_profile_picture():
    data = request.json
    token = data.get('token')
    image_data = data.get('image_data')

    if not token or not image_data:
        return jsonify({"error": "Token and image data are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    try:
        # Decode the Base64 image
        image_bytes = base64.b64decode(image_data)

        # Define the filename with the appropriate extension
        filename = f"{username}.png"  # Adjust based on image type if needed

        # Ensure the directory exists
        os.makedirs("profile_pictures", exist_ok=True)

        # Save the image file
        file_path = os.path.join("profile_pictures", filename)
        with open(file_path, "wb") as img_file:
            img_file.write(image_bytes)

        # Update the user's profile in the database with the image URL
        image_url = f"http://localhost:5000/profile_pictures/{filename}"
        users_collection.update_one(
            {"username": username},
            {"$set": {"profile_picture_url": image_url}}
        )

        logger.info(f"Profile picture updated for user '{username}'.")
        return jsonify({"message": "Profile picture updated successfully.", "image_url": image_url}), 200
    except Exception as e:
        logger.error(f"Error updating profile picture for user '{username}': {str(e)}")
        return jsonify({"error": "Failed to update profile picture."}), 500


@app.route('/get_profile_picture', methods=['GET'])
def get_profile_picture():
    token = request.args.get('token')
    target_username = request.args.get('username')

    if not token or not target_username:
        return jsonify({"error": "Token and username are required."}), 400

    requester = validate_token(token)
    if not requester:
        return jsonify({"error": "Invalid or missing token."}), 401

    user = users_collection.find_one({"username": target_username})
    if not user:
        return jsonify({"error": "User does not exist."}), 404

    # Retrieve the image URL from the database
    image_url = user.get("profile_picture_url")
    if not image_url:
        return jsonify({"error": "No profile picture set."}), 404

    return jsonify({"image_url": image_url}), 200

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register_via_erlang', methods=['POST'])
def register_via_erlang():
    # Extract form fields
    username = request.form.get('username')
    password = request.form.get('password')

    # Call the Erlang function register_user(Username, Password) on a running node
    # Adjust 'node1@HOST' and cookie as per your actual Erlang node name / cookie
    # Example usage of rpc:call: 
    #
    #   rpc:call('node1@HOST', node_manager, register_user, [Username, Password])
    #
    # We'll do it via command-line invocation to keep it simple:

    command = (
        f'erl -noshell -sname bridge -setcookie mycookie '
        f'-eval "'
        f'net_kernel:connect_node(\'node1@localhost\'), '          # ensure connection
        f'rpc:call(\'node1@localhost\', node_manager, register_user, [\\"{username}\\", \\"{password}\\"]), ' 
        f'halt()"'
    )

    # Execute the command
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    # Check for success or error
    if result.returncode == 0:
        # Return an HTML response or JSON as desired
        return f"<h3>Registration command sent to Erlang for user '{username}'.</h3><p>Output:<br>{result.stdout}</p>"
    else:
        error_msg = result.stderr or "Unknown error during Erlang command."
        return f"<h3>Registration failed!</h3><p>Error: {error_msg}</p>", 500

if __name__ == "__main__":
    app.run(port=5000, debug=True)