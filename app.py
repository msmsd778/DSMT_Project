import os
import re
import datetime
import logging
import secrets
from flask import Flask, request, jsonify, g, send_from_directory, render_template, session, redirect, url_for, flash
from pymongo import MongoClient
from urllib.parse import unquote
import bcrypt
from bson.objectid import ObjectId
from bson.errors import InvalidId
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.utils import secure_filename
import atexit
import base64
import subprocess
import requests
import dateutil.parser


app = Flask(__name__)
app.secret_key = "mysecretkey"


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
sessions_collection.create_index("username", unique=True)
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

# Allowed extensions for profile pictures
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp'}

def validate_token(token):
    if not token:
        return None
    session = sessions_collection.find_one({"token": token})
    if session and session["expires_at"] > datetime.datetime.utcnow():
        return session["username"]
    return None

@app.route('/refresh_token', methods=['POST'])
# @limiter.limit("2000 per hour")
def refresh_token():
    data = request.json
    token = data.get('token')

    if not token:
        return jsonify({"error": "Token is required."}), 400

    # Lookup session by token
    session_doc = sessions_collection.find_one({"token": token})
    if not session_doc:
        return jsonify({"error": "Invalid or expired token."}), 401

    username = session_doc['username']

    # Generate a new token
    new_token = secrets.token_urlsafe(32)

    # Update the session with the new token and reset expiry
    sessions_collection.update_one(
        {"_id": session_doc["_id"]},
        {"$set": {
            "token": new_token,
            "expires_at": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }}
    )

    logger.info(f"Token refreshed for user '{username}'. New token: {new_token}")

    return jsonify({"message": "Token refreshed successfully.", "token": new_token}), 200


@app.route('/update_token', methods=['POST'])
def update_token():
    data = request.json
    new_token = data.get('token')
    if not new_token:
        return jsonify({"error": "Token is required."}), 400
    session['token'] = new_token
    username = session.get('username')
    node_name = session.get('node_name', 'node1@Asus-k571gt')  # Default node name

    if not username:
        return jsonify({"error": "Username not found in session."}), 400

    try:
        # Notify node_manager.erl to update the token in ETS
        result = subprocess.run(
            [
                "erl",
                "-noshell",
                "-sname", "bridge",
                "-setcookie", "mycookie",
                "-eval",
                f'rpc:call(\'{node_name}\', node_manager, replace_session, [<<"{username}">>, <<"{new_token}">>]).',
                "halt()"
            ],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            logger.error(f"Failed to update token in node_manager.erl: {result.stderr}")
            return jsonify({"error": "Failed to update token in node_manager."}), 500

        logger.info(f"Token updated in node_manager.erl for user '{username}'.")
        return jsonify({"message": "Token updated successfully."}), 200

    except Exception as e:
        logger.error(f"Error updating token: {str(e)}")
        return jsonify({"error": "Internal server error."}), 500


def refresh_soon_expiring_tokens():
    now = datetime.datetime.utcnow()
    soon_cutoff = now + datetime.timedelta(minutes=5)  # anything expiring in < 5 minutes

    # Find all sessions whose expires_at is between now and soon_cutoff
    soon_to_expire_sessions = sessions_collection.find({
        "expires_at": {"$gte": now, "$lt": soon_cutoff}
    })

    for session_doc in soon_to_expire_sessions:
        old_token = session_doc["token"]
        username = session_doc["username"]
        logger.info(f"Refreshing token for user '{username}' that expires soon...")

        # Make a direct POST to our own /refresh_token endpoint
        resp = requests.post("http://localhost:5000/refresh_token",
                            json={"token": old_token})
        if resp.status_code == 200:
            data = resp.json()
            new_token = data.get("token")
            logger.info(f"Refreshed token for '{username}': {new_token}")
        else:
            logger.warning(f"Failed to refresh token for '{username}': {resp.text}")


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
            "current_node": None,
            "status": "offline",
            "created_at": datetime.datetime.utcnow(),
            "last_online": None,
            "profile_picture_url": None
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
    node_name = data.get('node_name')  # Accept node_name from the request

    if not username or not password or not node_name:
        return jsonify({"error": "Username, password, and node_name are required."}), 400

    user = users_collection.find_one({"username": username})
    if user is None:
        return jsonify({"error": "Invalid credentials."}), 401

    stored_hash = user["password"].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        # User authenticated, create a session token
        token = secrets.token_urlsafe(32)
        
        # **NEW: Remove existing sessions for the user to enforce single session**
        sessions_collection.delete_many({"username": username})
        
        # Insert the new session
        sessions_collection.insert_one({
            "username": username,
            "token": token,
            "node_name": node_name,
            "created_at": datetime.datetime.utcnow(),
            "expires_at": datetime.datetime.utcnow() + datetime.timedelta(hours=2)  # Token valid for 2 hours
        })

        # Update user's status and current_node
        users_collection.update_one(
            {"username": username},
            {"$set": {
                "current_node": node_name,
                "status": "online"
            }}
        )

        return jsonify({"message": "Login successful.", "token": token}), 200
    else:
        return jsonify({"error": "Invalid credentials."}), 401


@app.route('/logout', methods=['POST'])
@limiter.limit("100 per hour")
def logout():
    """
    DO NOT call this directly from the frontend.
    This is called internally by Erlang's logout_user/2
    to finalize removing the session from MongoDB.
    """
    data = request.json
    token = data.get('token')
    if not token:
        return jsonify({"error": "Token is required."}), 400

    session_doc = sessions_collection.find_one({"token": token})
    if session_doc:
        username = session_doc['username']
        # Remove session from DB
        sessions_collection.delete_one({"token": token})

        # Set user offline, update last_online
        users_collection.update_one(
            {"username": username},
            {
                "$set": {
                    "status": "offline",
                    "last_online": datetime.datetime.utcnow(),
                    "current_node": None
                }
            }
        )
        logger.info(f"User '{username}' logged out successfully (Python).")
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
scheduler.add_job(update_last_online, 'interval', minutes=1)
scheduler.add_job(refresh_soon_expiring_tokens, 'interval', minutes=5)
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
    messages_cursor = messages_collection.find({
        "$or": [
            {"sender": sender, "receiver": other_user},
            {"sender": other_user, "receiver": sender}
        ],
        "deleted_globally": False
    }).sort("timestamp", 1)

    response = []
    message_ids_to_update = []

    for msg in messages_cursor:
        # Convert ObjectId to string
        msg_id = str(msg["_id"])
        # Prepare a timestamp ISO
        iso_ts = msg["timestamp"].isoformat()
        response.append({
            "_id": msg_id,
            "sender": msg['sender'],
            "receiver": msg['receiver'],
            "message": msg['message'],
            "timestamp": iso_ts,
            "read_by": msg.get('read_by', [])
        })

        # Collect message IDs that need to be marked as read
        if msg['receiver'] == sender and sender not in msg.get('read_by', []):
            message_ids_to_update.append(msg['_id'])

    # Mark messages as read
    if message_ids_to_update:
        messages_collection.update_many(
            {"_id": {"$in": message_ids_to_update}},
            {"$push": {"read_by": sender}}
        )

    logger.info(f"Messages fetched between '{sender}' and '{other_user}'.")
    return jsonify({"messages": response}), 200


@app.route('/delete_message', methods=['POST'])
def delete_message():
    data = request.json
    token = data.get('token')
    message_id = data.get('message_id')
    # You can ignore `delete_for_both` for now if you truly want to remove it.

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    msg = messages_collection.find_one({"_id": ObjectId(message_id)})
    if not msg:
        return jsonify({"error": "Message not found."}), 404

    # Optionally check if user is the sender or receiver
    # if username not in [msg.get("sender"), msg.get("receiver")]:
    #    return jsonify({"error": "Not authorized to delete this message."}), 403

    messages_collection.delete_one({"_id": ObjectId(message_id)})
    return jsonify({"message": "Message permanently deleted."}), 200



@app.route('/get_chat_partners', methods=['GET'])
@limiter.limit("100 per hour")
def get_chat_partners():
    token = request.args.get('token')
    user = sessions_collection.find_one({"token": token})
    if not user:
        return jsonify({"error": "Invalid or expired token."}), 401

    username = user['username']
    try:
        sent_messages = messages_collection.find({"sender": username, "deleted_globally": False})
        received_messages = messages_collection.find({"receiver": username, "deleted_globally": False})
        
        sent_partners = set(msg['receiver'] for msg in sent_messages)
        received_partners = set(msg['sender'] for msg in received_messages)
        
        chat_partners = list(sent_partners.union(received_partners))
        
        # Return JSON: { "chat_partners": ["bob", "alice"] }
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
    extension = data.get('extension')  # Now extension is without the dot

    if not token or not image_data or not extension:
        return jsonify({"error": "Token, image data, and extension are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    try:
        allowed_extensions = ['png', 'jpg', 'jpeg', 'gif', 'bmp']
        if extension not in allowed_extensions:
            return jsonify({"error": f"Unsupported file extension: {extension}"}), 400

        image_bytes = base64.b64decode(image_data)
        filename = f"{username}.{extension}"  # Add the dot when creating filename

        os.makedirs("profile_pictures", exist_ok=True)
        file_path = os.path.join("profile_pictures", filename)
        with open(file_path, "wb") as img_file:
            img_file.write(image_bytes)

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

@app.route("/")
def index():
    if "username" in session and "token" in session:
        return render_template("index.html", is_logged_in=True, username=session["username"])
    else:
        return render_template("index.html", is_logged_in=False)


def parse_erlang_ok_list(stdout_str):
    """
    Given something like:
      ReturnVal: {ok,[<<"alice">>,<<"bob">>]}
    returns ["alice","bob"].
    """
    if "ReturnVal: {ok," not in stdout_str:
        return []

    # Extract the bracketed part inside {ok,[ ... ]}
    pattern_outer = r'\{ok,\s*\[(.*?)\]\}'
    match_outer = re.search(pattern_outer, stdout_str)
    if not match_outer:
        return []

    # e.g. '<<"alice">>,<<"bob">>'
    raw_list = match_outer.group(1).strip()
    # Now find all occurrences of <<"...">>
    pattern_inner = r'<<\"(.*?)\">>'
    items = re.findall(pattern_inner, raw_list)

    return items


@app.route("/dashboard")
def dashboard():
    token = session.get('token')
    username = session.get('username')
    node_name = session.get('node_name', "node1@Asus-k571gt")

    if not token or not username:
        return redirect(url_for('index'))

    # Fetch your own user doc
    user_doc = users_collection.find_one({"username": username})
    if user_doc:
        user_profile_url = user_doc.get("profile_picture_url", "/static/default_profile.png")
    else:
        user_profile_url = "/static/default_profile.png"

    # 1) fetch chat partners via Erlang
    partners_result = call_erlang_function(
        node_name=node_name,
        function='get_chat_partners',
        args=[]
    )
    # parse them (already done in your code with parse_erlang_ok_list or similar):
    chat_partners = parse_erlang_ok_list(partners_result['stdout'])

    # 2) fetch user groups
    groups_result = call_erlang_function(
        node_name=node_name,
        function='get_user_groups',
        args=[]
    )
    group_names = parse_erlang_ok_list(groups_result['stdout'])

    return render_template(
        "dashboard.html",
        username=username,
        user_profile_url=user_profile_url,
        chat_partners=chat_partners,
        group_names=group_names
    )


@app.route('/register_via_erlang', methods=['POST'])
def register_via_erlang():
    node_name = request.form.get('reg_nodeName')
    username = request.form.get('reg_username')
    password = request.form.get('reg_password')
    profile_pic = request.files.get('reg_profile_pic')

    # Validate mandatory fields
    if not node_name or not username or not password:
        flash("Erlang Node Name, Username, and Password are required for registration.", "error")
        return render_template("index.html", is_logged_in=False)

    # Call node_manager:register_user
    reg_result = call_erlang_function(
        node_name=node_name,
        function='register_user',
        args=[username, password]
    )
    if "ReturnVal: {ok," in reg_result['stdout']:
        # Registration succeeded. Now login
        login_result = call_erlang_function(
            node_name=node_name,
            function='login_user',
            args=[username, password]
        )
        if "ReturnVal: {ok," in login_result['stdout']:
            token = extract_token_from_stdout(login_result['stdout'])
            if token:
                # Save to session
                session['username'] = username
                session['token'] = token
                session['node_name'] = node_name

                # If user uploaded a profile pic, process it
                if profile_pic and profile_pic.filename != '':
                    try:
                        file_bytes = profile_pic.read()
                        base64_data = base64.b64encode(file_bytes).decode('utf-8')

                        # Determine the file extension without the dot
                        _, file_extension = os.path.splitext(profile_pic.filename)
                        file_extension = file_extension.lower().lstrip('.')  # Remove the dot
                        if file_extension not in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
                            flash(f"Unsupported image format: {file_extension}", "error")
                            return render_template("index.html", is_logged_in=False)

                        # Prepare payload for profile picture update
                        payload = {
                            "token": token,
                            "image_data": base64_data,
                            "extension": file_extension  # Send without the dot
                        }
                        resp = requests.post(
                            "http://localhost:5000/set_profile_picture",
                            json=payload
                        )
                        if resp.status_code == 200:
                            flash("Registration and profile picture upload successful!", "success")
                        else:
                            error_msg = resp.json().get("error", "Failed to set profile picture.")
                            flash(f"Registration successful, but profile picture upload failed: {error_msg}", "error")
                    except Exception as e:
                        flash(f"Registration succeeded, but an error occurred while uploading the profile picture: {str(e)}", "error")
                        return render_template("index.html", is_logged_in=False)

                else:
                    flash("Registration successful!", "success")

                # Redirect to dashboard
                return redirect(url_for('dashboard'))
            else:
                flash("Registration was successful, but failed to retrieve token from login.", "error")
                return render_template("index.html", is_logged_in=False)
        else:
            flash("Registration succeeded, but login failed in Erlang.", "error")
            flash(f"Login Output: {reg_result['stdout']}", "error")
            return render_template("index.html", is_logged_in=False)
    elif "ReturnVal: {error," in reg_result['stdout']:
        error_message = extract_error_from_stdout(reg_result['stdout'])
        flash(f"Registration Failed: {error_message}", "error")
        return render_template("index.html", is_logged_in=False)
    else:
        flash("Registration command finished with an unknown outcome.", "error")
        flash(f"Output: {reg_result['stdout']}", "error")
        return render_template("index.html", is_logged_in=False)


def extract_error_from_stdout(stdout_str):
    """
    Extract error message from Erlang's stdout.
    Handles multiple error message formats.
    Examples:
    - {error,"Username already exists."}
    - {error,<<"Invalid credentials.">>}
    - {error,invalid_credentials}
    - {error,{invalid_credentials, "Detailed message."}}
    """
    # Pattern 1: {error,"Message"}
    pattern1 = r'\{error,\s*"(.+?)"\}'
    match1 = re.search(pattern1, stdout_str)
    if match1:
        return match1.group(1)

    # Pattern 2: {error,<<"Message">>}
    pattern2 = r'\{error,\s*<<\"(.+?)\">>\}'
    match2 = re.search(pattern2, stdout_str)
    if match2:
        return match2.group(1)

    # Pattern 3: {error,atom}
    pattern3 = r'\{error,\s*([a-zA-Z0-9_]+)\}'
    match3 = re.search(pattern3, stdout_str)
    if match3:
        return match3.group(1).replace('_', ' ').capitalize()

    # Pattern 4: {error,{atom, "Detailed message."}}
    pattern4 = r'\{error,\s*\{[a-zA-Z0-9_]+,\s*"(.+?)"\}\}'
    match4 = re.search(pattern4, stdout_str)
    if match4:
        return match4.group(1)

    # If no pattern matches
    return "Unknown error."



@app.route('/login_via_erlang', methods=['POST'])
def login_via_erlang():
    node_name = request.form.get('login_nodeName')
    username = request.form.get('login_username')
    password = request.form.get('login_password')

    # Validate mandatory fields
    if not node_name or not username or not password:
        flash("Erlang Node Name, Username, and Password are required for login.", "error")
        return render_template("index.html", is_logged_in=False)

    # Call node_manager:login_user
    login_result = call_erlang_function(
        node_name=node_name,
        function='login_user',
        args=[username, password]
    )

    # Check if login succeeded
    if "ReturnVal: {ok," in login_result['stdout']:
        token = extract_token_from_stdout(login_result['stdout'])
        if token:
            # Save in session
            session['username'] = username
            session['token'] = token
            session['node_name'] = node_name
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Login succeeded, but failed to parse token from login.", "error")
            return render_template("index.html", is_logged_in=False)
    elif "ReturnVal: {error," in login_result['stdout']:
        error_message = extract_error_from_stdout(login_result['stdout'])
        flash(f"Login Failed: {error_message}", "error")
        return render_template("index.html", is_logged_in=False)
    else:
        flash("Login command finished with an unknown outcome.", "error")
        flash(f"Output: {login_result['stdout']}", "error")
        return render_template("index.html", is_logged_in=False)
    

def call_erlang_function(node_name, function, args):
    """
    Spawns an ephemeral Erlang shell named 'bridge', 
    calls rpc:call(NodeName, node_manager, Function, Args),
    prints ReturnVal, then halts.
    Returns a dict with { 'returncode': int, 'stdout': str, 'stderr': str }
    """
    # Build the argument array for the rpc:call
    # Convert each string arg to an Erlang-escaped string
    erlang_args = ", ".join([f'\\"{arg}\\"' for arg in args])

    command = (
        f'erl -noshell -sname bridge -setcookie mycookie '
        f'-eval "'
        f'net_kernel:connect_node(\'{node_name}\'), '
        f'ReturnVal = rpc:call(\'{node_name}\', node_manager, {function}, [{erlang_args}]), '
        f'io:format(\\"ReturnVal: ~p~n\\", [ReturnVal]), '
        f'halt()"'
    )

    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return {
        'returncode': result.returncode,
        'stdout': result.stdout,
        'stderr': result.stderr
    }

def extract_token_from_stdout(stdout_str):

    # Look for something like {ok,"TOKEN"} or {ok,<<"TOKEN">>}

    # Regex to match {ok,"token"} or {ok,<<"token">>}
    # group(1) => the token
    pattern = r'\{ok,\s*("?<<)?\"?([^\"]+?)\"?(>>"?)?\}'

    match = re.search(pattern, stdout_str)
    if match:
        # The second group typically has the actual token
        token = match.group(2)
        return token
    return None


@app.route('/logout_local')
def logout_local():
    username = session.get("username")
    token = session.get("token")
    node_name = session.get("node_name")

    if username and token:
        logout_result = call_erlang_function(
            node_name=node_name,
            function="logout_user",
            args=[username, token]
        )
        app.logger.info(f"Erlang logout result: {logout_result['stdout']}")
    
    # Clear the local Flask session
    session.clear()
    return redirect(url_for("index"))


def format_time_for_display(dt):
    """
    dt is a datetime object in UTC. 
    Return short time if <24h old, else date + short time.
    """
    if not dt:
        return "Never"
    now = datetime.datetime.utcnow()
    diff = now - dt
    if diff.total_seconds() < 24 * 3600:
        # show HH:MM
        return dt.strftime("%H:%M")
    else:
        # show "DD Mon YYYY, HH:MM"
        return dt.strftime("%d %b %Y, %H:%M")


@app.route("/chat/<string:other_user>")
def chat_user(other_user):
    token = session.get('token')
    username = session.get('username')
    if not token or not username:
        return redirect(url_for('index'))

    # 1) Get other user’s profile
    # (We can do a direct GET or use the node_manager get_profile_picture if you want.)
    profile_url = None
    try:
        resp = requests.get("http://localhost:5000/get_profile_picture",
                            params={"token": token, "username": other_user})
        if resp.status_code == 200:
            data = resp.json()
            profile_url = data.get("image_url")
        else:
            profile_url = "/static/default_profile.png"
    except:
        profile_url = "/static/default_profile.png"

    # 2) Get other user’s status
    # e.g. GET /get_user_status?token=...&username=other_user
    other_user_display_status = ""  # the final string to display
    try:
        stat_resp = requests.get("http://localhost:5000/get_user_status",
                                params={"token": token, "username": other_user})
        if stat_resp.status_code == 200:
            st_data = stat_resp.json()
            if st_data["status"] == "online":
                other_user_display_status = "online"
            else:
                # offline => st_data["last_online"] is an ISO string?
                last_s = st_data.get("last_online")
                # parse
                dt = dateutil.parser.isoparse(last_s) if last_s else None
                formatted = format_time_for_display(dt)
                other_user_display_status = f"last seen {formatted}"
        else:
            # error fallback
            other_user_display_status = ""
    except:
        other_user_display_status = ""


    return render_template("chat_user.html",
                        username=username,
                        other_user=other_user,
                        other_user_profile=profile_url,
                        other_user_status=other_user_display_status)

@app.template_filter('to_datetime')
def to_datetime(value):
    from datetime import datetime
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# **NEW: Route to Render Change Information Page**
@app.route('/change_info', methods=['GET'])
def change_info():
    if "username" not in session or "token" not in session:
        flash("You need to be logged in to access this page.", "error")
        return redirect(url_for('index'))
    return render_template("change_info.html")

# **NEW: Route to Handle Password Change**
@app.route('/change_password', methods=['POST'])
@limiter.limit("10 per hour")  # Adjust rate limiting as needed
def change_password():
    if "username" not in session or "token" not in session:
        flash("You need to be logged in to change your password.", "error")
        return redirect(url_for('index'))
    
    username = session["username"]
    token = session["token"]
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash("All password fields are required.", "error")
        return redirect(url_for('change_info'))
    
    if new_password != confirm_password:
        flash("New passwords do not match.", "error")
        return redirect(url_for('change_info'))
    
    user = users_collection.find_one({"username": username})
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('change_info'))
    
    stored_hash = user["password"].encode('utf-8')
    if not bcrypt.checkpw(current_password.encode('utf-8'), stored_hash):
        flash("Current password is incorrect.", "error")
        return redirect(url_for('change_info'))
    
    # Hash the new password
    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    
    # Update the password in the database
    try:
        users_collection.update_one(
            {"username": username},
            {"$set": {"password": hashed_new_password.decode('utf-8')}}
        )
        flash("Password updated successfully.", "success")
        
        # Optionally, you might want to logout the user after password change
        # and require them to login again with the new password.
        # For now, we'll keep them logged in.
        
        return redirect(url_for('change_info'))
    except Exception as e:
        flash("An error occurred while updating the password.", "error")
        return redirect(url_for('change_info'))

# **NEW: Route to Handle Profile Picture Change**
@app.route('/change_profile_picture', methods=['POST'])
@limiter.limit("10 per hour")  # Adjust rate limiting as needed
def change_profile_picture():
    if "username" not in session or "token" not in session:
        flash("You need to be logged in to change your profile picture.", "error")
        return redirect(url_for('index'))
    
    username = session["username"]
    token = session["token"]
    
    if 'profile_picture' not in request.files:
        flash("No file part in the request.", "error")
        return redirect(url_for('change_info'))
    
    file = request.files['profile_picture']
    
    if file.filename == '':
        flash("No file selected for uploading.", "error")
        return redirect(url_for('change_info'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_ext = os.path.splitext(filename)[1].lower().lstrip('.')  # Remove the dot
        
        # Read file content
        file_bytes = file.read()
        base64_image = base64.b64encode(file_bytes).decode('utf-8')
        
        # Prepare payload for profile picture update
        payload = {
            "token": token,
            "image_data": base64_image,
            "extension": file_ext  # Now extension is without the dot
        }
        
        try:
            # Call the existing /set_profile_picture route internally
            # For simplicity, we'll make an HTTP request to the route
            response = requests.post("http://localhost:5000/set_profile_picture", json=payload)
            if response.status_code == 200:
                data = response.json()
                flash("Profile picture updated successfully.", "success")
            else:
                error_msg = data.get("error", "Failed to update profile picture.")
                flash(f"Error: {error_msg}", "error")
        except Exception as e:
            flash("An error occurred while updating the profile picture.", "error")
        
        return redirect(url_for('change_info'))
    else:
        flash("Allowed image types are - png, jpg, jpeg, gif, bmp.", "error")
        return redirect(url_for('change_info'))


if __name__ == "__main__":
    app.run(port=5000, debug=True)