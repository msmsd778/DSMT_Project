import os
import re
import datetime
import logging
import secrets
from flask import Flask, request, jsonify, g, send_from_directory, render_template, session, redirect, url_for, flash, current_app
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
import tempfile
import json
import glob
import socket


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
erlang_node_process = None


def get_server_url():
    return os.getenv("SERVER_URL", "http://localhost:5000")


def validate_token(token):
    if not token:
        return None
    session = sessions_collection.find_one({"token": token})
    if session and session["expires_at"] > datetime.datetime.utcnow():
        return session["username"]
    return None

def normalize_node_name(node_name):
    # If node_name does not contain an '@', append "@" plus the hostname.
    if "@" not in node_name:
        host = socket.gethostname()
        return f"{node_name}@{host}"
    return node_name

@app.route('/refresh_token', methods=['POST'])
def refresh_token():
    data = request.json
    token = data.get('token')

    if not token:
        return jsonify({"error": "Token is required."}), 400

    session_doc = sessions_collection.find_one({"token": token})
    if not session_doc:
        return jsonify({"error": "Invalid or expired token."}), 401

    username = session_doc['username']

    # Generate a new token
    new_token = secrets.token_urlsafe(32)

    sessions_collection.update_one(
        {"_id": session_doc["_id"]},
        {"$set": {
            "token": new_token,
            "expires_at": datetime.datetime.utcnow() + datetime.timedelta(hours=168)
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
    node_name = session.get('node_name')

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
    soon_cutoff = now + datetime.timedelta(minutes=5)

    soon_to_expire_sessions = sessions_collection.find({
        "expires_at": {"$gte": now, "$lt": soon_cutoff}
    })

    for session_doc in soon_to_expire_sessions:
        old_token = session_doc["token"]
        username = session_doc["username"]
        logger.info(f"Refreshing token for user '{username}' that expires soon...")

        # Use the dynamic URL here.
        refresh_url = get_server_url() + "/refresh_token"
        resp = requests.post(refresh_url, json={"token": old_token})
        if resp.status_code == 200:
            data = resp.json()
            new_token = data.get("token")
            logger.info(f"Refreshed token for '{username}': {new_token}")
        else:
            logger.warning(f"Failed to refresh token for '{username}': {resp.text}")


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
            "profile_picture_url": None,
            "blocked_users": []
        })
        logger.info(f"User '{username}' registered successfully.")
        return jsonify({"message": "User registered successfully."}), 201
    except Exception as e:
        if "E11000 duplicate key error" in str(e):
            return jsonify({"error": "Username already exists."}), 400
        logger.error(f"Error registering user '{username}': {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/internal_login', methods=['POST'])
def internal_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    node_name = data.get('node_name')

    if not username or not password or not node_name:
        return jsonify({"error": "Username, password, and node_name are required."}), 400

    user = users_collection.find_one({"username": username})
    if user is None:
        return jsonify({"error": "Invalid credentials."}), 401

    stored_hash = user["password"].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        token = secrets.token_urlsafe(32)
        
        # Remove existing sessions for the user to enforce single session
        sessions_collection.delete_many({"username": username})
        
        sessions_collection.insert_one({
            "username": username,
            "token": token,
            "node_name": node_name,
            "created_at": datetime.datetime.utcnow(),
            "expires_at": datetime.datetime.utcnow() + datetime.timedelta(hours=168)  # Token valid for one week
        })

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


@app.route('/internal_logout', methods=['POST'])
def internal_logout():

    data = request.json
    token = data.get('token')
    if not token:
        return jsonify({"error": "Token is required."}), 400

    session_doc = sessions_collection.find_one({"token": token})
    if session_doc:
        username = session_doc['username']
        sessions_collection.delete_one({"token": token})

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


@app.route('/internal_get_user_status', methods=['POST'])
def internal_get_user_status():
    data = request.json
    token = data.get("token")
    username = data.get("username")

    if not token or not username:
        return jsonify({"error": "Token and username are required."}), 400

    requester = validate_token(token)
    if not requester:
        return jsonify({"error": "Invalid or missing token."}), 401

    try:
        user = users_collection.find_one({"username": username})
        if not user:
            return jsonify({"error": "User does not exist."}), 404

        # Use the status field from the user document.
        status = user.get("status", "offline")
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


scheduler = BackgroundScheduler()
scheduler.add_job(update_last_online, 'interval', minutes=1)
scheduler.add_job(refresh_soon_expiring_tokens, 'interval', minutes=5)
scheduler.start()

atexit.register(lambda: scheduler.shutdown())

@app.route("/internal_send_message", methods=["POST"])
def internal_send_message():
    data = request.json
    token = data.get('token')
    receiver = data.get('receiver')
    message = data.get('message')
    reply_to_msg_id = data.get('reply_to_msg_id')
    reply_preview = data.get('reply_preview')

    if not token or not receiver or not message:
        return jsonify({"error": "Token, receiver, and message are required."}), 400

    sender = validate_token(token)
    if not sender:
        return jsonify({"error": "Invalid or missing token."}), 401

    if not users_collection.find_one({"username": receiver}):
        return jsonify({"error": "Receiver does not exist."}), 400

    if reply_to_msg_id:
        try:
            original_msg = messages_collection.find_one({"_id": ObjectId(reply_to_msg_id)})
            if not original_msg:
                return jsonify({"error": "Original message to reply to does not exist."}), 400
        except:
            return jsonify({"error": "Invalid reply_to_msg_id format."}), 400

    msg_doc = {
        "sender": sender,
        "receiver": receiver,
        "message": message,
        "timestamp": datetime.datetime.utcnow(),
        "read_by": [],
        "deleted_globally": False,
        "edited": False
    }
    if reply_to_msg_id:
        msg_doc["reply_to"] = reply_to_msg_id
    if reply_preview:
        msg_doc["reply_preview"] = reply_preview

    try:
        messages_collection.insert_one(msg_doc)
        return jsonify({"message": "Message sent successfully."}), 200
    except Exception as e:
        return jsonify({"error": "Failed to send message."}), 500

@app.route('/internal_get_messages', methods=['POST'])
def internal_get_messages():
    data = request.json
    token = data.get("token")
    other_user = data.get("other_user")

    if not token or not other_user:
        return jsonify({"error": "Token and other_user are required."}), 400

    sender = validate_token(token)
    if not sender:
        return jsonify({"error": "Invalid or missing token."}), 401

    try:
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
            msg_id_str = str(msg["_id"])
            iso_ts = msg["timestamp"].isoformat()

            resp_msg = {
                "_id": msg_id_str,
                "sender": msg['sender'],
                "receiver": msg['receiver'],
                "message": msg['message'],
                "timestamp": iso_ts,
                "read_by": msg.get('read_by', []),
                "edited": msg.get('edited', False)
            }

            if 'reply_to' in msg:
                resp_msg["reply_to"] = str(msg['reply_to'])
            if 'reply_preview' in msg:
                resp_msg["reply_preview"] = msg['reply_preview']

            response.append(resp_msg)

            # Mark as read if the receiver is the sender and hasn't read it yet
            if msg['receiver'] == sender and sender not in msg.get('read_by', []):
                message_ids_to_update.append(msg['_id'])

        if message_ids_to_update:
            messages_collection.update_many(
                {"_id": {"$in": message_ids_to_update}},
                {"$push": {"read_by": sender}}
            )

        logger.info(f"Messages fetched between '{sender}' and '{other_user}'.")
        return jsonify({"messages": response}), 200

    except Exception as e:
        logger.error(f"Error fetching messages between '{sender}' and '{other_user}': {str(e)}")
        return jsonify({"error": "Failed to retrieve messages."}), 500


@app.route('/internal_delete_message', methods=['POST'])
def internal_delete_message():
    data = request.json
    token = data.get("token")
    message_id = data.get("message_id")

    if not token or not message_id:
        return jsonify({"error": "Token and message_id are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    try:
        msg_obj_id = ObjectId(message_id)
    except:
        return jsonify({"error": "Invalid message_id."}), 400

    message_doc = messages_collection.find_one({"_id": msg_obj_id})
    if not message_doc:
        return jsonify({"error": "Message not found."}), 404

    if message_doc['sender'] != username:
        return jsonify({"error": "You can only delete your own messages."}), 403

    try:
        messages_collection.delete_one({"_id": msg_obj_id})
        return jsonify({"message": "Message deleted successfully."}), 200
    except Exception as e:
        return jsonify({"error": "Failed to delete message."}), 500


@app.route('/internal_edit_message', methods=['POST'])
def internal_edit_message():
    data = request.json
    token = data.get("token")
    message_id = data.get("message_id")
    new_text = data.get("new_text")

    if not token or not message_id or not new_text:
        return jsonify({"error": "Token, message_id, and new_text are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    try:
        msg_obj_id = ObjectId(message_id)
    except:
        return jsonify({"error": "Invalid message_id."}), 400

    message_doc = messages_collection.find_one({"_id": msg_obj_id})
    if not message_doc:
        return jsonify({"error": "Message not found."}), 404

    # Ensure the current user is the sender
    if message_doc['sender'] != username:
        return jsonify({"error": "You can only edit your own messages."}), 403

    try:
        messages_collection.update_one(
            {"_id": msg_obj_id},
            {"$set": {
                "message": new_text,
                "edited": True
            }}
        )
        return jsonify({"message": "Message edited successfully."}), 200
    except Exception as e:
        return jsonify({"error": "Failed to edit message."}), 500


@app.route('/internal_get_chat_partners', methods=['GET'])
def internal_get_chat_partners():
    token = request.args.get('token')
    user = sessions_collection.find_one({"token": token})
    if not user:
        return jsonify({"error": "Invalid or expired token."}), 401

    username = user['username']
    try:
        sent = messages_collection.find({"sender": username, "deleted_globally": False})
        received = messages_collection.find({"receiver": username, "deleted_globally": False})
        chat_partners = list({m['receiver'] for m in sent} | {m['sender'] for m in received})
        return jsonify({"chat_partners": chat_partners}), 200
    except Exception as e:
        logger.error(f"Error: {str(e)}")
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


@app.route('/internal_create_group', methods=['POST'])
def internal_create_group():
    token = request.form.get("token")
    group_name = request.form.get("group_name", "").strip()
    members = request.form.get("members", "[]").strip()

    if not token or not group_name:
        return jsonify({"error": "Token and group_name are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or expired token."}), 401

    try:
        members = eval(members) if isinstance(members, str) else list(members)
        if not isinstance(members, list):
            raise ValueError
    except:
        return jsonify({"error": "Invalid members format."}), 400

    if groups_collection.find_one({"group_name": group_name}):
        return jsonify({"error": "Group name already exists."}), 400

    existing_users = users_collection.find({"username": {"$in": members}})
    existing_usernames = [user["username"] for user in existing_users]
    invalid_members = set(members) - set(existing_usernames)
    if invalid_members:
        return jsonify({"error": f"Users not found: {', '.join(invalid_members)}"}), 400

    # Add the creator to the members list if not already included
    if username not in members:
        members.append(username)

    try:
        groups_collection.insert_one({
            "group_name": group_name,
            "owner": username,
            "members": members,
            "created_at": datetime.datetime.utcnow()
        })
        return jsonify({"message": f"Group '{group_name}' created successfully."}), 201
    except Exception as e:
        app.logger.error(f"Error creating group: {str(e)}")
        return jsonify({"error": "Failed to create group."}), 500
    

@app.route('/internal_delete_group', methods=['POST'])
def internal_delete_group():
    data = request.get_json()
    token = data.get('token')
    group_name = data.get('group_name')

    if not token or not group_name:
        return jsonify({"error": "Token and group_name are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": "Group does not exist."}), 400

    if group.get("owner") != username:
        return jsonify({"error": "Only the group owner can delete the group."}), 403

    try:
        group_messages_collection.delete_many({"group_name": group_name})
        groups_collection.delete_one({"group_name": group_name})
        logger.info(f"Group '{group_name}' deleted by owner '{username}'.")
        return jsonify({"message": f"Group '{group_name}' deleted successfully."}), 200
    except Exception as e:
        logger.error(f"Error deleting group '{group_name}': {str(e)}")
        return jsonify({"error": "Failed to delete group."}), 500


@app.route('/internal_get_user_groups', methods=['GET'])
def internal_get_user_groups():
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "Token is required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or expired token."}), 401

    groups = groups_collection.find({"members": username})
    group_names = [grp["group_name"] for grp in groups]

    return jsonify({"group_names": group_names}), 200
    

@app.route("/internal_add_user_to_group", methods=["POST"])
def internal_add_user_to_group():
    data = request.json
    token = data.get("token")
    group_name = data.get("group_name")
    username_to_add = data.get("username")

    if not token or not group_name or not username_to_add:
        return jsonify({"error": "Token, group_name, and username are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": "Failed to add user to the group."}), 400

    if username not in group.get("members", []):
        return jsonify({"error": "Failed to add user to the group."}), 403

    if username_to_add in group.get("members", []):
        return jsonify({"error": "Failed to add user to the group."}), 400

    if not users_collection.find_one({"username": username_to_add}):
        return jsonify({"error": "Failed to add user to the group."}), 400

    try:
        groups_collection.update_one(
            {"group_name": group_name},
            {"$push": {"members": username_to_add}}
        )
        logger.info(f"User '{username_to_add}' added to group '{group_name}' by '{username}'.")
        return jsonify({"message": f"User '{username_to_add}' added to group '{group_name}' successfully."}), 200
    except Exception as e:
        logger.error(f"Error adding user '{username_to_add}' to group '{group_name}': {str(e)}")
        return jsonify({"error": "Failed to add user to the group."}), 500


@app.route("/internal_remove_user_from_group", methods=["POST"])
def internal_remove_user_from_group():
    data = request.json
    token = data.get("token")
    group_name = data.get("group_name")
    username_to_remove = data.get("username")

    if not token or not group_name or not username_to_remove:
        return jsonify({"error": "Token, group_name, and username are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or expired token."}), 401

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": "Group does not exist."}), 404

    if username_to_remove not in group["members"]:
        return jsonify({"error": "User not in group."}), 400

    if username_to_remove != username and group["owner"] != username:
        return jsonify({"error": "Only the owner can remove other users."}), 403

    if username_to_remove == username and group["owner"] == username:
        return jsonify({"error": "Owner must reassign ownership before leaving."}), 400

    try:
        groups_collection.update_one(
            {"group_name": group_name},
            {"$pull": {"members": username_to_remove}}
        )
        return jsonify({"message": f"User '{username_to_remove}' removed from group '{group_name}' successfully."}), 200
    except Exception as e:
        app.logger.error(f"Error removing user from group: {str(e)}")
        return jsonify({"error": "Failed to remove user from the group."}), 500


@app.route('/internal_search_users', methods=['GET'])
def internal_search_users():
    token = request.args.get('token', '')
    query = request.args.get('query', '').strip()

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or expired token."}), 401

    if not query:
        return jsonify({"users": []}), 200

    results_cursor = users_collection.find({
        "username": {
            "$regex": f"^{query}",
            "$options": "i"
        }
    }).limit(10)

    current_username = username
    results = []
    for u in results_cursor:
        uname = u["username"]
        if uname.lower() == "admin":
            continue
        # if uname == current_username:
        #     continue
        results.append(uname)

    return jsonify({"users": results}), 200


@app.route('/internal_send_group_message', methods=['POST'])
def internal_send_group_message():
    data = request.json
    token = data.get("token")
    group_name = data.get("group_name")
    message_text = data.get("message")

    if not token or not group_name or not message_text:
        return jsonify({"error": "Token, group_name, and message are required."}), 400

    sender = validate_token(token)
    if not sender:
        return jsonify({"error": "Invalid or missing token."}), 401

    group = db['groups'].find_one({"group_name": group_name, "members": sender})
    if not group:
        return jsonify({"error": "Access denied or group does not exist."}), 403

    group_msg = {
        "group_name": group_name,
        "sender": sender,
        "message": message_text,
        "reply_to": data.get("reply_to_msg_id"),
        "reply_preview": data.get("reply_preview"), 
        "timestamp": datetime.datetime.utcnow(),
        "read_by": [],
        "deleted_globally": False,
        "edited": False
    }

    db['group_messages'].insert_one(group_msg)
    return jsonify({"message": "Group message sent successfully."}), 200


@app.route('/internal_get_group_messages', methods=['GET'])
def internal_get_group_messages():
    token = request.args.get('token')
    group_name = request.args.get('group_name')

    if not token or not group_name:
        return jsonify({"error": "Token and group_name are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    group = db['groups'].find_one({"group_name": group_name, "members": username})
    if not group:
        return jsonify({"error": "Access denied or group does not exist."}), 403

    group_messages_cursor = db['group_messages'].find({
        "group_name": group_name,
        "deleted_globally": False
    }).sort("timestamp", 1)

    group_messages = list(group_messages_cursor)

    # Mark messages as read for this user
    for msg in group_messages:
        if username not in msg.get('read_by', []):
            db['group_messages'].update_one(
                {"_id": msg['_id']},
                {"$push": {"read_by": username}}
            )

    response = []
    for msg in group_messages:
        response.append({
            "_id": str(msg["_id"]),
            "sender": msg["sender"],
            "message": msg["message"],
            "reply_to": str(msg.get("reply_to")) if msg.get("reply_to") else None,
            "reply_preview": msg.get("reply_preview") if msg.get("reply_preview") else "",
            "timestamp": msg["timestamp"].isoformat(),
            "read_by": msg.get("read_by", []),
            "edited": msg.get("edited", False)
        })

    return jsonify({"group_messages": response}), 200


@app.route("/internal_edit_group_message", methods=["POST"])
def internal_edit_group_message():
    data = request.get_json()
    token = data.get("token")
    group_name = data.get("group_name")
    message_id = data.get("message_id")
    new_text = data.get("new_text")

    if not token or not group_name or not message_id or not new_text:
        return jsonify({"error": "Missing required parameters."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or expired token."}), 401

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": "Group does not exist."}), 404

    if username not in group["members"]:
        return jsonify({"error": "Access denied. You are not a member of this group."}), 403

    msg_doc = group_messages_collection.find_one({
      "_id": ObjectId(message_id),
      "group_name": group_name
    })
    if not msg_doc:
        return jsonify({"error": "Message not found."}), 404

    if msg_doc["sender"] != username and group["owner"] != username:
        return jsonify({"error": "You can only edit your own messages or be the group owner."}), 403

    try:
        group_messages_collection.update_one(
          {"_id": msg_doc["_id"]},
          {"$set": {"message": new_text, "edited": True}}
        )
        return jsonify({"message": "Group message edited successfully."}), 200
    except Exception as e:
        app.logger.error(f"Error editing group message: {str(e)}")
        return jsonify({"error": "Failed to edit group message."}), 500


@app.route('/internal_delete_group_message', methods=['POST'])
def internal_delete_group_message():
    data = request.json
    token = data.get('token')
    group_name = data.get('group_name')
    message_id = data.get('message_id')

    if not token or not group_name or not message_id:
        return jsonify({"error": "Token, group_name, and message_id are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or expired token."}), 401

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": "Group does not exist."}), 404

    if username not in group["members"]:
        return jsonify({"error": "Access denied. You are not a member of this group."}), 403

    message = group_messages_collection.find_one({"_id": ObjectId(message_id), "group_name": group_name})
    if not message:
        return jsonify({"error": "Message not found."}), 404

    if username != group["owner"] and username != message["sender"]:
        return jsonify({"error": "You can only delete your own messages or be the group owner."}), 403

    try:
        group_messages_collection.update_one(
            {"_id": ObjectId(message_id)},
            {"$set": {"deleted_globally": True}}
        )
        return jsonify({"message": "Message deleted successfully."}), 200
    except Exception as e:
        app.logger.error(f"Error deleting group message: {str(e)}")
        return jsonify({"error": "Failed to delete group message."}), 500


@app.route('/internal_get_group_members', methods=['GET'])
def internal_get_group_members():
    token = request.args.get("token")
    group_name = request.args.get("group_name")

    if not token or not group_name:
        return jsonify({"error": "Token and group_name are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or expired token."}), 401

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": f"Group '{group_name}' does not exist."}), 404

    if username not in group["members"]:
        return jsonify({"error": "Access denied. You are not a member of this group."}), 403

    return jsonify({
        "members": group["members"],
        "owner": group["owner"]
    }), 200


@app.route('/internal_reassign_group_owner_and_remove', methods=['POST'])
def internal_reassign_group_owner_and_remove():
    data = request.json
    token = data.get("token")
    group_name = data.get("group_name")
    new_owner = data.get("new_owner")

    if not token or not group_name or not new_owner:
        return jsonify({"error": "Token, group_name, and new_owner are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or expired token."}), 401

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": f"Group '{group_name}' does not exist."}), 404

    if group["owner"] != username:
        return jsonify({"error": "Only the current owner can reassign ownership."}), 403

    if new_owner not in group["members"]:
        return jsonify({"error": "New owner must be an existing group member."}), 400

    try:
        groups_collection.update_one(
            {"group_name": group_name},
            {"$set": {"owner": new_owner}}
        )
        groups_collection.update_one(
            {"group_name": group_name},
            {"$pull": {"members": username}}
        )
        return jsonify({"message": f"Ownership reassigned to '{new_owner}', and you have left the group."}), 200
    except Exception as e:
        app.logger.error(f"Error reassigning group ownership: {str(e)}")
        return jsonify({"error": "Failed to reassign group ownership."}), 500



@app.route('/leave_group', methods=['POST'])
def leave_group():
    data = request.json
    token = data.get('token')
    group_name = data.get('group_name')

    if not token or not group_name:
        return jsonify({"error": "Token and group_name are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or expired token."}), 401

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        return jsonify({"error": "Group does not exist."}), 404

    if username not in group["members"]:
        return jsonify({"error": "You are not a member of this group."}), 403

    if group["owner"] == username:
        return jsonify({"error": "You must reassign ownership before leaving the group."}), 400

    try:
        groups_collection.update_one(
            {"group_name": group_name},
            {"$pull": {"members": username}}
        )
        return jsonify({"message": f"You have left the group '{group_name}' successfully."}), 200
    except Exception as e:
        app.logger.error(f"Error leaving group: {str(e)}")
        return jsonify({"error": "Failed to leave the group."}), 500


@app.route("/group_chat/<string:group_name>")
def group_chat(group_name):
    now_utc = datetime.datetime.utcnow().isoformat()
    token = session.get('token')
    username = session.get('username')
    node_name = session.get('node_name')
    if not token or not username:
        return redirect(url_for('index'))

    group = groups_collection.find_one({"group_name": group_name})
    if not group:
        flash(f"Group '{group_name}' does not exist.", "error")
        return redirect(url_for('dashboard'))
    if username not in group["members"]:
        flash("You are not a member of this group.", "error")
        return redirect(url_for('dashboard'))

    members = group["members"]
    owner = group["owner"]

    group_msgs = list(group_messages_collection.find({
        "group_name": group_name,
        "deleted_globally": False
    }).sort("timestamp", 1))

    for msg in group_msgs:
        if username not in msg.get('read_by', []):
            group_messages_collection.update_one(
                {"_id": msg["_id"]},
                {"$push": {"read_by": username}}
            )

    processed = []
    for m in group_msgs:
        processed.append({
            "_id": str(m["_id"]),
            "sender": m["sender"],
            "message": m["message"],
            "timestamp": m["timestamp"].isoformat(),
            "read_by": m.get("read_by", [])
        })

    return render_template(
        "group_chat.html",
        username=username,
        group_name=group_name,
        node_name=node_name,
        owner=owner,
        members=members,
        messages=processed,
        now_utc=now_utc
    )


@app.route('/profile_pictures/<filename>', methods=['GET'])
def serve_profile_picture(filename):
    try:
        return send_from_directory(os.path.join(current_app.root_path, 'profile_pictures'), filename)
    except Exception as e:
        logger.error(f"Error serving profile picture '{filename}': {str(e)}")
        return jsonify({"error": "Profile picture not found."}), 404


@app.route('/internal_get_profile_picture', methods=['POST'])
def internal_get_profile_picture():
    data = request.json
    token = data.get("token")
    username = data.get("username")

    if not token or not username:
        return jsonify({"error": "Token and username are required."}), 400

    validated_user = validate_token(token)
    if not validated_user:
        return jsonify({"error": "Invalid or missing token."}), 401

    user_doc = users_collection.find_one({"username": username})
    if not user_doc:
        return jsonify({"error": "User not found."}), 404

    profile_picture_url = user_doc.get("profile_picture_url", "/profile_pictures/default_profile.png")

    return jsonify({"profile_picture": profile_picture_url}), 200



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

    image_url = user.get("profile_picture_url")
    if not image_url:
        return jsonify({"error": "No profile picture set."}), 404

    return jsonify({"image_url": image_url}), 200

@app.route("/")
def index():
    my_hostname = socket.gethostname()
    ua_string = request.headers.get("User-Agent", "")
    short_browser_name = get_browser_short_name(ua_string, my_hostname)

    default_nodename = f"{short_browser_name}@{my_hostname}"

    if "username" in session and "token" in session:
        return render_template(
            "index.html",
            is_logged_in=True,
            username=session["username"],
            default_nodename=default_nodename
        )
    else:
        return render_template(
            "index.html",
            is_logged_in=False,
            default_nodename=default_nodename
        )


def parse_erlang_ok_list(stdout_str):
    pattern = r'\{ok,\s*\[(.*?)\]\}'
    match = re.search(pattern, stdout_str, re.DOTALL)
    if match:
        users_str = match.group(1)
        users = re.findall(r'"([^"]+)"', users_str)
        return users
    return []

def parse_erlang_ok_message(stdout_str):
    list_of_maps_match = re.search(r'\{ok,\s*\[(#\{.*)\]\}', stdout_str, re.DOTALL)
    if list_of_maps_match:
        try:
            raw_array_str = list_of_maps_match.group(1)
            raw_array_str = raw_array_str.replace('<<>>', '<<"">>')
            raw_array_str = "[" + raw_array_str + "]"
            raw_array_str = raw_array_str.replace("=>", ":")
            raw_array_str = re.sub(r'<<"(.*?)">>', r'"\1"', raw_array_str)
            raw_array_str = raw_array_str.replace('#{', '{')

            return json.loads(raw_array_str)
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to parse array-of-maps JSON: {e}")
            print(f"Attempted array string: {raw_array_str}")
            return None

    pure_json_array_match = re.search(r'\{ok,\s*(\[[{].*?\])\}', stdout_str, re.DOTALL)
    if pure_json_array_match:
        try:
            raw_array_str = pure_json_array_match.group(1)
            return json.loads(raw_array_str)
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to parse pure JSON array: {e}")
            print(f"Attempted array string: {raw_array_str}")
            return None

    json_match = re.search(r'\{ok,\s*#{(.*?)}\}', stdout_str, re.DOTALL)
    if json_match:
        try:
            json_str = json_match.group(1)

            json_str = json_str.replace('<<>>', '<<"">>')

            json_str = json_str.replace("=>", ":")
            json_str = re.sub(r'<<"(.*?)">>', r'"\1"', json_str)
            json_str = json_str.replace('#{', '{')
            json_str = "{" + json_str + "}"

            return json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to parse Erlang JSON response: {e}")
            print(f"Attempted JSON string: {json_str}")
            return None

    string_match = re.search(r'\{ok,\s*"(.+?)"\}', stdout_str)
    if string_match:
        return string_match.group(1)

    return None


@app.route("/dashboard")
def dashboard():
    token = session.get('token')
    username = session.get('username')
    node_name = session.get('node_name')

    if not token or not username:
        return redirect(url_for('index'))

    user_doc = users_collection.find_one({"username": username})
    if user_doc:
        user_profile_url = user_doc.get("profile_picture_url", "/profile_pictures/default_profile.png")
    else:
        user_profile_url = "/profile_pictures/default_profile.png"

    partners_result = call_erlang_function(
        node_name=node_name,
        function='get_chat_partners',
        args=[]
    )
    chat_partners = parse_erlang_ok_list(partners_result['stdout'])

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
        group_names=group_names,
        node_name=node_name
    )


@app.route('/internal_get_unread_counts', methods=['GET'])
def internal_get_unread_counts():
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "Token is required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    private_unread = {}
    messages_cursor = messages_collection.find(
        {"$or": [{"sender": username}, {"receiver": username}]},
        {"sender": 1, "receiver": 1, "read_by": 1}
    )
    for msg in messages_cursor:
        sender_ = msg['sender']
        receiver_ = msg['receiver']
        partner = sender_ if receiver_ == username else receiver_
        if receiver_ == username and username not in msg.get('read_by', []):
            private_unread[partner] = private_unread.get(partner, 0) + 1

    all_partners = set()
    sent = messages_collection.find({"sender": username}, {"receiver": 1})
    received = messages_collection.find({"receiver": username}, {"sender": 1})
    for m in sent:
        all_partners.add(m['receiver'])
    for m in received:
        all_partners.add(m['sender'])
    for p in all_partners:
        if p not in private_unread:
            private_unread[p] = 0

    private_unread.pop("admin", None)
    private_unread.pop(username, None)

    group_unread = {}
    groups = groups_collection.find({"members": username}, {"group_name": 1})
    for g in groups:
        gname = g["group_name"]
        count = group_messages_collection.count_documents({
            "group_name": gname,
            "read_by": {"$ne": username},
            "deleted_globally": False
        })
        group_unread[gname] = count

    return jsonify({
        "private_unread": private_unread,
        "group_unread": group_unread
    }), 200


@app.route('/internal_change_password', methods=['GET'])
def internal_change_password():
    token = request.args.get('token')
    old_password = request.args.get('old_password')
    new_password = request.args.get('new_password')

    if not token or not old_password or not new_password:
        return jsonify({"error": "token, old_password, and new_password are required"}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or expired token."}), 401

    user_doc = users_collection.find_one({"username": username})
    if not user_doc:
        return jsonify({"error": "User not found."}), 404

    stored_hash = user_doc["password"].encode('utf-8')
    if not bcrypt.checkpw(old_password.encode('utf-8'), stored_hash):
        return jsonify({"error": "Old password is incorrect."}), 403

    hashed_new = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    users_collection.update_one(
        {"username": username},
        {"$set": {"password": hashed_new.decode('utf-8')}}
    )
    logger.info(f"Password changed for user '{username}'.")
    return jsonify({"message": "Password changed successfully."}), 200


@app.route('/internal_set_profile_picture', methods=['POST'])
def internal_set_profile_picture():
    data = request.get_json() or {}
    token = data.get('token')
    image_data = data.get('image_data')
    extension = data.get('extension')

    if not token or not image_data or not extension:
        return jsonify({"error": "token, image_data, and extension are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or expired token."}), 401

    try:
        extension = extension.lower()
        if extension not in ALLOWED_EXTENSIONS:
            return jsonify({"error": f"Unsupported extension: {extension}"}), 400

        profile_dir = "profile_pictures"
        os.makedirs(profile_dir, exist_ok=True)

        old_pictures = glob.glob(os.path.join(profile_dir, f"{username}.*"))
        for old_pic in old_pictures:
            if old_pic.split('.')[-1].lower() in ALLOWED_EXTENSIONS:
                os.remove(old_pic)
                logger.info(f"Deleted old profile picture: {old_pic}")

        base64_clean = image_data.strip().replace('\n', '').replace('\r', '')
        missing_padding = 4 - (len(base64_clean) % 4)
        if missing_padding < 4:
            base64_clean += "=" * missing_padding

        img_bytes = base64.b64decode(base64_clean)
        filename = f"{username}.{extension}"
        file_path = os.path.join(profile_dir, filename)
        with open(file_path, "wb") as f:
            f.write(img_bytes)

        image_url = f"{get_server_url()}/profile_pictures/{filename}"
        users_collection.update_one({"username": username}, {"$set": {"profile_picture_url": image_url}})
        logger.info(f"Profile picture updated for user '{username}'.")
        return jsonify({"message": "Profile picture updated successfully.", "image_url": image_url}), 200

    except Exception as e:
        logger.error(f"Error updating profile picture for user '{username}': {str(e)}")
        return jsonify({"error": "Failed to update profile picture."}), 500


@app.route('/internal_toggle_block_user', methods=['POST'])
def internal_toggle_block_user():
    if request.content_type == "application/json":
        data = request.json
    else:
        data = request.form

    token = data.get("token")
    other_user = data.get("other_user")

    if not token or not other_user:
        return jsonify({"error": "Token and other_user are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    if username == other_user:
        return jsonify({"error": "You cannot block yourself."}), 400

    user_doc = users_collection.find_one({"username": username})

    if not user_doc:
        return jsonify({"error": "User not found."}), 400

    blocked_users = user_doc.get("blocked_users", [])

    if other_user in blocked_users:
        users_collection.update_one({"username": username}, {"$pull": {"blocked_users": other_user}})
        return jsonify({"message": f"You have unblocked {other_user}."})
    else:
        users_collection.update_one({"username": username}, {"$addToSet": {"blocked_users": other_user}})
        return jsonify({"message": f"You have blocked {other_user}."})


@app.route("/internal_delete_chat", methods=["POST"])
def internal_delete_chat():
    data = request.json or {}
    token = data.get("token")
    other_user = data.get("other_user")

    if not token or not other_user:
        return jsonify({"error": "Missing required parameters."}), 400

    sender = validate_token(token)
    if not sender:
        return jsonify({"error": "Invalid or missing token."}), 401

    try:
        messages_collection.delete_many({
            "$or": [
                {"sender": sender, "receiver": other_user},
                {"sender": other_user, "receiver": sender}
            ]
        })
        return jsonify({"message": "Chat deleted successfully."}), 200
    except Exception as e:
        current_app.logger.error(f"Error in internal_delete_chat: {str(e)}")
        return jsonify({"error": "Failed to delete chat."}), 500
    

@app.route('/register_via_erlang', methods=['POST'])
def register_via_erlang():
    node_name = request.form.get('reg_nodeName')
    username = request.form.get('reg_username')
    password = request.form.get('reg_password')
    profile_pic = request.files.get('reg_profile_pic')

    reg_result = call_erlang_function(
        node_name=node_name,
        function='register_user',
        args=[username, password]
    )

    if "ReturnVal: {ok," in reg_result['stdout']:
        login_result = call_erlang_function(
            node_name=node_name,
            function='login_user',
            args=[username, password]
        )
        if "ReturnVal: {ok," in login_result['stdout']:
            token = extract_token_from_stdout(login_result['stdout'])
            if token:
                session['username'] = username
                session['token'] = token
                session['node_name'] = node_name

                if profile_pic and profile_pic.filename != '':
                    try:
                        file_bytes = profile_pic.read()
                        base64_data = base64.b64encode(file_bytes).decode('utf-8')
                        _, file_extension = os.path.splitext(profile_pic.filename)
                        file_extension = file_extension.lower().lstrip('.')
                        payload = {
                            "node_name": node_name,
                            "token": token,
                            "image_data": base64_data,
                            "extension": file_extension
                        }
                        # Use the dynamic URL here
                        pic_url = get_server_url() + "/set_profile_picture_via_erlang"
                        resp = requests.post(pic_url, data=payload)
                        if resp.status_code == 200:
                            flash("Registration and profile picture upload successful!", "success")
                        else:
                            error_msg = resp.json().get("error", "Failed to set profile picture.")
                            flash(f"Registration succeeded, but picture upload failed: {error_msg}", "error")
                    except Exception as e:
                        flash(f"Registration ok, but error uploading profile picture: {str(e)}", "error")
                        return render_template("index.html", is_logged_in=False)
                else:
                    flash("Registration successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Registration was successful, but we couldn’t retrieve token from login.", "error")
                return render_template("index.html", is_logged_in=False)
        else:
            flash("Registration succeeded, but login failed in Erlang.", "error")
            return render_template("index.html", is_logged_in=False)
    elif "ReturnVal: {error," in reg_result['stdout']:
        error_message = extract_error_from_stdout(reg_result['stdout'])
        flash(f"Registration Failed: {error_message}", "error")
        return render_template("index.html", is_logged_in=False)
    else:
        flash("Registration command finished with an unknown outcome.", "error")
        return render_template("index.html", is_logged_in=False)


def extract_error_from_stdout(stdout_str):
    pattern1 = r'\{error,\s*"(.+?)"\}'
    match1 = re.search(pattern1, stdout_str)
    if match1:
        return match1.group(1)

    pattern2 = r'\{error,\s*<<\"(.+?)\">>\}'
    match2 = re.search(pattern2, stdout_str)
    if match2:
        return match2.group(1)

    pattern3 = r'\{error,\s*([a-zA-Z0-9_]+)\}'
    match3 = re.search(pattern3, stdout_str)
    if match3:
        return match3.group(1).replace('_', ' ').capitalize()

    pattern4 = r'\{error,\s*\{[a-zA-Z0-9_]+,\s*"(.+?)"\}\}'
    match4 = re.search(pattern4, stdout_str)
    if match4:
        return match4.group(1)

    return "Unknown error."


@app.route('/login_via_erlang', methods=['POST'])
def login_via_erlang():
    node_name = request.form.get('login_nodeName')
    username = request.form.get('login_username')
    password = request.form.get('login_password')

    if not node_name or not username or not password:
        flash("Erlang Node Name, Username, and Password are required for login.", "error")
        return redirect(url_for('index'))

    login_result = call_erlang_function(
        node_name=node_name,
        function='login_user',
        args=[username, password]
    )

    if "ReturnVal: {ok," in login_result['stdout']:
        token = extract_token_from_stdout(login_result['stdout'])
        if token:
            session['username'] = username
            session['token'] = token
            session['node_name'] = node_name
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Login succeeded, but failed to parse token from login.", "error")
            return redirect(url_for('index'))
    elif "ReturnVal: {error," in login_result['stdout']:
        error_message = extract_error_from_stdout(login_result['stdout'])
        flash(f"Login Failed: {error_message}", "error")
        return redirect(url_for('index'))
    else:
        flash("Login command finished with an unknown outcome.", "error")
        flash(f"Output: {login_result['stdout']}", "error")
        return redirect(url_for('index'))


@app.route('/logout_via_erlang')
def logout_via_erlang():
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


@app.route('/get_chat_partners_via_erlang', methods=['POST'])
def get_chat_partners_via_erlang():
    node_name = request.form.get('node_name')
    user_token = request.form.get('token')

    if not node_name:
        return jsonify({"error": "Erlang Node Name is required for get_chat_partners."}), 400
    if not user_token:
        return jsonify({"error": "User Token is required."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='get_chat_partners',
        args=[user_token]
    )

    stdout_str = result['stdout']
    if "ReturnVal: {ok," in stdout_str:
        partners = parse_erlang_ok_list(stdout_str)
        return jsonify({"chat_partners": partners}), 200
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unknown result: {stdout_str}"}), 400


@app.route('/get_user_groups_via_erlang', methods=['POST'])
def get_user_groups_via_erlang():
    node_name = request.form.get('node_name')
    user_token = request.form.get('token')

    if not node_name:
        return jsonify({"error": "Erlang Node Name is required for get_user_groups."}), 400
    if not user_token:
        return jsonify({"error": "User Token is required."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='get_user_groups',
        args=[user_token]
    )

    stdout_str = result['stdout']
    if "ReturnVal: {ok," in stdout_str:
        groups = parse_erlang_ok_list(stdout_str)
        return jsonify({"group_names": groups}), 200
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unknown result: {stdout_str}"}), 400


@app.route('/get_unread_counts_via_erlang', methods=['POST'])
def get_unread_counts_via_erlang():
    node_name = request.form.get('node_name')
    user_token = request.form.get('token')

    if not node_name:
        return jsonify({"error": "Erlang Node Name is required for get_unread_counts."}), 400
    if not user_token:
        return jsonify({"error": "User Token is required."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='get_unread_counts',
        args=[user_token]
    )

    stdout_str = result['stdout']
    if "ReturnVal: {ok," in stdout_str:
        pattern = r'\{ok,\s*\#\{(.*?)\},\s*\#\{(.*?)\}\}'
        match = re.search(pattern, stdout_str, re.DOTALL)
        if match:
            raw_private = match.group(1).strip()
            raw_group = match.group(2).strip()

            private_unread = parse_erlang_map(raw_private)
            group_unread = parse_erlang_map(raw_group)

            return jsonify({"private_unread": private_unread, "group_unread": group_unread}), 200
        else:
            logger.error(f"Failed to parse Erlang stdout for unread counts: {stdout_str}")
            return jsonify({"error": "Failed to parse unread counts from Erlang response."}), 500

    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unknown result: {stdout_str}"}), 400
    

@app.route('/search_users_via_erlang', methods=['POST'])
def search_users_via_erlang():
    node_name = request.form.get('node_name')
    user_token = request.form.get('token')
    query = request.form.get('query', '').strip()

    if not node_name:
        return jsonify({"error": "Erlang Node Name is required for search_users."}), 400
    if not user_token:
        return jsonify({"error": "User Token is required."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='search_users',
        args=[user_token, query]
    )

    stdout_str = result['stdout']

    if "ReturnVal: {ok," in stdout_str:
        matched = parse_erlang_ok_list(stdout_str)
        return jsonify({"users": matched}), 200

    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unknown result: {stdout_str}"}), 400


@app.route('/add_user_to_group_via_erlang', methods=['POST'])
def add_user_to_group_via_erlang():
    data = request.json or {}
    node_name = data.get("node_name")
    user_token = data.get("token")
    group_name = data.get("group_name")
    username_to_add = data.get("username")

    if not node_name or not user_token or not group_name or not username_to_add:
        return jsonify({"error": "Missing required parameters."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='add_user_to_group',
        args=[user_token, group_name, username_to_add]
    )

    stdout_str = result['stdout']
    if "ReturnVal: {ok," in stdout_str:
        message = parse_erlang_ok_message(stdout_str)
        return jsonify({"message": message}), 200
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500


@app.route('/remove_user_from_group_via_erlang', methods=['POST'])
def remove_user_from_group_via_erlang():
    data = request.json or {}
    node_name = data.get("node_name")
    user_token = data.get("token")
    group_name = data.get("group_name")
    username_to_remove = data.get("username")

    if not node_name or not user_token or not group_name or not username_to_remove:
        return jsonify({"error": "Missing required parameters."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='remove_user_from_group',
        args=[user_token, group_name, username_to_remove]
    )

    stdout_str = result['stdout']
    if "ReturnVal: {ok," in stdout_str:
        message = parse_erlang_ok_message(stdout_str)
        return jsonify({"message": message}), 200
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500


def parse_erlang_map(map_str):
    result = {}
    items = re.findall(r'<<\"(.*?)\">>\s*=>\s*(\d+)', map_str)
    for key, value in items:
        try:
            result[key] = int(value)
        except ValueError:
            result[key] = 0
    return result


@app.route('/change_password_via_erlang', methods=['POST'])
def change_password_via_erlang():
    node_name = request.form.get('node_name')
    user_token = request.form.get('token')
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')

    if not node_name:
        return jsonify({"error": "Erlang Node Name is required for change_password."}), 400
    if not user_token or not old_password or not new_password:
        return jsonify({"error": "Token, old_password, and new_password are required."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='change_user_password',
        args=[user_token, old_password, new_password]
    )
    stdout_str = result['stdout']

    if "ReturnVal: {ok," in stdout_str:
        return jsonify({"message": "Password changed successfully via Erlang."}), 200

    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unknown result: {stdout_str}"}), 400


@app.route('/set_profile_picture_via_erlang', methods=['POST'])
def set_profile_picture_via_erlang():
    node_name = request.form.get('node_name')
    user_token = request.form.get('token')
    image_data = request.form.get('image_data')
    extension  = request.form.get('extension')

    if not node_name:
        return jsonify({"error": "Erlang Node Name is required for set_profile_picture."}), 400
    if not user_token or not image_data or not extension:
        return jsonify({"error": "Token, image_data, and extension are required."}), 400

    try:
        # Save image_data to a temporary file as text
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.' + extension) as temp_file:
            temp_file.write(image_data)
            temp_file_path = temp_file.name.replace("\\", "/")

        result = call_erlang_function(
            node_name=node_name,
            function='set_profile_picture',
            args=[user_token, temp_file_path, extension]
        )

        # Clean up the temporary file
        os.unlink(temp_file_path)

        stdout_str = result['stdout']
        if "ReturnVal: {ok," in stdout_str:
            return jsonify({"message": "Profile picture changed successfully via Erlang."}), 200
        elif "ReturnVal: {error," in stdout_str:
            error_message = extract_error_from_stdout(stdout_str)
            return jsonify({"error": error_message}), 400
        else:
            return jsonify({"error": f"Unknown result: {stdout_str}"}), 400

    except Exception as e:
        logger.error(f"Error handling profile picture upload via Erlang: {str(e)}")
        return jsonify({"error": "Failed to process image data."}), 500


@app.route('/get_profile_picture_via_erlang', methods=['POST'])
def get_profile_picture_via_erlang():
    try:
        data = request.json
        node_name = data.get("node_name")
        user_token = data.get("token")
        username = data.get("username")

        if not node_name or not user_token or not username:
            return jsonify({"error": "Missing required parameters."}), 400

        args = [user_token, username]
        result = call_erlang_function(node_name=node_name, function="get_profile_picture", args=args)

        stdout_str = result.get("stdout", "").strip()

        if not stdout_str:
            return jsonify({"error": "Empty response from Erlang."}), 500

        parsed_response = parse_erlang_ok_message(stdout_str)

        if isinstance(parsed_response, dict):
            profile_picture = parsed_response.get("profile_picture")
        elif isinstance(parsed_response, str):
            profile_picture = parsed_response
        else:
            return jsonify({"error": "Invalid response format from Erlang."}), 500

        if not profile_picture or profile_picture.endswith("default_profile.png"):
            return jsonify({"profile_picture": "/profile_pictures/default_profile.png"}), 200

        return jsonify({"profile_picture": profile_picture}), 200

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500


@app.route('/create_group_via_erlang', methods=['POST'])
def create_group_via_erlang():
    node_name = request.form.get('node_name')
    user_token = request.form.get('token')
    group_name = request.form.get('group_name', '').strip()
    members = request.form.get('members', '[]').strip()

    if not node_name:
        return jsonify({"error": "Erlang Node Name is required for create_group."}), 400
    if not user_token or not group_name:
        return jsonify({"error": "Token and group_name are required."}), 400

    try:
        members_list = json.loads(members)
        if not isinstance(members_list, list):
            raise ValueError
    except:
        return jsonify({"error": "Invalid members format. Expected a JSON list."}), 400

    args = [user_token, group_name, members_list]

    result = call_erlang_function(
        node_name=node_name,
        function='create_group',
        args=args
    )

    stdout_str = result['stdout']
    if "ReturnVal: {ok," in stdout_str:
        message = parse_erlang_ok_message(stdout_str)
        if message:
            return jsonify({"message": message}), 201
        else:
            return jsonify({"error": "Failed to parse success message from Erlang."}), 500

    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unknown result: {stdout_str}"}), 400


@app.route("/delete_group_via_erlang", methods=["POST"])
def delete_group_via_erlang():
    data = request.json or {}
    node_name = data.get("node_name")
    user_token = data.get("token")
    group_name = data.get("group_name")

    if not node_name or not user_token or not group_name:
        return jsonify({"error": "Missing required parameters."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function="delete_group",
        args=[user_token, group_name]
    )
    stdout_str = result["stdout"]

    if "ReturnVal: {ok," in stdout_str:
        message = parse_erlang_ok_message(stdout_str) 
        if isinstance(message, str):
            return jsonify({"message": message}), 200
        else:
            return jsonify({"message": "Group deleted successfully."}), 200

    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400

    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500


@app.route("/delete_chat_via_erlang", methods=["POST"])
def delete_chat_via_erlang():
    data = request.json or {}
    node_name = data.get("node_name")
    user_token = data.get("token")
    other_user = data.get("other_user")

    if not node_name or not user_token or not other_user:
        return jsonify({"error": "Missing required parameters."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function="delete_chat",
        args=[user_token, other_user]
    )

    stdout_str = result["stdout"]

    if "ReturnVal: {ok," in stdout_str:
        message = parse_erlang_ok_message(stdout_str)
        if isinstance(message, str):
            return jsonify({"message": message}), 200
        else:
            return jsonify({"message": "Chat deleted successfully."}), 200
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500


@app.route('/toggle_block_user_via_erlang', methods=['POST'])
def toggle_block_user_via_erlang():
    data = request.get_json()
    node_name = data.get("node_name")
    user_token = data.get("token")
    other_user = data.get("other_user")

    if not node_name or not user_token or not other_user:
        return jsonify({"error": "Missing required parameters."}), 400

    args = [user_token, other_user]
    result = call_erlang_function(node_name=node_name, function="toggle_block_user", args=args)

    stdout_str = result["stdout"]
    if "ReturnVal: {ok," in stdout_str:
        message = parse_erlang_ok_message(stdout_str)
        return jsonify({"message": message}), 200
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500


@app.route('/get_user_status_via_erlang', methods=['POST'])
def get_user_status_via_erlang():
    try:
        data = request.get_json()

        node_name = data.get("node_name")
        user_token = data.get("token")
        username = data.get("username")

        if not node_name or not user_token or not username:
            print("ERROR: Missing required parameters.")
            return jsonify({"error": "Missing required parameters."}), 400

        args = [user_token, username]  
        result = call_erlang_function(node_name=node_name, function="get_user_status", args=args)

        stdout_str = result.get("stdout", "")

        if not stdout_str.strip():
            return jsonify({"error": "Empty response from Erlang."}), 500

        parsed_response = parse_erlang_ok_message(stdout_str)

        if isinstance(parsed_response, dict):
            return jsonify(parsed_response), 200
        elif isinstance(parsed_response, str):
            return jsonify({"message": parsed_response}), 200
        else:
            return jsonify({"error": "Invalid response format from Erlang."}), 500

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500


@app.route("/send_message_via_erlang", methods=["POST"])
def send_message_via_erlang():
    data = request.json or {}
    node_name = data.get("node_name")
    user_token = data.get("token")
    receiver = data.get("receiver")
    msg_text = data.get("message", "")
    reply_id = data.get("reply_to_msg_id", "")
    reply_preview = data.get("reply_preview", "")

    if not node_name or not user_token or not receiver or not msg_text:
        return jsonify({"error": "Missing required parameters."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='send_message',
        args=[user_token, receiver, msg_text, reply_id, reply_preview]
    )

    stdout_str = result['stdout']
    if "ReturnVal: {ok," in stdout_str:
        message = parse_erlang_ok_message(stdout_str)
        return jsonify({"message": message}), 201
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500



@app.route('/get_messages_via_erlang', methods=['POST'])
def get_messages_via_erlang():
    try:
        data = request.get_json()

        node_name = data.get("node_name")
        user_token = data.get("token")
        other_user = data.get("other_user")

        if not node_name or not user_token or not other_user:
            return jsonify({"error": "Missing required parameters."}), 400

        args = [user_token, other_user]
        result = call_erlang_function(node_name=node_name, function="get_messages", args=args)

        stdout_str = result.get("stdout", "")

        if not stdout_str.strip():
            return jsonify({"error": "Empty response from Erlang."}), 500

        parsed_response = parse_erlang_ok_message(stdout_str)

        if isinstance(parsed_response, dict):
            return jsonify(parsed_response), 200
        elif isinstance(parsed_response, str):
            return jsonify({"message": parsed_response}), 200
        else:
            return jsonify({"error": "Invalid response format from Erlang."}), 500

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500


@app.route('/check_block_status_via_erlang', methods=['POST'])
def check_block_status_via_erlang():
    try:
        data = request.json
        node_name = data.get("node_name")
        user_token = data.get("token")
        other_user = data.get("other_user")

        if not node_name or not user_token or not other_user:
            return jsonify({"error": "Missing required parameters."}), 400

        args = [user_token, other_user]
        result = call_erlang_function(node_name=node_name, function="check_block_status", args=args)

        stdout_str = result.get("stdout", "")

        if not stdout_str.strip():
            return jsonify({"error": "Empty response from Erlang."}), 500

        parsed_response = parse_erlang_ok_message(stdout_str)

        if isinstance(parsed_response, dict):
            return jsonify(parsed_response), 200
        elif isinstance(parsed_response, str):
            return jsonify({"message": parsed_response}), 200
        else:
            return jsonify({"error": "Invalid response format from Erlang."}), 500

    except Exception as e:
        print(f"ERROR: Exception in check_block_status_via_erlang: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/edit_message_via_erlang', methods=['POST'])
def edit_message_via_erlang():
    try:
        data = request.json
        node_name = data.get("node_name")
        user_token = data.get("token")
        message_id = data.get("message_id")
        new_text = data.get("new_text")

        if not node_name or not user_token or not message_id or not new_text:
            return jsonify({"error": "Missing required parameters."}), 400

        args = [user_token, message_id, new_text]
        result = call_erlang_function(node_name=node_name, function="edit_message", args=args)

        stdout_str = result.get("stdout", "")

        if not stdout_str.strip():
            return jsonify({"error": "Empty response from Erlang."}), 500

        parsed_response = parse_erlang_ok_message(stdout_str)

        if isinstance(parsed_response, dict):
            return jsonify(parsed_response), 200
        elif isinstance(parsed_response, str):
            return jsonify({"message": parsed_response}), 200
        else:
            return jsonify({"error": "Invalid response format from Erlang."}), 500

    except Exception as e:
        print(f"ERROR: Exception in edit_message_via_erlang: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/delete_message_via_erlang', methods=['POST'])
def delete_message_via_erlang():
    try:
        data = request.json
        node_name = data.get("node_name")
        user_token = data.get("token")
        message_id = data.get("message_id")

        if not node_name or not user_token or not message_id:
            return jsonify({"error": "Missing required parameters."}), 400

        args = [user_token, message_id]
        result = call_erlang_function(node_name=node_name, function="delete_message", args=args)

        stdout_str = result.get("stdout", "")

        if not stdout_str.strip():
            return jsonify({"error": "Empty response from Erlang."}), 500

        parsed_response = parse_erlang_ok_message(stdout_str)

        if isinstance(parsed_response, dict):
            return jsonify(parsed_response), 200
        elif isinstance(parsed_response, str):
            return jsonify({"message": parsed_response}), 200
        else:
            return jsonify({"error": "Invalid response format from Erlang."}), 500

    except Exception as e:
        print(f"ERROR: Exception in delete_message_via_erlang: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/edit_group_message_via_erlang", methods=["POST"])
def edit_group_message_via_erlang():
    data = request.get_json() or {}
    node_name = data.get("node_name")
    user_token = data.get("token")
    group_name = data.get("group_name")
    message_id = data.get("message_id")
    new_text = data.get("new_text")

    if not node_name or not user_token or not group_name or not message_id or not new_text:
        return jsonify({"error": "Missing required parameters."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='edit_group_message',
        args=[user_token, group_name, message_id, new_text]
    )
    stdout_str = result["stdout"]
    if "ReturnVal: {ok," in stdout_str:
        message = parse_erlang_ok_message(stdout_str)
        if isinstance(message, str):
            return jsonify({"message": message}), 200
        else:
            return jsonify({"message": "Group message edited."}), 200
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500


@app.route('/delete_group_message_via_erlang', methods=['POST'])
def delete_group_message_via_erlang():
    data = request.json or {}
    node_name = data.get("node_name")
    user_token = data.get("token")
    group_name = data.get("group_name")
    message_id = data.get("message_id")

    if not node_name or not user_token or not group_name or not message_id:
        return jsonify({"error": "Missing required parameters."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='delete_group_message',
        args=[user_token, group_name, message_id]
    )

    stdout_str = result['stdout']
    if "ReturnVal: {ok," in stdout_str:
        message = parse_erlang_ok_message(stdout_str)
        return jsonify({"message": message}), 200
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500


@app.route('/get_group_members_via_erlang', methods=['GET'])
def get_group_members_via_erlang():
    node_name = request.args.get("node_name")
    user_token = request.args.get("token")
    group_name = request.args.get("group_name")

    if not node_name or not user_token or not group_name:
        return jsonify({"error": "Missing required query parameters."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='get_group_members',
        args=[user_token, group_name]
    )

    stdout_str = result["stdout"]
    if "ReturnVal: {ok," in stdout_str:
        parsed = parse_erlang_ok_message(stdout_str)  
        if isinstance(parsed, dict):
            return jsonify(parsed), 200
        else:
            return jsonify({"error": f"Invalid response format: {parsed}"}), 400

    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500


@app.route('/reassign_group_owner_and_remove_via_erlang', methods=['POST'])
def reassign_group_owner_and_remove_via_erlang():
    data = request.json or {}
    node_name = data.get("node_name")
    user_token = data.get("token")
    group_name = data.get("group_name")
    new_owner = data.get("new_owner")

    if not node_name or not user_token or not group_name or not new_owner:
        return jsonify({"error": "Missing required parameters."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='reassign_group_owner_and_remove',
        args=[user_token, group_name, new_owner]
    )

    stdout_str = result['stdout']
    if "ReturnVal: {ok," in stdout_str:
        message = parse_erlang_ok_message(stdout_str)
        return jsonify({"message": message}), 200
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500


@app.route('/get_group_messages_via_erlang', methods=['GET'])
def get_group_messages_via_erlang():
    node_name = request.args.get('node_name')
    user_token = request.args.get('token')
    group_name = request.args.get('group_name')

    if not node_name or not user_token or not group_name:
        return jsonify({"error": "Missing required parameters."}), 400

    result = call_erlang_function(
        node_name=node_name,
        function='get_group_messages',
        args=[user_token, group_name]
    )

    stdout_str = result['stdout']
    if "ReturnVal: {ok," in stdout_str:
        parsed = parse_erlang_ok_message(stdout_str) 
        if isinstance(parsed, list):
            return jsonify({"group_messages": parsed}), 200
        else:
            return jsonify({"error": f"Expected a list of messages, got: {parsed}"}), 400
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500

    

@app.route('/send_group_message_via_erlang', methods=['POST'])
def send_group_message_via_erlang():
    data = request.json or {}
    node_name = data.get("node_name")
    user_token = data.get("token")
    group_name = data.get("group_name")
    msg_text = data.get("message")

    if not node_name or not user_token or not group_name or not msg_text:
        return jsonify({"error": "Missing required parameters."}), 400

    reply_id = data.get("reply_to_msg_id", "")
    reply_preview = data.get("reply_preview", "")

    result = call_erlang_function(
        node_name=node_name,
        function='send_group_message',
        args=[user_token, group_name, msg_text, reply_id, reply_preview]
    )

    stdout_str = result['stdout']
    if "ReturnVal: {ok," in stdout_str:
        message = parse_erlang_ok_message(stdout_str)
        return jsonify({"message": message}), 201
    elif "ReturnVal: {error," in stdout_str:
        error_message = extract_error_from_stdout(stdout_str)
        return jsonify({"error": error_message}), 400
    else:
        return jsonify({"error": f"Unexpected response: {stdout_str}"}), 500
    

def format_time_for_display(dt):
    if not dt:
        return "Never"
    now = datetime.datetime.utcnow()
    diff = now - dt
    if diff.total_seconds() < 24 * 3600:
        return dt.strftime("%H:%M")
    else:
        return dt.strftime("%d %b %Y, %H:%M")


@app.route("/chat/<string:other_user>")
def chat_user(other_user):
    token = session.get('token')
    username = session.get('username')
    node_name = session.get('node_name')
    if not token or not username:
        return redirect(url_for('index'))

    other_user_display_status = ""
    try:
        # Use dynamic URL here:
        url = get_server_url() + "/get_user_status_via_erlang"
        stat_resp = requests.post(url, json={"token": token, "node_name": node_name, "username": other_user})
        if stat_resp.status_code == 200:
            st_data = stat_resp.json()
            if st_data["status"] == "online":
                other_user_display_status = "online"
            else:
                last_s = st_data.get("last_online")
                dt = dateutil.parser.isoparse(last_s) if last_s else None
                formatted = format_time_for_display(dt)
                other_user_display_status = f"last seen {formatted}"
        else:
            other_user_display_status = "Status unavailable"
    except:
        other_user_display_status = "Status unavailable"

    return render_template("chat_user.html", username=username, node_name=node_name, other_user=other_user, other_user_status=other_user_display_status)


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

@app.route('/change_info', methods=['GET'])
def change_info():
    if "username" not in session or "token" not in session:
        flash("You need to be logged in to access this page.", "error")
        return redirect(url_for('index'))
    
    node_name = session.get('node_name')
    
    if not node_name:
        flash("Node name not found in session.", "error")
        return redirect(url_for('dashboard'))
    
    return render_template("change_info.html", node_name=node_name)
    

@app.route('/create_group_page', methods=['GET'])
def create_group_page():
    if "username" not in session or "token" not in session:
        flash("You need to be logged in to access this page.", "error")
        return redirect(url_for('index'))
    
    node_name = session.get('node_name')
    
    if not node_name:
        flash("Node name not found in session.", "error")
        return redirect(url_for('dashboard'))
    
    return render_template("create_group.html", node_name=node_name, token=session['token'], username=session['username'])


@app.route('/internal_check_block_status', methods=['POST'])
def internal_check_block_status():
    data = request.json
    token = data.get("token")
    other_user = data.get("other_user")

    if not token or not other_user:
        return jsonify({"error": "Token and other_user are required."}), 400

    username = validate_token(token)
    if not username:
        return jsonify({"error": "Invalid or missing token."}), 401

    me = users_collection.find_one({"username": username})
    them = users_collection.find_one({"username": other_user})

    if not me or not them:
        return jsonify({"error": "One of the users does not exist."}), 400

    we_blocked_them = other_user in me.get("blocked_users", [])
    they_blocked_us = username in them.get("blocked_users", [])

    return jsonify({"we_blocked_them": we_blocked_them, "they_blocked_us": they_blocked_us}), 200


def format_erlang_arg(arg):
    if isinstance(arg, list):
        return "[" + ", ".join([f'\\"{a}\\"' for a in arg]) + "]"
    else:
        escaped = arg.replace('"', '\\"')
        return f'\\"{escaped}\\"'

def call_erlang_function(node_name, function, args):
    full_node_name = normalize_node_name(node_name)
    erlang_args = ", ".join([format_erlang_arg(arg) for arg in args])
    
    # Set the directory where your beam files reside.
    current_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(current_dir, "backend")
    if not os.path.exists(backend_dir):
        backend_dir = current_dir

    command = (
        f'erl -noshell -sname bridge -setcookie mycookie '
        f'-pa "{backend_dir}" '
        f'-eval "net_kernel:connect_node(\'{full_node_name}\'), '
        f'ReturnVal = rpc:call(\'{full_node_name}\', node_manager, {function}, [{erlang_args}]), '
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

    pattern = r'\{ok,\s*("?<<)?\"?([^\"]+?)\"?(>>"?)?\}'

    match = re.search(pattern, stdout_str)
    if match:
        token = match.group(2)
        return token
    return None


def is_ip_address(hostname: str) -> bool:

    ipv4_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$"
    return bool(re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname))


def get_browser_short_name(user_agent: str, hostname: str) -> str:

    ua_lower = user_agent.lower()

    if "opr" in ua_lower or "opera" in ua_lower:
        return "opera"
    elif "chrome" in ua_lower and "safari" in ua_lower and "edg" not in ua_lower and "opr" not in ua_lower:
        return "chrome"
    elif "edg" in ua_lower:
        return "edge"
    elif "firefox" in ua_lower:
        return "firefox"
    elif "trident" in ua_lower or "msie" in ua_lower:
        return "ie"
    elif "safari" in ua_lower:
        return "safari"
    else:
        return "unknown"

if __name__ == "__main__":
    app.run(port=5000, debug=True)