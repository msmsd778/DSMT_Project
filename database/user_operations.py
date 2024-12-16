from pymongo import MongoClient
import logging

def register_user(username, password):
    client = MongoClient("mongodb://localhost:27017/")
    db = client["messenger_db"]
    users_collection = db["users"]
    try:
        users_collection.insert_one({"username": username, "password": password})
        logging.info("User registered successfully.")
    except Exception as e:
        logging.info(f"Error registering user: {e}")
    client.close()

def login_user(username, password):
    client = MongoClient("mongodb://localhost:27017/")
    db = client["messenger_db"]
    users_collection = db["users"]
    try:
        user = users_collection.find_one({"username": username, "password": password})
        if user:
            logging.info("Login successful.")
            return True
        else:
            logging.info("Invalid username or password.")
            return False
    except Exception as e:
        logging.info(f"Error logging in: {e}")
    client.close()
