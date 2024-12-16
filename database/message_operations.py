from pymongo import MongoClient
import datetime
import logging

def send_message(sender, receiver, message):
    client = MongoClient("mongodb://localhost:27017/")
    db = client["messenger_db"]
    messages_collection = db["messages"]
    try:
        messages_collection.insert_one({
            "sender": sender,
            "receiver": receiver,
            "message": message,
            "timestamp": datetime.datetime.utcnow()
        })
        logging.info("Message sent successfully.")
    except Exception as e:
        logging.info(f"Error sending message: {e}")
    client.close()

def retrieve_messages(receiver):
    client = MongoClient("mongodb://localhost:27017/")
    db = client["messenger_db"]
    messages_collection = db["messages"]
    try:
        messages = messages_collection.find({"receiver": receiver})
        logging.info("Messages for", receiver)
        for message in messages:
            logging.info(f"{message['timestamp']} - {message['sender']}: {message['message']}")
    except Exception as e:
        logging.info(f"Error retrieving messages: {e}")
    client.close()
