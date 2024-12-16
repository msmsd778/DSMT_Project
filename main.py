from database.user_operations import register_user, login_user
from database.message_operations import send_message, retrieve_messages

if __name__ == "__main__":
    # Register a new user
    register_user("user1", "password1")
    register_user("user2", "password2")
    
    # Login with a user
    if login_user("user1", "password1"):
        print("Logged in as user1.")
    
    # Send messages
    send_message("user1", "user2", "Hello, user2!")
    send_message("user2", "user1", "Hi, user1! How are you?")
    
    # Retrieve messages
    retrieve_messages("user2")
    retrieve_messages("user1")
