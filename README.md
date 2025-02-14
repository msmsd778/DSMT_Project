# D-Messenger: A Distributed Erlang-based Messenger Application

D-Messenger is a distributed messaging application designed to provide robust, real-time communication in a fault-tolerant and scalable environment. By combining a Python-based Flask backend with an Erlang node manager, D-Messenger achieves high availability and efficient message routing. The system supports both private and group messaging, and offers features such as message editing, deletion, read receipts, and comprehensive group management.

---

## Key Features

- **Real-Time Messaging:**  
  Supports private one-to-one and group messaging with real-time message delivery.

- **Group Management:**  
  Create, delete, and manage groups with features like adding/removing members and reassigning group ownership.

- **Message Management:**  
  Edit, delete, and reply to messages with real-time read receipts and "last seen" indicators.

- **User Management:**  
  Secure user registration, authentication, and profile management using token-based sessions.

- **Distributed Architecture:**  
  Combines Flask for API management and Erlang for distributed node management, ensuring scalability and fault tolerance.

- **Responsive Web Interface:**  
  A user-friendly interface built with HTML, CSS, and JavaScript using AJAX for asynchronous updates.

---

## System Architecture

D-Messenger follows a hybrid architectural model that leverages the strengths of both Flask and Erlang.

### Flask Web Server

- Handles user authentication and provides RESTful API endpoints.
- Manages session handling and interacts with a MongoDB database to store user credentials, profiles, and chat history.
- Acts as a bridge to Erlang by invoking distributed functions via RPC calls.

### Erlang Node Manager

- Manages distributed nodes and ensures efficient message routing.
- Uses Erlang’s lightweight processes and ETS (Erlang Term Storage) for fast, in-memory data management.
- Coordinates actions such as sending messages, editing/deleting messages, and propagating status changes (like logout or block status) across nodes.
- Exposes functions (e.g., `send_message`, `edit_message`, etc.) that are called remotely via RPC.

### Database Layer

- **MongoDB** is used for persistent storage of user data, messages, groups, and session information.
- Ensures that even though messaging is handled in real-time via Erlang, critical data is stored persistently.

---

## Component Interactions

### 1. User Registration and Authentication

- **Registration:**  
  Users register through the web interface. The Flask backend validates credentials and stores them in MongoDB. A unique authentication token is issued upon successful registration.

- **Login:**  
  During login, Flask verifies the credentials, issues a session token, and calls the Erlang node manager to set up the session across the distributed network.

### 2. Message Sending and Delivery

- **Sending Messages:**  
  - The client uses AJAX to send message data (along with metadata like reply or block status) to the Flask API.
  - Flask forwards the message to the Erlang node manager via RPC.
  - Erlang routes the message to the intended recipient(s) in real time.
  - The message is also stored in MongoDB for persistence.

- **Receiving Messages:**  
  - The client periodically polls or receives pushed updates via AJAX.
  - The Flask server retrieves messages by calling Erlang functions (e.g., `/get_messages_via_erlang`), which return data from in-memory storage and persistent logs.

### 3. Group Management

- **Group Creation:**  
  Users can create groups and add members via the Flask interface. Group metadata is stored in MongoDB and propagated across Erlang nodes.
  
- **Group Messaging:**  
  Similar to private messages, group messages are routed through the Erlang node manager, ensuring that all group members receive real-time updates.

- **Group Administration:**  
  Operations such as reassigning group ownership, adding or removing members, and deleting groups are coordinated between Flask and Erlang to maintain consistency across nodes.

### 4. Frontend Interactions (AJAX)

- **Editing, Deleting, and Replying to Messages:**  
  JavaScript functions on the client side use the `fetch()` API to make asynchronous requests (AJAX) to Flask endpoints (e.g., `/edit_message_via_erlang`, `/delete_message_via_erlang`).
  
- **Toggling Block Status:**  
  Users can block or unblock contacts. The client sends AJAX requests to `/toggle_block_user_via_erlang` to update block status in the backend.

- **Real-Time Updates:**  
  The client continuously polls endpoints (such as `/get_messages_via_erlang` and `/check_block_status_via_erlang`) to refresh the chat interface with new messages, status updates, and profile picture changes.

---

## Deployment

D-Messenger is deployed on two virtual machines (VMs):

- **Primary Node:**  
  Hosts the MongoDB database, Flask application, and Erlang node manager.

- **Secondary Node:**  
  Runs the Flask application and Erlang node manager (without a local database).

### Deployment Steps

1. **Start the Flask Application:**

   ```bash
   python3 app.py
   ```
The Flask app listens on port 5000 and can be accessed via the VM's IP address (e.g., 10.2.1.37:5000).

2. **Start the Erlang Node:**

Open a terminal and run:

  ```bash
  erl -sname edge -setcookie mycookie
```

This initializes the Erlang node. The node manager (defined in node_manager.erl) will be started and will set up ETS tables and node registration.

3. **Inter-Node Communication:**

-Erlang nodes communicate via RPC calls to ensure synchronization and shared session information.
-The Flask helper function call_erlang_function/3 constructs and executes commands that remotely invoke Erlang functions.

## Future Enhancements

- **Scalability & Performance:**
  - Integrate container orchestration (e.g., Kubernetes) for automated scaling.
  - Add a caching layer (e.g., Redis) to speed up frequent data access.

- **Feature Expansion:**
  - Support multimedia messaging (images, videos, audio).
  - Enable file sharing, voice, and video chat.

- **Security Improvements:**
  - Implement end-to-end encryption for messages.
  - Conduct regular security audits and penetration tests.

- **Cross-Platform Support:**
  - Develop native mobile applications using React Native or Flutter.
  - Integrate third-party APIs to enhance functionality.

