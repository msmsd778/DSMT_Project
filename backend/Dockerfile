# Use the official Erlang image as the base
FROM erlang:23

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy your Erlang project files into the container
COPY node_manager.erl /app/
RUN erlc node_manager.erl

# Expose necessary ports for node communication (e.g., 4369 and dynamic ports)
EXPOSE 4369
EXPOSE 8080-8085

# Set the default command to run your node_manager
CMD ["erl", "-name", "node@127.0.0.1", "-setcookie", "mycookie", "-s", "node_manager", "init"]
