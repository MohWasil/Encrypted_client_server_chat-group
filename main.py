# # socket
import socket
import threading

# Server configuration
host = socket.gethostbyname(socket.gethostname())
port = 12345

# List to store connected clients
clients = []

# Flag to signal server termination
server_terminate = False


# Function to handle a client's messages
def handle_client(client_socket):
    global server_terminate
    while True:
        try:
            message = client_socket.recv(120000)
            if not message:
                break

            print(message)

            # Relay the message to all connected clients
            for client in clients:
                if client != client_socket:
                    client.send(message)
        except:
            continue

    # Remove the client from the list and close the socket
    clients.remove(client_socket)
    client_socket.close()


# Create a server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen(5)

print(f"Server listening on {host}:{port}")

# Accept and handle client connections
while not server_terminate:
    client_socket, addr = server.accept()
    clients.append(client_socket)
    print(f"Accepted connection from {addr}")
    client_handler = threading.Thread(target=handle_client, args=(client_socket,))
    client_handler.start()

# Close the server socket when done
server.close()

