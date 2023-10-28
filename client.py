import socket
import threading


class ChatClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect()
        self.messages = []

        # Start a separate thread to continuously receive messages
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    def connect(self):
        self.socket.connect((self.host, self.port))

    def send(self, message):
        self.socket.send(message)

    def receive_messages(self):
        while True:
            try:
                message = self.socket.recv(120000)
                # Process the received message (e.g., display it in the chat interface)
                self.messages.append(message)
                # print("Received:", message)
            except ConnectionResetError:
                print("Connection closed by the server.")
                break

    def close(self):
        self.socket.close()
