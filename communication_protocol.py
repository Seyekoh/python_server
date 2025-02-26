"""
communication_protocol.py
Simple HTTP-based communication server.

Author: James Bridges
Date: 25-Feb-25
Description:
    This module implements a simple HTTP server using Python's http.server.
    It provides endpoints for user authentication, board creation, topic handling, 
    and message management with authentication via tokens.

Usage:
    Run this script to start the server:
        python communication_protocol.py
    The server listens on port 8000 and handles JSON-based requests.
"""
import http.server
import json
import socketserver
import uuid
import time

PORT = 8000

# Data storage
users = {}
auth_tokens = {}
boards = {}
topics = {}
messages = {}

TOKEN_EXPIRATION_TIME = 300  # 5 minutes

def generate_auth_token():
    """
    Generates a new authentication token.

    Returns:
        str: A UUID-based authentication token.
    """
    return str(uuid.uuid4())

def is_token_valid(token):
    """
    Checks if an authentication token is valid and not expired.

    Args:
        token (str): The authentication token to check.

    Returns:
        bool: True if valid
        str: "auth expired" if expired, or "fail" if invalid
    """
    if token in auth_tokens:
        created_time = auth_tokens[token]['timestamp']
        if time.time() - created_time <= TOKEN_EXPIRATION_TIME:
            return True
        del auth_tokens[token]  # Expire token
        return "auth expired"
    return "fail"

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Handles HTTP POST requests for user authentication, board management, topic handling, and message processing.

    Supported Request Types:
        -create accoune
        -login
        -get boards
        -get topics
        -get messages
        -create board
        -create topic
        -create message
        -delete message
        -logout
    """
    def do_POST(self):
        """
        Handles incoming HTTP POST requests by parsing JSON data and processing various reuest types.
        """
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))
        request_type = data.get('type')

        response = {"success code": "fail", "error description": "Unknown request type."}

        if request_type == "create account":
            username = data.get('username')
            password = data.get('password')
            if username in users:
                response = {"success code": "fail", "error description": "Username already exists."}
            else:
                users[username] = password
                auth_token = generate_auth_token()
                auth_tokens[auth_token] = {'username': username, 'timestamp': time.time()}
                response = {"success code": "success", "auth token": auth_token}

        elif request_type == "login":
            username = data.get('username')
            password = data.get('password')
            if username in users and users[username] == password:
                auth_token = generate_auth_token()
                auth_tokens[auth_token] = {'username': username, 'timestamp': time.time()}
                response = {"success code": "success", "auth token": auth_token}
            else:
                response = {"success code": "fail", "error description": "Invalid credentials."}

        elif request_type == "get boards":
            token = data.get('auth token')
            token_status = is_token_valid(token)
            if token_status is True:
                response = {"success code": "success", "boards": list(boards.keys())}
            elif token_status == "auth expired":
                response = {"success code": token_status, "error description": token_status}
            else:
                response = {"success code": token_status, "error description": "Authentication issue."}

        elif request_type == "get topics":
            board_id = data.get('board')
            token = data.get('auth token')
            token_status = is_token_valid(token)
            if token_status is True and board_id in topics:
                response = {"success code": "success", "topics": topics[board_id]}
            elif token_status == "auth expired":
                response = {"success code": token_status, "error description": token_status}
            else:
                response = {"success code": token_status, "error description": "Authentication issue."}

        elif request_type == "get messages":
            topic_id = data.get('topic')
            token = data.get('auth token')
            token_status = is_token_valid(token)
            if token_status is True and topic_id in messages:
                response = {"success code": "success", "messages": messages[topic_id]}
            elif token_status == "auth expired":
                response = {"success code": token_status, "error description": token_status}
            else:
                response = {"success code": token_status, "error description": "Authentication issue."}

        elif request_type == "create board":
            token = data.get('auth token')
            board_name = data.get('board')
            token_status = is_token_valid(token)
            if token_status is True:
                board_id = str(uuid.uuid4())
                boards[board_id] = board_name
                topics[board_id] = []
                response = {"success code": "success", "board id": board_id}
            elif token_status == "auth expired":
                response = {"success code": token_status, "error description": token_status}
            else:
                response = {"success code": token_status, "error description": "Authentication issue."}

        elif request_type == "create topic":
            topic_name = data.get('topic')
            board_id = data.get('board_id')
            token = data.get('auth token')
            token_status = is_token_valid(token)
            if token_status is True:
                topic_id = str(uuid.uuid4())
                
                if board_id not in topics:
                    topics[board_id] = []

                topics[board_id].append(topic_name)
                messages[topic_id] = []
                response = {"success code": "success", "topic id": topic_id}
            elif token_status == "auth expired":
                response = {"success code": token_status, "error description": token_status}
            else:
                response = {"success code": token_status, "error description": "Authentication issue."}

        elif request_type == "create message":
            message_text = data.get('text')
            topic_id = data.get('topic_id')
            token = data.get('auth token')
            token_status = is_token_valid(token)
            if token_status is True and topic_id in messages:
                message_id = str(uuid.uuid4())
                messages[topic_id].append({"id": message_id, "text": message_text})
                response = {"success code": "success", "message id": message_id}
            elif token_status == "auth expired":
                response = {"success code": token_status, "error description": token_status}
            else:
                response = {"success code": token_status, "error description": "Authentication issue."}

        elif request_type == "delete message":
            message_id = data.get('message id')
            token = data.get('auth token')
            token_status = is_token_valid(token)
            if token_status is True:
                for topic in messages:
                    messages[topic] = [m for m in messages[topic] if m['id'] != message_id]
                response = {"success code": "success"}
            elif token_status == "auth expired":
                response = {"success code": token_status, "error description": token_status}
            else:
                response = {"success code": token_status, "error description": "Authentication issue."}

        elif request_type == "logout":
            token = data.get('auth token')
            token_status = is_token_valid(token)
            if token_status is True:
                if token in auth_tokens:
                    del auth_tokens[token]
                    response = {"success code": "success"}
            elif token_status == "auth expired":
                response = {"success code": token_status, "error description": token_status}
            else:
                response = {"success code": token_status, "error description": "Authentication issue."}

        else:
            raise ValueError("Invalid request type.")

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('utf-8'))

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), RequestHandler) as httpd:
        print(f"Serving at port {PORT}")
        httpd.serve_forever()
