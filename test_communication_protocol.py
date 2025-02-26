"""
test_communication_protocol.py
Unit tests for communication_protocol.py

Author: James Bridges
Date: 25-Feb-25
Description:
    This module contains unit tests for the communication_protocol.py file.
    It tests user authentication, board creation, messaging, and logout functionality.

Usage:
    Run with unittest:
        python -m unittest discover -s . -p "test_communication_protocol.py"
"""
import unittest
import json
import time
import uuid
from communication_protocol import RequestHandler, generate_auth_token, is_token_valid, users, auth_tokens, boards, topics, messages
from http.server import HTTPServer
from io import BytesIO

class MockRequestHandler(RequestHandler):
    """
    Mock request handler to simulate HTTP POST requests to the server.

    This class overrides RequestHandler to allow testing of POST request handling
    without needing an actual HTTP server.

    Attributes:
        rfile (BytesIO): Simulated request input stream.
        wfile (BytesIO): Simulated response output stream.
        headers (dict): Simulated request headers.
    """
    def __init__(self, request, client_address, server):
        """
        Initializes the mock request handler with a simulated request.

        Args:
            request (bytes): JSON-encoded request data.
            client_address (tuple): The client's IP address and port.
            server (HTTPServer): The HTTP server instance.
        """
        self.rfile = BytesIO(request)
        self.rfile.seek(0)
        self.headers = {'Content-Length': str(len(request))}
        self.wfile = BytesIO()
        self.client_address = client_address
        self.server = server
        self.requestline = ""
        self.request_version = "HTTP/1.1"
        self.command = "POST"
        self.do_POST()
        self.wfile.seek(0)

    def get_response(self):
        """
        Reads and parses the JSON response from the mock HTTP request.

        Returns:
            dict: The JSON-decoded resposne.

        Raises:
            ValueError: If the response is empty or invalid JSON.
        """
        response_data = self.wfile.read().decode('utf-8').strip()

        if not response_data:
            raise ValueError("Empty response from server.")
        
        json_start = response_data.index('{')
        return json.loads(response_data[json_start:])

class TestCommunicationProtocol(unittest.TestCase):
    """
    Unit tests for communication_protocol.py.

    Tests include:
        -User authentication (create account, login, logout)
        -Board creation
        -Message creation
        -Invalid login and token handling
    """
    
    def setUp(self):
        users.clear()
        auth_tokens.clear()
        boards.clear()
        topics.clear()
        messages.clear()

    def test_invalid_json_request(self):
        request = json.dumps({"type": "invalid request"}).encode('utf-8')
        with self.assertRaises(ValueError):
            handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)

    def test_create_account(self):
        request = json.dumps({"type": "create account", "username": "user1", "password": "pass"}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "success")
        self.assertIn(response["auth token"], auth_tokens)

    def test_create_account_duplicate(self):
        request = json.dumps({"type": "create account", "username": "user1", "password": "pass"}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        handler.get_response()
        request = json.dumps({"type": "create account", "username": "user1", "password": "pass"}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "fail")
        self.assertEqual(response["error description"], "Username already exists.")

    def test_login(self):
        request = json.dumps({"type": "create account", "username": "user1", "password": "pass"}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        handler.get_response()
        request = json.dumps({"type": "login", "username": "user1", "password": "pass"}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "success")
        self.assertIn(response["auth token"], auth_tokens)

    def test_login_invalid_credentials(self):
        request = json.dumps({"type": "create account", "username": "user1", "password": "pass"}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        handler.get_response()
        request = json.dumps({"type": "login", "username": "user1", "password": "wrongpass"}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "fail")
        self.assertEqual(response["error description"], "Invalid credentials.")

    def test_get_boards(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time()}
        request = json.dumps({"type": "get boards", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "success")
        self.assertIn("boards", response)

    def test_get_boards_expired_token(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time() - 10000}
        request = json.dumps({"type": "get boards", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "auth expired")
        self.assertEqual(response["error description"], "auth expired")

    def test_get_boards_other_issue(self):
        token = generate_auth_token()
        request = json.dumps({"type": "get boards", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "fail")
        self.assertEqual(response["error description"], "Authentication issue.")

    def test_get_topics(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time()}
        boards["board1"] = "Board 1"
        topics["board1"] = ["Topic 1", "Topic 2"]
        request = json.dumps({"type": "get topics", "board": "board1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "success")
        self.assertIn("topics", response)

    def test_get_topics_expired_token(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time() - 10000}
        request = json.dumps({"type": "get topics", "board": "board1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "auth expired")
        self.assertEqual(response["error description"], "auth expired")

    def test_get_topics_other_issue(self):
        token = generate_auth_token()
        request = json.dumps({"type": "get topics", "board": "board1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "fail")
        self.assertEqual(response["error description"], "Authentication issue.")

    def test_get_messages(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time()}
        boards["board1"] = "Board 1"
        topics["board1"] = ["Topic 1"]
        messages["Topic 1"] = ["Message 1", "Message 2"]
        request = json.dumps({"type": "get messages", "topic": "Topic 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "success")
        self.assertIn("messages", response)

    def test_get_messages_expired_token(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time() - 10000}
        request = json.dumps({"type": "get messages", "topic": "Topic 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "auth expired")
        self.assertEqual(response["error description"], "auth expired")

    def test_get_messages_other_issue(self):
        token = generate_auth_token()
        request = json.dumps({"type": "get messages", "topic": "Topic 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "fail")
        self.assertEqual(response["error description"], "Authentication issue.")

    def test_create_board(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time()}
        request = json.dumps({"type": "create board", "board": "Board 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "success")
        self.assertIn("Board 1", boards.values())

    def test_create_board_expired_token(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time() - 10000}
        request = json.dumps({"type": "create board", "board": "Board 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "auth expired")
        self.assertEqual(response["error description"], "auth expired")

    def test_create_board_other_issue(self):
        token = generate_auth_token()
        request = json.dumps({"type": "create board", "board": "Board 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "fail")
        self.assertEqual(response["error description"], "Authentication issue.")

    def test_create_topic(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time()}
        boards["board1"] = "Board 1"
        topics["board1"] = []
        request = json.dumps({"type": "create topic", "topic": "Topic 1", "board_id": "board1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "success")
        self.assertIn("Topic 1", topics["board1"])

    def test_create_topic_expired_token(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time() - 10000}
        request = json.dumps({"type": "create topic", "topic": "Topic 1", "board_id": "board1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "auth expired")
        self.assertEqual(response["error description"], "auth expired")

    def test_create_topic_other_issue(self):
        token = generate_auth_token()
        request = json.dumps({"type": "create topic", "topic": "Topic 1", "board_id": "board1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "fail")
        self.assertEqual(response["error description"], "Authentication issue.")

    def test_create_message(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time()}
        boards["board1"] = "Board 1"
        topics["board1"] = ["Topic 1"]
        messages["Topic 1"] = []
        request = json.dumps({"type": "create message", "text": "Message 1", "topic_id": "Topic 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "success")
        self.assertTrue(any(m["text"] == "Message 1" for m in messages["Topic 1"]))

    def test_create_message_expired_token(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time() - 10000}
        request = json.dumps({"type": "create message", "text": "Message 1", "topic_id": "Topic 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "auth expired")
        self.assertEqual(response["error description"], "auth expired")

    def test_create_message_other_issue(self):
        token = generate_auth_token()
        request = json.dumps({"type": "create message", "text": "Message 1", "topic_id": "Topic 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "fail")
        self.assertEqual(response["error description"], "Authentication issue.")

    def test_delete_message(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time()}
        boards["board1"] = "Board 1"
        topics["board1"] = ["Topic 1"]
        message_id = str(uuid.uuid4())
        messages["Topic 1"] = [{"id": message_id, "text": "Message 1"}]
        request = json.dumps({"type": "delete message", "message id": message_id, "topic_id": "Topic 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "success")
        self.assertFalse(any(m["text"] == "Message 1" for m in messages["Topic 1"]))

    def test_delete_message_expired_token(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time() - 10000}
        request = json.dumps({"type": "delete message", "message id": "invalid_id", "topic_id": "Topic 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "auth expired")
        self.assertEqual(response["error description"], "auth expired")

    def test_delete_message_other_issue(self):
        token = generate_auth_token()
        request = json.dumps({"type": "delete message", "message id": "invalid_id", "topic_id": "Topic 1", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "fail")
        self.assertEqual(response["error description"], "Authentication issue.")

    def test_logout(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time()}
        request = json.dumps({"type": "logout", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "success")
        self.assertNotIn(token, auth_tokens)

    def test_logout_expired_token(self):
        token = generate_auth_token()
        auth_tokens[token] = {'username': 'user1', 'password': 'pass', 'timestamp': time.time() - 10000}
        request = json.dumps({"type": "logout", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "auth expired")
        self.assertEqual(response["error description"], "auth expired")

    def test_logout_other_issue(self):
        token = generate_auth_token()
        request = json.dumps({"type": "logout", "auth token": token}).encode('utf-8')
        handler = MockRequestHandler(request, ('127.0.0.1', 8080), HTTPServer)
        response = handler.get_response()
        self.assertEqual(response["success code"], "fail")
        self.assertEqual(response["error description"], "Authentication issue.")



if __name__ == '__main__':
    unittest.main()
