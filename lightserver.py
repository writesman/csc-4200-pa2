import argparse
import logging
import socket
import struct
import sys

# --- Protocol Constants ---
PROTOCOL_VERSION = 17
PACKET_HEADER_FORMAT = (
    ">III"  # Big-endian (Network Byte Order), 3 Unsigned Integers (4 bytes each)
)
HEADER_SIZE = struct.calcsize(PACKET_HEADER_FORMAT)  # 12 bytes

# --- Message Type Constants (Deliverable 8) ---
MSG_TYPE_HELLO = 1
MSG_TYPE_COMMAND = 2

# --- Helper Function: Logging Setup ---


def setup_logging(log_file_path):
    """Sets up a logger that writes messages to both the console and the specified file."""
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file_path, mode="a"),  # Log file location
            logging.StreamHandler(sys.stdout),
        ],
    )


# --- Helper Function: Sending Reply ---


def send_reply(client_socket, version, msg_type, message_body):
    """Constructs and sends a packet back to the client (Deliverable 10)."""

    encoded_message = message_body.encode("ascii")
    message_length = len(encoded_message)

    # Pack the Header
    header = struct.pack(PACKET_HEADER_FORMAT, version, msg_type, message_length)

    # Send the full packet (Header + Message)
    try:
        client_socket.sendall(header + encoded_message)

    except socket.error as e:
        logging.error(f"Failed to send reply to client: {e}")


# --- Core Logic: Command Processing ---


def process_command(client_socket, version, msg_type, message):
    """Handles supported commands (Deliverable 8, 9, 10)."""

    if msg_type == MSG_TYPE_HELLO:
        # Deliverable 4: Once it receives a hello message, it logs the connection and sends a hello back.
        logging.info("Received Message Hello")
        send_reply(client_socket, PROTOCOL_VERSION, MSG_TYPE_HELLO, "Hello")
        return

    elif msg_type == MSG_TYPE_COMMAND:
        command_name = message

        # Deliverable 8: Check message type and command
        if command_name == "LIGHTON" or command_name == "LIGHTOFF":
            # Deliverable 9 (Supported Command)
            logging.info(f"EXECUTING SUPPORTED COMMAND: {command_name}")

            # Deliverable 10: Send back a "SUCCESS" message
            logging.info("Returning SUCCESS")
            send_reply(client_socket, PROTOCOL_VERSION, msg_type, "SUCCESS")

        else:
            # Deliverable 9 (Unknown Command)
            logging.warning(f"IGNORING UNKNOWN COMMAND: {command_name}")
            # Still reply with success as per client requirement 6 assumption
            send_reply(client_socket, PROTOCOL_VERSION, msg_type, "SUCCESS")

    else:
        logging.warning(f"IGNORING UNKNOWN MESSAGE TYPE: {msg_type}")
        pass


# --- Core Logic: Client Handling Loop ---


def handle_client(client_socket, client_address):
    """Handles communication with a single client by receiving and validating packets."""
    ip, port = client_address
    # Deliverable 3: Log the connection
    logging.info(f"Received connection from (IP, PORT): ('{ip}', {port})")

    while True:  # Deliverable 2: Server must not exit
        try:
            # 1. Receive the Packet Header (12 bytes) - First RECV call (Deliverable 6)
            header_data = client_socket.recv(HEADER_SIZE)

            # Deliverable 12: Check for 0-byte messages (client closed connection)
            if not header_data:
                logging.info(f"Client disconnected gracefully: ('{ip}', {port})")
                break

            if len(header_data) < HEADER_SIZE:
                logging.warning("Received incomplete header. Closing connection.")
                break

            # Unpack the header
            version, msg_type, msg_len = struct.unpack(
                PACKET_HEADER_FORMAT, header_data
            )

            # Log the received header data
            logging.info(
                f"Received Data: version: {version} message_type: {msg_type} length: {msg_len}"
            )

            # 2. Check Version (Deliverable 7)
            if version != PROTOCOL_VERSION:
                logging.error("VERSION MISMATCH. Continuing to listen.")
                break  # Exit the loop for this client only

            # 3. Receive the Message Payload - Second RECV call (Deliverable 6)
            message_data = client_socket.recv(msg_len)

            if len(message_data) < msg_len:
                logging.warning(
                    "Received incomplete message payload. Closing connection."
                )
                break

            message = message_data.decode("ascii").strip("\x00")

            process_command(client_socket, version, msg_type, message)

        except ConnectionResetError:
            logging.warning(f"Connection reset by client: ('{ip}', {port})")
            break
        except Exception as e:
            logging.error(f"Error handling client {client_address}: {e}")
            break

    client_socket.close()


# --- Main Server Initialization ---


def start_server(port, log_file):
    """Initializes and runs the light protocol server (Deliverable 2)."""

    setup_logging(log_file)
    logging.info(f"Server starting on port: {port} and logging to: {log_file}")

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_socket.bind(("", port))
        server_socket.listen(5)
        logging.info("Server is listening...")

    except socket.error as e:
        logging.error(f"Failed to set up socket: {e}")
        sys.exit(1)

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            handle_client(client_socket, client_address)

        except KeyboardInterrupt:
            logging.info("Server shutting down.")
            server_socket.close()
            break
        except Exception as e:
            logging.error(f"An unexpected error occurred in the main loop: {e}")
            continue


if __name__ == "__main__":
    # Deliverable 1: Parse command line arguments
    parser = argparse.ArgumentParser(description="Simple Protocol Light Server")
    parser.add_argument(
        "-p", "--port", type=int, required=True, help="The port the server listens on."
    )
    parser.add_argument(
        "-l", "--log", type=str, required=True, help="Log file location."
    )

    args = parser.parse_args()

    start_server(args.port, args.log)
