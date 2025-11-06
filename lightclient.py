import argparse
import logging
import socket
import struct
import sys

# --- Protocol Constants ---
PROTOCOL_VERSION = 17
PACKET_HEADER_FORMAT = ">III"  # Big-endian, 3 Unsigned Integers
HEADER_SIZE = struct.calcsize(PACKET_HEADER_FORMAT)  # 12 bytes

# --- Message Type Constants ---
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
            logging.FileHandler(log_file_path, mode="a"),
            logging.StreamHandler(sys.stdout),
        ],
    )


# --- Helper Function: Packet Creation ---


def create_packet(version, msg_type, message_body):
    """Constructs a packet using the required protocol format (>III header)."""

    encoded_message = message_body.encode("ascii")
    message_length = len(encoded_message)

    # Pack the Header: Version(4B), Message Type(4B), Message Length(4B)
    header = struct.pack(PACKET_HEADER_FORMAT, version, msg_type, message_length)

    return header + encoded_message


# --- Helper Function: Receive Reply ---


def receive_reply(s):
    """Receives a packet reply from the server (Header + Payload)."""

    # Receive the header
    header_data = s.recv(HEADER_SIZE)
    if not header_data:
        raise ConnectionError("Connection closed by server while waiting for header.")

    version, msg_type, msg_len = struct.unpack(PACKET_HEADER_FORMAT, header_data)

    # Log received header data (matches sample output)
    logging.info(
        f"Received Data: version: {version} type: {msg_type} length: {msg_len}"
    )

    # Client Requirement 4: Check version
    if version == PROTOCOL_VERSION:
        logging.info("VERSION ACCEPTED")
    else:
        logging.warning("VERSION MISMATCH")

    # Receive the payload
    message_data = s.recv(msg_len)
    if len(message_data) < msg_len:
        raise ConnectionError("Received incomplete message payload.")

    message = message_data.decode("ascii").strip("\x00")

    return version, msg_type, message


# --- Core Logic: Client Main Execution ---


def start_client(server_ip, port):
    """Main client logic for connecting and sending packets."""

    logging.info(f"Attempting connection to {server_ip}:{port}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # Client Requirement 2: Connect to the server
            s.connect((server_ip, port))

            # --- PHASE 1: Send HELLO Packet (Client Requirement 3) ---
            hello_packet = create_packet(PROTOCOL_VERSION, MSG_TYPE_HELLO, "Hello")
            s.sendall(hello_packet)
            logging.info("Sending HELLO Packet")  # Matches sample output

            # --- PHASE 2: Receive HELLO Reply (Client Requirement 4) ---
            reply_version, reply_type, reply_message = receive_reply(s)

            if reply_version != PROTOCOL_VERSION:
                return  # Stop if version mismatch

            logging.info(f"Received Message {reply_message}")

            # --- PHASE 3: Send Command Packet (Client Requirement 5) ---
            # Send LIGHTON first, as it's the dominant example in the sample
            command_body = "LIGHTON"
            command_packet = create_packet(
                PROTOCOL_VERSION, MSG_TYPE_COMMAND, command_body
            )
            s.sendall(command_packet)
            logging.info("Sending command")  # Matches sample output

            # --- PHASE 4: Receive Server's Reply (Client Requirement 6) ---
            success_version, success_type, success_message = receive_reply(s)

            logging.info(f"Received Message {success_message}")
            if success_message == "SUCCESS":
                logging.info("Command Successful")  # Matches sample output

            # Client Requirement 6: Gracefully shutdown the socket.
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            logging.info("Closing socket")  # Matches sample output

        except ConnectionRefusedError:
            logging.error(
                f"Connection refused by server at {server_ip}:{port}. Is the server running?"
            )
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")


# --- Main Execution Block ---

if __name__ == "__main__":
    # Client Requirement 1: Parse command line arguments
    parser = argparse.ArgumentParser(description="Simple Protocol Light Client")
    parser.add_argument(
        "-s", "--server", type=str, required=True, help="The IP address of the server."
    )
    parser.add_argument(
        "-p", "--port", type=int, required=True, help="The port the server listens on."
    )
    parser.add_argument(
        "-l", "--log", type=str, required=True, help="Log file location."
    )

    args = parser.parse_args()

    setup_logging(args.log)
    start_client(args.server, args.port)
