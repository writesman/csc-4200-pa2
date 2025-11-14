import argparse
import logging
import socket
import struct
import sys

PROTOCOL_VERSION = 17
# Deliverable 5: Packet format structure
PACKET_HEADER_FORMAT = ">III"
HEADER_SIZE = struct.calcsize(PACKET_HEADER_FORMAT)
# Deliverable 8: Message Type Constants
MSG_TYPE_HELLO = 1
MSG_TYPE_COMMAND = 2


def setup_logging(log_file_path: str) -> None:
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


def send_reply(
    client_socket: socket.socket, version: int, msg_type: int, message: str
) -> None:
    encoded_message = message.encode("ascii")
    message_length = len(encoded_message)

    header = struct.pack(PACKET_HEADER_FORMAT, version, msg_type, message_length)

    client_socket.sendall(header + encoded_message)


def process_command(
    client_socket: socket.socket, version: int, msg_type: int, message: str
) -> None:
    if msg_type == MSG_TYPE_HELLO:
        # Deliverable 4: Log the connection and send a hello back
        logging.info("Received Message Hello")
        send_reply(client_socket, PROTOCOL_VERSION, MSG_TYPE_HELLO, "Hello")
        return

    elif msg_type == MSG_TYPE_COMMAND:
        command_name = message

        # Deliverable 8: Check message body for supported command
        if command_name == "LIGHTON" or command_name == "LIGHTOFF":
            # Deliverable 9: Log supported command execution
            logging.info(f"EXECUTING SUPPORTED COMMAND: {command_name}")

            # Deliverable 10: Send back a "SUCCESS" message
            logging.info("Returning SUCCESS")
            send_reply(client_socket, PROTOCOL_VERSION, msg_type, "SUCCESS")

        else:
            # Deliverable 9: Log unknown command
            logging.warning(f"IGNORING UNKNOWN COMMAND: {command_name}")

    else:
        logging.warning(f"IGNORING UNKNOWN MESSAGE TYPE: {msg_type}")
        pass


def handle_client(
    client_socket: socket.socket, client_address: tuple[str, int]
) -> None:
    ip, port = client_address

    # Deliverable 3: Log client connection details
    logging.info(f"Received connection from {ip}:{port}")

    # Deliverable 2: Server must not exit after receiving a single packet
    while True:
        try:
            # Deliverable 6: Receive the packet header first
            header_data = client_socket.recv(HEADER_SIZE)

            # Deliverable 12: Check for 0-byte message (client closed connection)
            if not header_data:
                logging.info(f"Client disconnected gracefully: ('{ip}', {port})")
                break

            version, msg_type, msg_len = struct.unpack(
                PACKET_HEADER_FORMAT, header_data
            )

            logging.info(
                f"Received Data: version: {version}, message_type: {msg_type}, length: {msg_len}"
            )

            # Deliverable 7: Check if Version is 17
            if version != PROTOCOL_VERSION:
                logging.error("VERSION MISMATCH. Continuing to listen.")
                break

            # Deliverable 6: Receive the message payload
            message_data = client_socket.recv(msg_len)
            message = message_data.decode("ascii").strip("\x00")

            process_command(client_socket, version, msg_type, message)

        except ConnectionResetError:
            logging.warning(f"Connection reset by client: ('{ip}', {port})")
            break

    client_socket.close()


def start_server(port: int, log_file: str) -> None:
    setup_logging(log_file)
    logging.info(f"Server starting on port: {port} and logging to: {log_file}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(5)
    logging.info("Server is listening...")

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            handle_client(client_socket, client_address)
        except KeyboardInterrupt:
            logging.info("Server shutting down.")
            server_socket.close()
            break


def main() -> None:
    # Deliverable 1: Parse command line arguments (port and log file location)
    parser = argparse.ArgumentParser(description="Simple Protocol Light Server")
    parser.add_argument(
        "-p", "--port", type=int, required=True, help="The port the server listens on."
    )
    parser.add_argument(
        "-l", "--log", type=str, required=True, help="Log file location."
    )

    args = parser.parse_args()

    start_server(args.port, args.log)


if __name__ == "__main__":
    main()
