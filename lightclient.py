import argparse
import logging
import socket
import struct
import sys

PROTOCOL_VERSION = 17
PACKET_HEADER_FORMAT = ">III"
HEADER_SIZE = struct.calcsize(PACKET_HEADER_FORMAT)
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


def create_packet(version: int, msg_type: int, message_body: str) -> bytes:
    encoded_message = message_body.encode("ascii")
    message_length = len(encoded_message)

    header = struct.pack(PACKET_HEADER_FORMAT, version, msg_type, message_length)

    return header + encoded_message


def receive_reply(s: socket.socket) -> tuple[int, int, str]:
    # Receive the header
    header_data = s.recv(HEADER_SIZE)
    if not header_data:
        raise ConnectionError("Connection closed by server while waiting for header.")

    version, msg_type, msg_len = struct.unpack(PACKET_HEADER_FORMAT, header_data)

    logging.info(
        f"Received Data: version: {version} type: {msg_type} length: {msg_len}"
    )

    # Requirement 4: Check version and log status
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


def start_client(server_ip: str, port: int) -> None:
    """Main client logic for connecting and sending packets."""

    logging.info(f"Attempting connection to {server_ip}:{port}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # Requirement 2: Connect to the server
            s.connect((server_ip, port))

            # Requirement 3: Construct and send HELLO
            hello_packet = create_packet(PROTOCOL_VERSION, MSG_TYPE_HELLO, "Hello")
            s.sendall(hello_packet)
            logging.info("Sending HELLO Packet")

            # Requirement 4: Receive HELLO Reply and check version
            reply_version, _, reply_message = receive_reply(s)

            if reply_version != PROTOCOL_VERSION:
                return

            logging.info(f"Received Message {reply_message}")

            # Requirement 5: Send a command packet if version is accepted
            command_body = "LIGHTON"
            command_packet = create_packet(
                PROTOCOL_VERSION, MSG_TYPE_COMMAND, command_body
            )
            s.sendall(command_packet)
            logging.info("Sending command")

            # Requirement 6: Receive server's reply
            _, _, success_message = receive_reply(s)

            logging.info(f"Received Message {success_message}")
            if success_message == "SUCCESS":
                logging.info("Command Successful")

            # Requirement 6: Gracefully shutdown the socket
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            logging.info("Closing socket")

        except ConnectionRefusedError:
            logging.error(
                f"Connection refused by server at {server_ip}:{port}. Is the server running?"
            )
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")


def main() -> None:
    # Requirement 1: Parse command line arguments (server, port, logfile).
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


if __name__ == "__main__":
    main()
