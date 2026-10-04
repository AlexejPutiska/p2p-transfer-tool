import socket
import threading
import struct
import time
import crcmod
import os

FLAG_TEXT = 0b00000001
FLAG_TEXT_ACK = 0b00000101
FLAG_TEXT_NACK = 0b00100001
FLAG_TEXT_LAST_FRAGMENT = 0b10000001

FLAG_FILE = 0b00000010
FLAG_FILE_ACK = 0b00000110
FLAG_FILE_NACK = 0b00100010
FLAG_FILE_LAST_FRAGMENT = 0b10000010

FLAG_ACK = 0b00000100
FLAG_SYN = 0b00001000
FLAG_SYN_ACK = 0b00001100

FLAG_HEARTBEAT = 0b00010000
FLAG_HEARTBEAT_ACK = 0b00010100

FLAG_NACK = 0b00100000
FLAG_FIN = 0b01000000
FLAG_LAST_FRAGMENT = 0b10000000

handshake_done = threading.Event()
hs_initiator = None
seq_number = 0

fragment_size = 1463
saving_path = os.getcwd()
file_name = None
total_size = 0
start_time = None
fragment_num_receive = 1
ack_filename = False
ack_file = False
nack_file = False
fragment_num = 1
bad_fragment_num = None

exitting = False
exitting_now = False
exitting_done = threading.Event()
iniciator_exitting = False

sent_packets = {}

last_activity_time = time.time()
missed_heartbeats = 0
is_active = False

crc16_func = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, xorOut=0x0000)
def calculate_crc16(data):
    return crc16_func(data)


def show_commands():
    global sent_packets
    print("\nCommands:")
    print("  m - Send a message")
    print("  f - Send a file")
    print("  p - Change the path for saving files")
    print("  s - Set the fragment number to simulate CRC error")
    print("  e - Exit the program")
    print("Enter your command:", end="")


def create_header(message_type, sequence_number, data):
    data_size = len(data)
    crc = calculate_crc16(data)

    if message_type == FLAG_TEXT or message_type == FLAG_FILE:
        if fragment_num == bad_fragment_num:
            print(f"\nSimulating CRC error")
            crc ^= 0x1234

    header = struct.pack('!BIHH', message_type, sequence_number, data_size, crc)
    return header


def create_socket(local_ip, local_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((local_ip, local_port))
    return sock


def initiate_handshake(sock, peer_address):
    global seq_number
    global sent_packets
    if handshake_done.is_set():
        return
    print(f"\nInitiating handshake with {peer_address}")
    data = b''
    message_type = FLAG_SYN
    header = create_header(message_type, seq_number, data)
    packet = header + data
    sock.sendto(packet, peer_address)
    sent_packets[seq_number] = packet
    seq_number = seq_number + 1


def handle_handshake(sock, addr, message_type):
    global seq_number
    global sent_packets
    if message_type == FLAG_SYN:
        print(f"\nReceived SYN from {addr}")
        print(f"Sending SYN-ACK to {addr}")
        response_type = FLAG_SYN_ACK
        response_header = create_header(response_type, seq_number, b'')
        sock.sendto(response_header, addr)
        sent_packets[seq_number] = response_header
        seq_number += 1
    elif message_type == FLAG_SYN_ACK:
        print(f"Received SYN-ACK from {addr}")
        print(f"Sending ACK to {addr}")
        response_type = FLAG_ACK
        response_header = create_header(response_type, seq_number, b'')
        sock.sendto(response_header, addr)
        sent_packets[seq_number] = response_header
        seq_number += 1
        handshake_done.set()
        mark_activity()
        print("Handshake completed.\n")
    elif message_type == FLAG_ACK:
        print(f"Received ACK from {addr}")
        handshake_done.set()
        mark_activity()
        print("Handshake completed.\n")
        if hs_initiator is None:
            print("Press ENTER to continue...")


def send_heartbeat(sock, peer_address):
    global missed_heartbeats
    global last_activity_time
    global is_active
    global seq_number
    global exitting_now
    global sent_packets

    while not exitting_now:
        time.sleep(5)
        if exitting_now:
            break
        if handshake_done.is_set():
            if not is_active:
                try:
                    header = create_header(FLAG_HEARTBEAT, seq_number, b'')
                    sock.sendto(header, peer_address)
                    sent_packets[seq_number] = header
                    missed_heartbeats += 1
                    seq_number += 1

                    if missed_heartbeats >= 3:
                        print("\nConnection lost.")
                        print("\nPress ENTER to exit...")
                        exitting_now = True
                        break
                except OSError:
                    exitting_now = True
                    break
            else:
                is_active = False


def mark_activity():
    global is_active
    global last_activity_time
    global missed_heartbeats
    is_active = True
    last_activity_time = time.time()
    missed_heartbeats = 0


def handle_heartbeat(sock, addr):
    global seq_number
    global sent_packets
    header = create_header(FLAG_HEARTBEAT_ACK, seq_number, b'')
    sock.sendto(header, addr)
    sent_packets[seq_number] = header
    seq_number = seq_number + 1


def send_message(sock, peer_address):
    global seq_number
    global sent_packets
    global fragment_num
    global ack_file
    global nack_file
    global fragment_size
    global bad_fragment_num

    fragment_num = 1
    message = input("Enter your message: ")
    data = message.encode()

    total_fragments = (len(data) + fragment_size - 1) // fragment_size

    print(f"Message size: {len(data)} bytes")
    print(f"Fragment size: {fragment_size} bytes")
    print(f"Total fragments: {total_fragments}")

    for i in range(total_fragments):
        start_index = i * fragment_size
        end_index = start_index + fragment_size
        chunk = data[start_index:end_index]

        fragment_sent = False
        while not fragment_sent:
            ack_file = False
            nack_file = False
            if i == total_fragments - 1:
                header = create_header(FLAG_TEXT_LAST_FRAGMENT, seq_number, chunk)
            else:
                header = create_header(FLAG_TEXT, seq_number, chunk)
            packet = header + chunk
            sent_packets[seq_number] = packet
            mark_activity()

            sock.sendto(packet, peer_address)
            print(f"Sent fragment {fragment_num} ({len(chunk)} bytes)")
            seq_number += 1

            while True:
                time.sleep(0.01)
                if ack_file:
                    print(f"Received ACK for fragment {fragment_num}")
                    ack_file = False
                    fragment_sent = True
                    fragment_num += 1
                    break
                elif nack_file:
                    nack_file = False
                    bad_fragment_num = None
                    print(f"Received NACK for fragment {fragment_num}")
                    break

    print("\nMessage sent successfully\n")
    bad_fragment_num = None


def handle_message(sock, addr, message_type, data, message_reassembly):
    global seq_number
    global fragment_num_receive
    global total_size
    global sent_packets
    global start_time

    ack_header = create_header(FLAG_TEXT_ACK, seq_number, b'')
    sock.sendto(ack_header, addr)
    sent_packets[seq_number] = ack_header
    seq_number += 1
    if fragment_num_receive == 1:
        print(f"\nReceiving message:")
        start_time = time.time()
    message_reassembly['data'] += data
    total_size += len(data)
    print(f"Received fragment {fragment_num_receive} ({len(data)} bytes) successfully")
    fragment_num_receive += 1

    if message_type == FLAG_TEXT_LAST_FRAGMENT:
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"\nTransfer time: {elapsed_time:.3f} seconds")
        print(f"Message size: {total_size} bytes")
        complete_message = message_reassembly['data'].decode()
        print(f"Message: {complete_message}")
        print("\nMessage received successfully")
        show_commands()
        message_reassembly['data'] = b''
        total_size = 0
        start_time = None
        fragment_num_receive = 1


def send_file(sock, addr):
    global seq_number
    global fragment_size
    global sent_packets
    global ack_filename
    global ack_file
    global nack_file
    global fragment_num
    global bad_fragment_num

    fragment_num = 1
    file_path = input("Enter the path to the file you want to send: ").strip()

    if not os.path.isfile(file_path):
        print("File not found...\n")
        return

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    total_fragments = (file_size + fragment_size - 1) // fragment_size

    file_name_data = file_name.encode()
    header = create_header(FLAG_FILE, seq_number, file_name_data)
    packet = header + file_name_data
    sock.sendto(packet, addr)
    sent_packets[seq_number] = packet
    mark_activity()
    seq_number += 1

    time.sleep(0.1)

    if not ack_filename:
        header = create_header(FLAG_FILE, seq_number, file_name_data)
        packet = header + file_name_data
        sock.sendto(packet, addr)
        sent_packets[seq_number] = packet
        mark_activity()
        seq_number += 1
        time.sleep(0.01)
        if not ack_filename:
            print("\nFile transfer failed...")
            return

    print(f"\nSending file: {file_name}")
    print(f"File size: {file_size} bytes")
    print(f"Fragment size: {fragment_size} bytes")
    print(f"Total fragments: {total_fragments}")


    with open(file_path, 'rb') as f:
        for i in range(total_fragments):
            chunk = f.read(fragment_size)
            fragment_sent = False
            while not fragment_sent:
                ack_file = False
                nack_file = False
                if i == total_fragments - 1:
                    header = create_header(FLAG_FILE_LAST_FRAGMENT, seq_number, chunk)
                else:
                    header = create_header(FLAG_FILE, seq_number, chunk)
                packet = header + chunk
                sent_packets[seq_number] = packet
                mark_activity()

                sock.sendto(packet, addr)
                print(f"Sent fragment {fragment_num} ({len(chunk)} bytes)")
                seq_number += 1
                time.sleep(0.01)
                while True:
                    if ack_file:
                        print(f"Received ACK for fragment {fragment_num}")
                        ack_file = False
                        fragment_sent = True
                        fragment_num += 1
                        break
                    elif nack_file:
                        nack_file = False
                        bad_fragment_num = None
                        print(f"Received NACK for fragment {fragment_num}")
                        break

    print(f"\nFile {file_name} sent successfully\n")
    ack_filename = False
    bad_fragment_num = None


def handle_file(sock, addr, message_type, data, file_reassembly):
    global saving_path
    global file_name
    global total_size
    global start_time
    global fragment_num_receive
    global seq_number
    global sent_packets

    if file_name is None:
        file_name = data.decode()
        file_reassembly[file_name] = b''
        ack_header = create_header(FLAG_FILE_ACK, seq_number, b'')
        sock.sendto(ack_header, addr)
        sent_packets[seq_number] = ack_header
        seq_number += 1
        print(f"\n\nReceiving file: {file_name}")
        start_time = time.time()

    else:
        ack_header = create_header(FLAG_FILE_ACK, seq_number, b'')
        sock.sendto(ack_header, addr)
        sent_packets[seq_number] = ack_header
        seq_number += 1
        file_reassembly[file_name] += data
        total_size += len(data)
        print(f"Received fragment {fragment_num_receive} ({len(data)} bytes) successfully")
        fragment_num_receive += 1


    if message_type == FLAG_FILE_LAST_FRAGMENT:
        end_time = time.time()
        elapsed_time = end_time - start_time

        file_path = os.path.join(saving_path, file_name)
        with open(file_path, 'wb') as f:
            f.write(file_reassembly[file_name])

        print(f"\nTransfer time: {elapsed_time:.3f} seconds")
        print(f"File size: {total_size} bytes")
        print(f"File saved to: {saving_path}\n")
        print(f"File {file_name} received successfully")
        show_commands()

        file_name = None
        file_reassembly.clear()
        total_size = 0
        start_time = None
        fragment_num_receive = 1


def send_nack(sock, addr, sequence_number, message_type):
    global sent_packets
    global seq_number
    if message_type & FLAG_FILE or message_type & FLAG_TEXT:
        print(f"Received fragment {fragment_num_receive} - ERROR: CRC mismatch")
        print(f"Sending NACK for seq_number {fragment_num_receive}")
        nack_data = struct.pack('!I', sequence_number)
        if message_type & FLAG_FILE:
            nack_header = create_header(FLAG_FILE_NACK, seq_number, nack_data)
        else:
            nack_header = create_header(FLAG_TEXT_NACK, seq_number, nack_data)
        nack_packet = nack_header + nack_data
        sock.sendto(nack_packet, addr)
        sent_packets[seq_number] = nack_packet
        mark_activity()
        seq_number += 1
    else:
        print(f"\nReceived fragment {sequence_number} - ERROR: CRC mismatch")
        print(f"Sending NACK for seq_number {sequence_number} to {addr}")
        nack_data = struct.pack('!I', sequence_number)
        nack_header = create_header(FLAG_NACK, seq_number, nack_data)
        nack_packet = nack_header + nack_data
        sock.sendto(nack_packet, addr)
        sent_packets[seq_number] = nack_packet
        mark_activity()
        seq_number += 1


def handle_nack(sock, addr, data):
    global seq_number
    global sent_packets

    resend_seq_number = struct.unpack('!I', data)[0]
    print(f"\nReceived NACK for seq_number {resend_seq_number} from {addr}")

    if resend_seq_number in sent_packets:
        original_packet = sent_packets[resend_seq_number]
        header_size = struct.calcsize('!BIHH')
        original_header = original_packet[:header_size]
        original_data = original_packet[header_size:]

        message_type, sequence_number, data_size, _ = struct.unpack('!BIHH', original_header)
        new_seq_number = seq_number
        new_header = create_header(message_type, new_seq_number, original_data)
        new_packet = new_header + original_data
        sock.sendto(new_packet, addr)
        print(f"Resent packet with seq_number {sequence_number}")
        sent_packets[new_seq_number] = new_packet
        seq_number += 1
    else:
        print(f"No packet found for seq_number {resend_seq_number}")
        show_commands()


def send_fin(sock, addr):
    global seq_number
    global exitting
    global iniciator_exitting
    global sent_packets
    print(f"Sending FIN to {addr}")
    message_type = FLAG_FIN
    header = create_header(message_type, seq_number, b'')
    sock.sendto(header, addr)
    sent_packets[seq_number] = header
    seq_number += 1
    exitting = True
    iniciator_exitting = True


def handle_4way_handshake(sock, addr, message_type):
    global seq_number
    global exitting_done
    global exitting_now
    global sent_packets
    if iniciator_exitting == True:
        if message_type == FLAG_ACK:
            print(f"Received ACK from {addr}")
        elif message_type == FLAG_FIN:
            print(f"Received FIN from {addr}")
            print(f"Sending ACK to {addr}")
            response_type = FLAG_ACK
            response_header = create_header(response_type, seq_number, b'')
            sock.sendto(response_header, addr)
            sent_packets[seq_number] = response_header
            seq_number += 1
            exitting_done.set()
    else:
        if message_type == FLAG_FIN:
            print(f"\nReceived FIN from {addr}")
            print(f"Sending ACK to {addr}")
            response_type = FLAG_ACK
            response_header = create_header(response_type, seq_number, b'')
            sock.sendto(response_header, addr)
            sent_packets[seq_number] = response_header
            seq_number += 1
            time.sleep(0.3)
            print(f"Sending FIN to {addr}")
            message_type = FLAG_FIN
            header = create_header(message_type, seq_number, b'')
            sock.sendto(header, addr)
            sent_packets[seq_number] = header
            seq_number += 1
        elif message_type == FLAG_ACK:
            print(f"Received ACK from {addr}")
            print("\nPress ENTER to exit...")
            exitting_now = True


def receive(sock):
    global missed_heartbeats
    global last_activity_time
    global is_active
    global exitting
    global ack_filename
    global ack_file
    global nack_file
    file_reassembly = {}
    message_reassembly = {'data': b''}
    while True:
        try:
            packet, addr = sock.recvfrom(1500)
            header_size = struct.calcsize('!BIHH')
            header = packet[:header_size]
            data = packet[header_size:]
            message_type, sequence_number, data_size, crc = struct.unpack('!BIHH', header)

            calculated_crc = calculate_crc16(data)
            if crc != calculated_crc:
                send_nack(sock, addr, sequence_number, message_type)
                mark_activity()
                continue

            if message_type & FLAG_NACK:
                if message_type == FLAG_FILE_NACK:
                    nack_file = True
                elif message_type == FLAG_TEXT_NACK:
                    nack_file = True
                else:
                    handle_nack(sock, addr, data)

            if not handshake_done.is_set():
                handle_handshake(sock, addr, message_type)

            elif exitting:
                handle_4way_handshake(sock, addr, message_type)

            else:
                if message_type == FLAG_HEARTBEAT:
                    mark_activity()
                    handle_heartbeat(sock, addr)
                elif message_type == (FLAG_HEARTBEAT_ACK):
                    mark_activity()

                elif message_type == FLAG_TEXT or message_type == FLAG_TEXT_LAST_FRAGMENT:
                    mark_activity()
                    handle_message(sock, addr, message_type, data, message_reassembly)
                elif message_type == FLAG_TEXT_ACK:
                    mark_activity()
                    ack_file = True
                elif message_type == FLAG_TEXT_NACK:
                    mark_activity()
                    nack_file = True

                elif message_type == FLAG_FILE_ACK:
                    if not ack_filename:
                        mark_activity()
                        ack_filename = True
                    else:
                        mark_activity()
                        ack_file = True
                elif message_type == FLAG_FILE_NACK:
                    mark_activity()
                    nack_file = True
                elif message_type == FLAG_FILE or message_type == FLAG_FILE_LAST_FRAGMENT:
                    mark_activity()
                    handle_file(sock, addr, message_type, data, file_reassembly)
                elif message_type == FLAG_FIN:
                    exitting = True
                    handle_4way_handshake(sock, addr, message_type)

        except OSError:
            if exitting_now == True:
                break
            else:
                continue


def main():
    local_ip = "0.0.0.0"

    local_port = int(input("Enter the local port: "))
    target_ip = input("Enter the target IP address: ")
    target_port = int(input("Enter the target port: "))

    sock = create_socket(local_ip, local_port)

    peer_address = (target_ip, target_port)

    receive_thread = threading.Thread(target=receive, args=(sock,))
    receive_thread.daemon = True
    receive_thread.start()

    try:
        global hs_initiator
        global saving_path
        global fragment_size
        global exitting_now
        global bad_fragment_num

        heartbeat_thread = threading.Thread(target=send_heartbeat, args=(sock, peer_address))
        heartbeat_thread.daemon = True
        heartbeat_thread.start()

        hs_initiator = input("Initiate handshake (yes/no): ").strip().lower()
        if hs_initiator == "no":
            print("Waiting for handshake to be initiated by second peer...")

        if hs_initiator == "yes":
            while not handshake_done.is_set():
                time.sleep(2)
                initiate_handshake(sock, peer_address)
        else:
            while not handshake_done.is_set():
                time.sleep(0.1)

        while True:
            print("Commands:")
            print("  m - Send a message")
            print("  f - Send a file")
            print("  p - Change the path for saving files")
            print("  s - Set the fragment number to simulate CRC error")
            print("  e - Exit the program")
            command = input("Enter your command: ").lower()

            if (exitting_now == True):
                print("Program exited successfully.")
                sock.close()
                receive_thread.join()
                break

            if command == 'm':
                while True:
                    try:
                        fragment_input = input("Enter fragment size (1,1463): ").strip()
                        fragment_size = int(fragment_input)
                        if 1 <= fragment_size <= 1463:
                            break
                        else:
                            print("Invalid input. Setting to default (1463)")
                            fragment_size = 1463
                            break
                    except ValueError:
                        print("Invalid input. Setting to default (1463)")
                        fragment_size = 1463
                        break
                send_message(sock, peer_address)

            elif command == 'f':
                while True:
                    try:
                        fragment_input = input("Enter fragment size (1,1463): ").strip()
                        fragment_size = int(fragment_input)
                        if 1 <= fragment_size <= 1463:
                            break
                        else:
                            print("Invalid input. Setting to default (1463)")
                            fragment_size = 1463
                            break
                    except ValueError:
                        print("Invalid input. Setting to default (1463)")
                        fragment_size = 1463
                        break
                send_file(sock, peer_address)

            elif command == 'p':
                new_path = input("Enter the new path for saving files: ").strip()
                if os.path.isdir(new_path):
                    saving_path = new_path
                    print(f"Saving path updated to: {saving_path}")
                else:
                    print("\nInvalid path.\n")

            elif command == 's':
                while True:
                    try:
                        bad_fragment_input = input("Enter the fragment number to simulate CRC error: ").strip()
                        bad_fragment_num = int(bad_fragment_input)
                        print(f"CRC error will be simulated for fragment number {bad_fragment_num}")
                        break
                    except ValueError:
                        print("Invalid input.")
                        break

            elif command == 'e':
                print("\nExiting program...")
                send_fin(sock, peer_address)
                exitting_done.wait()
                print("Program exited successfully.")
                exitting_now = True
                time.sleep(0.5)
                sock.close()
                receive_thread.join()
                break
            else:
                print("\nInvalid command...\n")
    except KeyboardInterrupt:
        print("\nProgram was unexpectedly interrupted.")
    finally:
        if sock:
            sock.close()
        if receive_thread.is_alive():
            receive_thread.join()
        if heartbeat_thread.is_alive():
            heartbeat_thread.join()


if __name__ == "__main__":
    main()
