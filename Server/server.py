##
# Code for the server
import hashlib
import logging
import math
import socket
import threading
import numpy as np
import traceback
from _thread import *
import time
from datetime import datetime
from tqdm import tqdm

# host = socket.gethostbyaddr("54.162.149.119")[0]
host = '0.0.0.0'
port = 60002
BUFFER_SIZE = 1024

# UDP Settings
udpPort = 60003
udpBUFFER_SIZE = 64000

File_path = "data/Files/"
Log_path = "data/Logs/"

file_100MB = 'File1.mp4'
file_250MB = 'File2.mp4'
files_names = {1: file_100MB, 2: file_250MB}

# open in binary

SYN = 'Hello'
AKN_READY = 'Ready'
AKN_NAME = 'Name'
AKN_OK = 'Ok'
AKN_HASH = 'HashOk'
AKN_COMPLETE = 'SendComplete'
ERROR = 'Error'
AKN_START_UDP = "UDP"



def threadsafe_function(fn):
    """decorator making sure that the decorated function is thread safe"""
    lock = threading.Lock()

    def new(*args, **kwargs):
        lock.acquire()
        try:
            r = fn(*args, **kwargs)
        except Exception as e:
            raise e
        finally:
            lock.release()
        return r

    return new


class ServerProtocol:

    def __init__(self, clients_number, file_name, UDPServer):

        # UDP
        self.udpServer = UDPServer
        self.udp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_server_address = (host, udpPort)

        # TCP
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.thread_count = 0
        self.clients_number = clients_number
        self.file_name = file_name
        self.ready_clients = 0
        self.failed_connections = 0
        self.all_ready_monitor = threading.Event()
        self.file_size = self.get_file_size()
        self.running_times = np.zeros(clients_number)
        self.completed_connections = np.zeros(clients_number)
        self.success_connections = np.zeros(clients_number)
        self.packages_sent = np.zeros(clients_number)
        self.bytes_sent = np.zeros(clients_number)

        try:
            self.server_socket.bind((host, port))
        except socket.error as e:
            print(str(e))

        print('Waitiing for a Connection..')
        self.server_socket.listen(5)

        # datetime object containing current date and time
        now = datetime.now()
        dt_string = now.strftime("%Y-%d-%m %H:%M:%S")
        dt_string2 = now.strftime("%Y-%d-%m-%H-%M-%S")

        logging.basicConfig(filename="data/Logs/{}.log".format(dt_string2), level=logging.INFO)
        logging.info(dt_string)
        logging.info("File name: {}; file size: {} B".format(self.file_name, self.file_size))

    def send_file_to_client(self, connection, thread_id):
        while True:
            try:
                reply = self.receive_from_client(connection)
                self.verify_reply(reply, SYN)

                self.send_to_client(connection, SYN, "Server Says: Hail from client {} received".format(thread_id),
                                    thread_id)

                self.send_to_client(connection, f'{thread_id};{self.clients_number}',
                                    "Server Says: Sent id to client {}".format(thread_id),
                                    thread_id)

                reply = self.receive_from_client(connection)
                self.verify_reply(reply, AKN_READY)

                self.update_ready_clients()

                while not self.all_clients_ready(thread_id):
                    print('Server Says: client {} is put in wait for the rest of clients'.format(thread_id))
                    self.all_ready_monitor.wait()

                self.send_to_client(connection, self.file_name, "Server Says: Sending file name ({}) to client "
                                                                "{}".format(self.file_name, thread_id), thread_id)

                reply = self.receive_from_client(connection)

                self.verify_reply(reply, AKN_NAME)

                hash = self.hash_file()
                self.send_to_client(connection, hash,
                                    "Server Says: Sending file hash ({}) to client {}".format(hash, thread_id),
                                    thread_id)
                reply = self.receive_from_client(connection)

                self.verify_reply(reply, AKN_OK)

                size = str(self.file_size)

                self.send_to_client(connection, size,
                                    "Server Says: Sending file size ({}) to client {}".format(size, thread_id),
                                    thread_id)

                start_time = time.time()

                # Send File to Client on UDP
                # self.send_file_UDP(thread_id)
                self.udpServer.send_file_UDP(thread_id, self.file_size, self.file_name, self.bytes_sent, self.packages_sent)

                reply = self.receive_from_client(connection)

                self.running_times[thread_id - 1] = time.time() - start_time

                self.verify_reply(reply, AKN_COMPLETE)

                self.udp_server_socket.close()

                reply = self.receive_from_client(connection)
                self.verify_reply(reply, AKN_HASH)

                print("Server Says: File integrity verified by  client {}".format(thread_id))

                connection.close()
                self.completed_connections[thread_id - 1] = 1
                self.success_connections[thread_id - 1] = 1
                self.log_info()
                break

            except Exception as err:
                self.update_failed_connections()
                connection.close()
                print("Server Says: Error during file transmission to client {}: {} \n".format(thread_id, str(err)))
                self.completed_connections[thread_id - 1] = 1
                self.log_info()
                break

    def receive_from_client(self, connection):
        return connection.recv(BUFFER_SIZE).decode('utf-8')

    def send_to_client(self, connection, segment, print_message, thread_id):
        b = connection.send(str.encode(segment))
        self.bytes_sent[thread_id - 1] += int(b)
        #  self.packages_sent[thread_id-1] += 1

        print("\n", print_message)

    def verify_reply(self, received, expected):
        if not expected == received:
            raise Exception("Error in protocol: expected {}; received {}".format(expected, received))

    @threadsafe_function
    def all_clients_ready(self, thread_id):

        all_ready = self.clients_number - self.ready_clients == 0

        if all_ready:
            print("Server Says: all clients ready: starting file transport to client {}".format(thread_id))

        return all_ready

    def send_file_UDP(self, thread_id):

        progress = tqdm(range(self.file_size), f'Transfer to client{thread_id}', unit="B",
                        unit_scale=True,
                        unit_divisor=BUFFER_SIZE)

        with open(File_path + self.file_name, 'rb') as file:

            while True:
                # read only 1024 bytes at a time
                chunk = file.read(udpBUFFER_SIZE)

                if chunk == b'':
                    break

                b = self.udp_server_socket.sendto(chunk, self.udp_server_address)
                self.bytes_sent[thread_id - 1] += int(b)

                progress.update(len(chunk))

            self.packages_sent[thread_id - 1] = self.file_size / udpBUFFER_SIZE
            print("Server Says: File transmission is complete to client {}".format(thread_id))
            file.close()

    def get_file_size(self):
        with open(File_path + self.file_name, 'rb') as file:
            packed_file = file.read()
        return int(len(packed_file))

    def hash_file(self):
        file = open(File_path + self.file_name, 'rb')  # open in binary

        """"This function returns the SHA-1 hash
        of the file passed into it"""
        # make a hash object
        h = hashlib.sha1()

        # open file for reading in binary mode

        # loop till the end of the file
        chunk = 0
        while chunk != b'':
            # read only 1024 bytes at a time
            chunk = file.read(BUFFER_SIZE)
            h.update(chunk)
        file.close()

        # return the hex representation of digest
        return h.hexdigest()

    def close(self):
        self.server_socket.close()

    @threadsafe_function
    def update_ready_clients(self):
        self.ready_clients += 1

        if self.clients_number - self.ready_clients == 0:
            self.all_ready_monitor.set()

    @threadsafe_function
    def update_failed_connections(self):
        self.failed_connections += 1

    def all_completed(self):
        return self.completed_connections.sum() == self.clients_number

    def log_info(self):
        if self.all_completed():
            logging.info(
                '_____________________________________________________________________________________________________')
            logging.info('Successful connections:')
            d = {1: 'yes', 0: 'no'}

            for n in range(self.clients_number):
                logging.info('Client{}: {}'.format(n + 1, d[self.success_connections[n]]))

            logging.info(
                '_____________________________________________________________________________________________________')
            logging.info('Running times:')
            for n in range(self.clients_number):
                logging.info('Client{}: {} s'.format(n + 1, self.running_times[n]))

            logging.info(
                '_____________________________________________________________________________________________________')
            logging.info('Bytes sent:')
            for n in range(self.clients_number):
                logging.info('Client{}: {} B'.format(n + 1, self.bytes_sent[n]))

            logging.info(
                '_____________________________________________________________________________________________________')
            logging.info('Packages sent:')
            for n in range(self.clients_number):
                logging.info('Client{}: {}'.format(n + 1, self.packages_sent[n]))

    def run(self):
        while True:
            print('Listening at', self.server_socket.getsockname())

            Client, address = self.server_socket.accept()
            self.thread_count += 1

            print('Connected to: ' + address[0] + ':' + str(address[1]))

            logging.info('Connection set to client{} ({}:{})'.format(self.thread_count, address[0], str(address[1])))

            if self.thread_count <= self.clients_number:
                start_new_thread(self.send_file_to_client, (Client, self.thread_count))

            print('Thread Number: ' + str(self.thread_count))


class UDPServer:
    ''' A simple UDP Server '''

    def __init__(self, host, port):

        self.host = host  # Host address
        self.port = port  # Host port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Socket
        self.sock.bind((self.host, self.port))


    def send_file_UDP(self, thread_id, file_size, file_name, bytes_sent, packages_sent):
        data, client_address = self.sock.recvfrom(1024)

        if data.decode('utf-8')==AKN_START_UDP:
            print("UDP Starting in thread {}".format(thread_id))

        progress = tqdm(range(file_size), f'Transfer to client{thread_id}', unit="B",
                        unit_scale=True,
                        unit_divisor=BUFFER_SIZE)
        with open(File_path + file_name, 'rb') as file:

            while True:
                # read only 1024 bytes at a time
                chunk = file.read(udpBUFFER_SIZE)

                if chunk == b'':
                    break

                b = self.sock.sendto(chunk, client_address)
                bytes_sent[thread_id - 1] += int(b)

                progress.update(len(chunk))

            packages_sent[thread_id - 1] = file_size / udpBUFFER_SIZE
            print("Server Says: File transmission is complete to client {}".format(thread_id))
            file.close()

    def shutdown_server(self):

        ''' Shutdown the UDP server '''
        self.sock.close()


def main():
    fn = int(input("Indicate file to send to clients: \nType 1 for 100 MB video \nType 2 for 250 MB video \n"))
    file_name = files_names[fn]

    nc = int(input("Indicate number of clients to send file to: \n"))

    udpServer = UDPServer(host, udpPort)
    s = ServerProtocol(nc, file_name, udpServer)
    s.run()


if __name__ == "__main__":
    main()
