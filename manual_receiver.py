import random 
from socket import * 
import sys 
import _io 
import time
from common import * 
import threading 
from collections import deque 

random.seed()
    
class Receiver:
    class StateControlBlock:
        def __init__(self):
            self.snd_base = 0
            self.next_seqnum = 0
            self.dup_acks = 0
            self.state = 'closed' 
            self.lock = threading.Lock()
            self.unacked_queue = deque()    # invariant: all bytes [snd_base, next_seqnum) are in queue. invariant 2: all segments have nonzero length
        
        def acquire(self):
            self.lock.acquire()

        def release(self):
            self.lock.release()

    class Stats:
        def __init__(self):
            self.original_bytes = 0
            self.tot_bytes = 0
            self.original_segs = 0
            self.tot_segs = 0
            self.cor_segs = 0
            self.dup_segs = 0
            self.tot_acks = 0
            self.dup_acks = 0
            
    def __init__(self, textf : _io.TextIOWrapper, logf : _io.TextIOWrapper, max_win, sock : socket, dest_address):
        self.textf = textf
        self.logf = logf
        self.max_win = max_win
        self.sock = sock
        self.dest_address = dest_address
        self.scb = Receiver.StateControlBlock()
        self.stats = Receiver.Stats()
        self.BUFSZ = 2048
        self.time_start = None

    def run(self):
        def recv_loop():
            while True:
                self.recv() 
        threading.Thread(target=recv_loop).start()

        while True:
            #res = input("Enter seq num to send, and optional type (default ack): ").split(' ')
            res = input().split(' ')
            
            type = 'ack'
            seq_num = int(res[0])
            if len(res) == 2:
                type = res[1]

            self.send(Segment.create(seq_num, type))

    def send(self, segment : Segment):
        self._write_log('snd', 'ok', segment)
        self.sock.sendto(segment.encode(), self.dest_address)

    def recv(self):
        """Guarantees that the received segment uncorrupted ack"""
        while True:
            data, address = self.sock.recvfrom(self.BUFSZ)
            if address != self.dest_address:
                print("WARNING: Received data from unexpected address")
                continue 

            seg, no_cor = Segment.decode(data)
            if not no_cor:
                if seg != None:
                    self._write_log('rcv', 'cor', seg)
                continue 

            self._write_log('rcv', 'ok', seg)
            return seg

    def _write_log(self, type, action, seg):
        if self.time_start == None:
            self.time_start = time.perf_counter_ns()

        elapsed = (time.perf_counter_ns() - self.time_start) / 1e6
        
        log_str = f'{type}  {action:<3}  {elapsed:6.2f}  {seg.type():<4}  {seg.seq_num:5d}  {len(seg.data):4d}\n' 

        self.logf.write(log_str)
        self.logf.flush()
        
        print(log_str, end='')
            
        

### Entry Code ### 
if (len(sys.argv) != 5):
    print(f"USAGE: python3 {sys.argv[0]} receiver_port sender_port txt_file_received max_win")
    exit()
receiver_port = int(sys.argv[1])
sender_port = int(sys.argv[2])
txt_file_to_receive = sys.argv[3]
max_win = int(sys.argv[4])

rcv_sock = socket(AF_INET, SOCK_DGRAM)
src_addr = ('127.0.0.1', receiver_port)
dest_addr = ('127.0.0.1', sender_port)
rcv_sock.bind(src_addr)

with open('receiver_log.txt', 'wt') as logf, open(txt_file_to_receive, 'wt') as textf:
    receiver = Receiver(textf, logf, max_win, rcv_sock, dest_addr)
    
    receiver.run()
    
    logf.write(f'Original data received:               {receiver.stats.original_bytes:6d}\n')
    logf.write(f'Total data received:                  {receiver.stats.tot_bytes:6d}\n')
    logf.write(f'Original segments received:           {receiver.stats.original_segs:6d}\n')
    logf.write(f'Total segments received:              {receiver.stats.tot_segs:6d}\n')
    logf.write(f'Corrupted segments discarded:          {receiver.stats.cor_segs:6d}\n')
    logf.write(f'Duplicate segments received:             {receiver.stats.dup_segs:6d}\n')
    logf.write(f'Total acks sent:          {receiver.stats.tot_acks:6d}\n')
    logf.write(f'Duplicate acks sent:         {receiver.stats.dup_acks:6d}\n')
