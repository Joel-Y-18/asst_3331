import random 
from socket import * 
import sys 
import _io 
import time
from common import * 
import threading 
from collections import deque 
from select import select

random.seed()
    
class Receiver:
    class StateControlBlock:
        def __init__(self):
            self.rcv_base = 0           # next expected byte
            self.state = 'closed' 
            self.buffer = deque()       # out of order segments. invariant: sequence numbers always > rcv_base
            self.lock = threading.Lock()
        
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
        self.msl = 1000
        self.scb = Receiver.StateControlBlock()
        self.stats = Receiver.Stats()
        self.BUFSZ = 2048
        self.time_start = None

    def run(self):
        self.scb.state = 'listen'

        seg = None
        while True:
            seg = self.recv()
            if seg.type() == 'SYN':        
                self.scb.rcv_base = wrap_add(seg.seq_num, 1)
                self.send(Segment.create(self.scb.rcv_base, 'ack'))
                self.scb.state = 'est'
            else:
                if self.scb.state == 'listen':
                    self.panic("initial segment was not a SYN. Aborting.")
                else:
                    break

        while True:
            if seg.type() == 'FIN':
                break
            elif seg.type() != 'DATA':
                self.panic(f"was expecting data segments; received {seg.type()}")
                
            self.process_data_segment(seg)
            self.send(Segment.create(self.scb.rcv_base, 'ack'))

            seg = self.recv()

        
        assert seg.type() == 'FIN'
        if seg.seq_num != self.scb.rcv_base:
            self.panic("fin has incorrect sequence number")

        self.send(Segment.create(wrap_add(seg.seq_num, 1), 'ack'))
        
        print('entering timed wait')
        self.scb.state = 'time_wait'
        threading.Timer(2*self.msl / 1000, self.close).start() #!! check this is actually 2s


        # without using nonblocking sockets the main thread 
        # may get stuck in a recv system call. The only way to kill
        # the program from the timer thread when this occurs is with a
        # hard kill (os._exit()), which we don't want. Hence, we use nonblocking
        # sockets 
        self.scb.acquire()
        while self.scb.state != 'closed':
            self.scb.release()

            read, write, error = select([self.sock], [], [], 0.001)
            if not read:
                self.scb.acquire()
                continue

            data, address = self.sock.recvfrom(self.BUFSZ, SOCK_NONBLOCK)
            seg = self._process_sock_output(data, address)
            if not seg:
                self.scb.acquire()
                continue

            if seg.type() != 'FIN':
                self.panic(f"expected a fin, received {seg.type()}")
            if seg.seq_num != self.scb.rcv_base:
                self.panic("fin has incorrect sequence number")

            self.send(Segment.create(wrap_add(seg.seq_num, 1), 'ack'))

            self.scb.acquire()

        self.scb.release()
          
        # at this point there is concurrency and we start using the scb lock
        # Does not work because may be stuck in recv. Instead timer thread forces exit
        # self.scb.acquire()
        # while self.scb.state != 'closed':
        #     self.scb.release()

        #     seg = self.recv()
        #     if seg.seq_num != self.scb.rcv_base:
        #         self.panic("fin has incorrect sequence number")
        #     self.send(Segment.create(wrap_add(seg.seq_num, 1), 'ack'))

        #     self.scb.acquire()

    def panic(self, message):
        print(f"ERROR: {message}")
        exit()
        
    def close(self):
        self.scb.acquire()
        self.scb.state = 'closed'
        self.scb.release()
        
    def process_data_segment(self, segment : Segment):
        assert segment.type() == 'DATA', f'process_data_segment called with non-data segment'
        
        if len(segment.data) == 0:
            print('dropping 0-length data packet')
            return
        if wrap_cmp(segment.seq_num, self.scb.rcv_base) == -1:
            # drop packets already received
            print('dropping packet beneath receive window')
            return
        if wrap_cmp(segment.end_seq_num(), wrap_add(self.scb.rcv_base, self.max_win)) == 1:
            # drop packets which are outside receive window
            print('dropping packet exceeding receive window')
            return

        if segment.seq_num == self.scb.rcv_base:
            self.scb.buffer.appendleft(segment)
            print(f'processing segment [{segment.seq_num, segment.end_seq_num()}) at rcvbase. {self._describe_buffer()}')
            while self.scb.buffer and self.scb.buffer[0].seq_num == self.scb.rcv_base:
                delivery = self.scb.buffer.popleft()
                self.scb.rcv_base = delivery.end_seq_num()
                self.deliver_segment(delivery)
            if self.scb.buffer and wrap_cmp(self.scb.rcv_base, self.scb.buffer[0].seq_num) == 1:
                self.panic(f'invalid segment sizes in buffer. rcv_base={self.scb.rcv_base}; {self._describe_buffer()}')
        else:
            insert_at_end = True
            for i in range(0, len(self.scb.buffer)):
                if self.scb.buffer[i].seq_num == segment.seq_num:
                    if (self.scb.buffer[i].end_seq_num() != segment.end_seq_num()):
                        self.panic(f'invalid duplicate segment [{segment.seq_num, segment.end_seq_num()}). {self._describe_buffer()}')

                    print('received duplicate out of order segment')
                    insert_at_end = False
                    break  
                elif wrap_cmp(self.scb.buffer[i].seq_num, segment.seq_num) == 1:
                    if (wrap_cmp(segment.end_seq_num(), self.scb.buffer[i].seq_num) == 1):
                        self.panic(f'invalid segment [{segment.seq_num, segment.end_seq_num()}) overlaps buffer segment. {self._describe_buffer()}')
                    self.scb.buffer.insert(i, segment)

                    print(f'inserting segment [{segment.seq_num, segment.end_seq_num()}) at position {i}. {self._describe_buffer()}')
                    insert_at_end = False
                    break

            if insert_at_end:
                self.scb.buffer.append(segment)
    
    def _describe_buffer(self):
        desc = 'Buffer: '
        for seg in self.scb.buffer:
            desc += f'[{seg.seq_num}, {seg.end_seq_num()}) '
        return desc 
    
    def deliver_segment(self, segment):
        self.textf.write(segment.data.decode('utf-8'))
        
    def send(self, segment : Segment):
        self._write_log('snd', 'ok', segment)
        self.sock.sendto(segment.encode(), self.dest_address)

    def recv(self):
        """Guarantees that the received segment is uncorrupted"""
        while True:
            data, address = self.sock.recvfrom(self.BUFSZ)
            seg = self._process_sock_output(data, address)
            if seg:
                return seg

            # if address != self.dest_address:
            #     print("WARNING: Received data from unexpected address")
            #     continue 

            # seg = Segment.decode(data)
            # if seg == None or not seg.validate():
            #     self._write_log('rcv', 'cor', seg)
            #     continue 

            # self._write_log('rcv', 'ok', seg)
            # return seg
    
    def _process_sock_output(self, data : bytes, address):
        if address != self.dest_address:
            print("WARNING: Received data from unexpected address")
            return None

        seg, no_cor = Segment.decode(data)
        if not no_cor:
            if seg != None:
                self._write_log('rcv', 'cor', seg)
            return None

        self._write_log('rcv', 'ok', seg)
        return seg

    def _write_log(self, type, action, seg):
        elapsed = 0.0
        if self.time_start == None:
            self.time_start = time.perf_counter_ns()
        else:
            elapsed = (time.perf_counter_ns() - self.time_start) / 1e6   #THIS MAKES INITIAL TIME NONZERO, DO IT PROPERLY
        
        log_str = f'{type}  {action:<3}  {elapsed:7.2f}  {seg.type():<4}  {seg.seq_num:5d}  {len(seg.data):4d}\n' 

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
    
    logf.write(f'Original data received:        {receiver.stats.original_bytes:6d}\n')
    logf.write(f'Total data received:           {receiver.stats.tot_bytes:6d}\n')
    logf.write(f'Original segments received:    {receiver.stats.original_segs:6d}\n')
    logf.write(f'Total segments received:       {receiver.stats.tot_segs:6d}\n')
    logf.write(f'Corrupted segments discarded   {receiver.stats.cor_segs:6d}\n')
    logf.write(f'Duplicate segments received:   {receiver.stats.dup_segs:6d}\n')
    logf.write(f'Total acks sent:               {receiver.stats.tot_acks:6d}\n')
    logf.write(f'Duplicate acks sent:           {receiver.stats.dup_acks:6d}\n')
