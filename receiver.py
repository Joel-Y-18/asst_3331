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
    """
    URP Receiver
    """
    class StateControlBlock:
        """
        Class to hold receiver state 
        """
        def __init__(self):
            # next expected byte
            self.rcv_base = 0          

            # buffer to hold out of order segments.
            # - Invariant: sequence numbers of packets in buffer always 
            #   greater than self.rcv_base
            self.buffer = deque() 

            self.state = 'closed' 
            self.lock = threading.Lock()
        
        def acquire(self):
            """
            Locks the control block 
            """
            self.lock.acquire()

        def release(self):
            """
            Releases the control block 
            """
            self.lock.release()

    class Stats:
        """
        Container for Receiver statistics
        """
        def __init__(self):
            self.original_bytes = 0
            self.tot_bytes = 0
            self.original_segs = 0
            self.tot_segs = 0
            self.cor_segs = 0
            self.dup_segs = 0
            self.tot_acks = 0
            self.dup_acks = 0
            self._last_ack_num = None
            
    def __init__(self, textf : _io.TextIOWrapper, 
                 logf : _io.TextIOWrapper, max_win, sock : socket, dest_address):
        self.textf = textf
        self.logf = logf
        
        self.max_win = max_win
        self.sock = sock
        self.dest_address = dest_address

        # maximum segment lifetime (milliseconds)
        self.MSL = 1000
        
        # maximum message size
        self.BUFSZ = 2048 

        # statistics, timing and state control block
        self.scb = Receiver.StateControlBlock()
        self.stats = Receiver.Stats()
        self.time_start = None

    def run(self):
        """
        Driver code for the receiver 
        """
        self.scb.state = 'listen'

        # perform stop-wait SYN-ACK exchange
        seg = None
        while True:
            seg = self.recv()
            if seg.type() == 'SYN':        
                self.scb.rcv_base = wrap_add(seg.seq_num, 1)
                self.send(Segment.create(self.scb.rcv_base, 'ack'))
                
                # check if this is the first SYN we received
                if self.scb.state != 'est':
                    self.scb.state = 'est'
                    self.stats.original_segs += 1
            else:
                if self.scb.state == 'listen':
                    self.panic("initial segment was not a SYN. Aborting.")
                else:
                    # SYN-ACK exchange has been completed
                    break

        # enter data receive loop until FIN
        while True:
            if seg.type() == 'FIN':
                break
            elif seg.type() != 'DATA':
                self.panic(f"was expecting data segments; received {seg.type()}")
            self.process_data_segment(seg)
            self.send(Segment.create(self.scb.rcv_base, 'ack'))
            seg = self.recv()

        assert seg.type() == 'FIN'
        
        # sender should only transmit a FIN when all data has been acknowledged
        if seg.seq_num != self.scb.rcv_base:
            self.panic("fin has incorrect sequence number")

        # register and acknowledge the FIN
        self.stats.original_segs += 1
        self.send(Segment.create(wrap_add(seg.seq_num, 1), 'ack'))
        
        # initiate timed wait state
        print('entering timed wait')
        self.scb.state = 'time_wait'
        wait_timer = threading.Timer(2*self.MSL / 1000, self.close)
        wait_timer.start()
        

        self.scb.acquire()
        while self.scb.state != 'closed':
            self.scb.release()

            # we use nonblocking sockets, so that the main thread
            # never gest stuck in a recv syscall
            read, write, error = select([self.sock], [], [], 0.001)
            if not read:
                self.scb.acquire()
                continue

            data, address = self.sock.recvfrom(self.BUFSZ, SOCK_NONBLOCK)
            seg = self._process_sock_output(data, address)
            if not seg:
                self.scb.acquire()
                continue

            # check that this is the same FIN as the original and send ACK
            if seg.type() != 'FIN':
                self.panic(f"expected a fin, received {seg.type()}")
            if seg.seq_num != self.scb.rcv_base:
                self.panic("fin has incorrect sequence number")
            self.send(Segment.create(wrap_add(seg.seq_num, 1), 'ack'))

            # restart timer. There is a possible race here but it is 
            # extremely unlikely and has no ill effects
            wait_timer.cancel()
            wait_timer = threading.Timer(2*self.MSL / 1000, self.close)
            wait_timer.start()

            self.scb.acquire()
        self.scb.release()

    def panic(self, message):
        """
        Print error and exit 
        """
        print(f"ERROR: {message}")
        exit()
        
    def close(self):
        self.scb.acquire()
        self.scb.state = 'closed'
        self.scb.release()
        
    def process_data_segment(self, segment : Segment):
        """
        Handle an incoming data segment 
        """

        assert segment.type() == 'DATA', \
            f'process_data_segment called with non-data segment'
        
        if len(segment.data) == 0:
            # packet is nonsensical
            print('dropping 0-length data packet')
            return
        if wrap_cmp(segment.seq_num, self.scb.rcv_base) == -1:
            # packet has already been received
            print('dropping packet beneath receive window')
            self.stats.dup_segs += 1
            return
        if wrap_cmp(segment.end_seq_num(), 
                wrap_add(self.scb.rcv_base, self.max_win)) == 1:
            # sender's receive window must be bigger than ours; drop packet
            print('dropping packet exceeding receive window')
            return

        if segment.seq_num == self.scb.rcv_base:
            # in order packet has arrived

            # log stats and add packet to buffer
            self.stats.original_segs += 1
            self.stats.original_bytes += len(segment.data)
            self.scb.buffer.appendleft(segment)
            print(f'processing segment [{segment.seq_num, segment.end_seq_num()})'
                  f' at rcvbase. {self._describe_buffer()}')
            
            # pop in-order packets from buffer, updating rcv_base
            while (
                self.scb.buffer
                and self.scb.buffer[0].seq_num == self.scb.rcv_base
            ):
                delivery = self.scb.buffer.popleft()
                self.scb.rcv_base = delivery.end_seq_num()
                self.deliver_segment(delivery)
            
            # check invariant that buffer should have only out of order
            # segments before our rcv_base
            if (
                self.scb.buffer 
                and wrap_cmp(self.scb.rcv_base, self.scb.buffer[0].seq_num) == 1
            ):
                self.panic(f'invalid segment sizes in buffer. '
                           f'rcv_base={self.scb.rcv_base}; {self._describe_buffer()}')
        else:
            insert_at_end = True
            for i in range(0, len(self.scb.buffer)):
                if self.scb.buffer[i].seq_num == segment.seq_num:
                    # this is a duplicate segment

                    # check segment is of same size as before
                    if (self.scb.buffer[i].end_seq_num() != segment.end_seq_num()):
                        self.panic(f'invalid duplicate segment '
                                   f'[{segment.seq_num, segment.end_seq_num()}). '
                                   f'{self._describe_buffer()}')

                    print('received duplicate out of order segment')
                    self.stats.dup_segs += 1
                    insert_at_end = False
                    break  
                elif wrap_cmp(self.scb.buffer[i].seq_num, segment.seq_num) == 1:
                    # the start of the segment just received is below the 
                    # start of the segment we are currently examining

                    # check that segment does not overlap the one we are currently examining
                    if (wrap_cmp(segment.end_seq_num(), self.scb.buffer[i].seq_num) == 1):
                        self.panic(f'invalid segment '
                                   f'[{segment.seq_num, segment.end_seq_num()})'
                                   f' overlaps buffer segment. {self._describe_buffer()}')
                    
                    # this is a new segment; insert it into buffer
                    self.scb.buffer.insert(i, segment)
                    print(f'inserting segment [{segment.seq_num, segment.end_seq_num()}) at position {i}. {self._describe_buffer()}')
                    self.stats.original_segs += 1
                    self.stats.original_bytes += len(segment.data)
                    insert_at_end = False
                    break

            if insert_at_end:
                self.stats.original_segs += 1
                self.stats.original_bytes += len(segment.data)
                self.scb.buffer.append(segment)
    
    def _describe_buffer(self):
        """
        Helper function for describing current buffer state
        """
        desc = 'Buffer: '
        for seg in self.scb.buffer:
            desc += f'[{seg.seq_num}, {seg.end_seq_num()}) '
        return desc 
    
    def deliver_segment(self, segment):
        """
        Writes segment to output file
        """
        self.textf.write(segment.data.decode('utf-8'))
        
    def send(self, segment : Segment):
        """
        Sends a segment
        """
        
        # update stats
        self.stats.tot_acks += 1
        if self.stats._last_ack_num and self.stats._last_ack_num == segment.seq_num:
            self.stats.dup_acks += 1
        self.stats._last_ack_num = segment.seq_num 

        # send and log
        self._write_log('snd', 'ok', segment)
        self.sock.sendto(segment.encode(), self.dest_address)

    def recv(self):
        """
        Receives a segment. 
        Guarantees that the received segment is uncorrupted; any 
        corrupted segments are discarded
        """
        while True:
            data, address = self.sock.recvfrom(self.BUFSZ)
            seg = self._process_sock_output(data, address)
            if seg:
                return seg
    
    def _process_sock_output(self, data : bytes, address):
        """
        Processes raw data received from a socket into a segment  
        """
        if address != self.dest_address:
            print("WARNING: Received data from unexpected address")
            return None

        seg, no_cor = Segment.decode(data)
        self.stats.tot_segs += 1
        
        if not no_cor:
            self.stats.cor_segs += 1
            if seg != None:
                # the segment header is not corrupted
                self._write_log('rcv', 'cor', seg)
            return None

        self.stats.tot_bytes += len(seg.data)
        self._write_log('rcv', 'ok', seg)
        return seg

    def _write_log(self, type, action, seg):
        """
        Helper function to write a log entry
        """
        
        # get time elapsed since start
        elapsed = 0.0
        if self.time_start == None:
            self.time_start = time.perf_counter_ns()
        else:
            elapsed = (time.perf_counter_ns() - self.time_start) / 1e6
        
        log_str = f'{type}  {action:<3}  {elapsed:7.2f}  {seg.type():<4}  {seg.seq_num:5d}  {len(seg.data):4d}\n' 

        self.logf.write(log_str)
        self.logf.flush()
        
        print(log_str, end='')
            
        

### Entry Code ### 

# parse arguments
if (len(sys.argv) != 5):
    print(f"USAGE: python3 {sys.argv[0]} "
          f"receiver_port sender_port txt_file_received max_win")
    exit()
receiver_port = int(sys.argv[1])
sender_port = int(sys.argv[2])
txt_file_to_receive = sys.argv[3]
max_win = int(sys.argv[4])

# socket creation
rcv_sock = socket(AF_INET, SOCK_DGRAM)
src_addr = ('127.0.0.1', receiver_port)
dest_addr = ('127.0.0.1', sender_port)
rcv_sock.bind(src_addr)

with open('receiver_log.txt', 'wt') as logf, open(txt_file_to_receive, 'wt') as textf:
    # run receiver
    receiver = Receiver(textf, logf, max_win, rcv_sock, dest_addr)
    receiver.run()
    
    # write stats
    logf.write(f'Original data received:        {receiver.stats.original_bytes:6d}\n')
    logf.write(f'Total data received:           {receiver.stats.tot_bytes:6d}\n')
    logf.write(f'Original segments received:    {receiver.stats.original_segs:6d}\n')
    logf.write(f'Total segments received:       {receiver.stats.tot_segs:6d}\n')
    logf.write(f'Corrupted segments discarded:  {receiver.stats.cor_segs:6d}\n')
    logf.write(f'Duplicate segments received:   {receiver.stats.dup_segs:6d}\n')
    logf.write(f'Total acks sent:               {receiver.stats.tot_acks:6d}\n')
    logf.write(f'Duplicate acks sent:           {receiver.stats.dup_acks:6d}\n')
