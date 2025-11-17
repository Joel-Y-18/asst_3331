import random 
from socket import * 
import sys 
import _io 
import time
from common import * 
import threading 
from collections import deque 

random.seed()
verbose = False

class PLCModule:
    """
    Performs packet loss and corruption
    """
    class Stats:
        """
        Tracks PLC stats
        """
        def __init__(self):
            self.fwd_drp = 0
            self.fwd_cor = 0
            self.rev_drp = 0
            self.rev_cor = 0

    def __init__(self, socket : socket, address, 
                flp, rlp, fcp, rcp, logf : _io.TextIOWrapper, header_sz = 4):
        # socket details
        self.socket = socket
        self.address = address
        
        # loss probabilities
        self.flp = flp 
        self.rlp = rlp 
        self.fcp = fcp
        self.rcp = rcp 
        
        # logging details and statistics
        self.time_start = None
        self.logf = logf
        self.stats = PLCModule.Stats()
        
        # constants
        self.HEADER_SZ = header_sz
        self.BUFSZ = 2048
        
        self.lock = threading.Lock()
    
    def send(self, seg : Segment): 
        """
        Sends a segment. 
        """

        self.lock.acquire()
        
        # drop with flp probability
        if self._flip(self.flp):
            self._write_log('snd', 'drp', seg)
            self.stats.fwd_drp += 1
            self.lock.release()
            return

        data = seg.encode()

        # corrupt with fcp probability
        if self._flip(self.fcp):
            self._write_log('snd', 'cor', seg)
            self.stats.fwd_cor += 1
            self.socket.sendto(self._corrupt(data), self.address)
        else:
            self._write_log('snd', 'ok', seg)
            self.socket.sendto(data, self.address)
            
        self.lock.release()

    def recv(self):
        data = None
        while True:
            data, incoming_address = self.socket.recvfrom(self.BUFSZ)
            if incoming_address != self.address:
                print(f"WARNING: Received data from unexpected address {incoming_address}")
                continue
            
            # parse segment
            seg, no_cor = Segment.decode(data)
            assert no_cor, "checksum was corrupted by transfer through localhost" 

            # drop with rlp probability
            if self._flip(self.rlp):
                if seg != None: 
                    self._write_log('rcv', 'drp', seg)
                self.stats.rev_drp += 1
                continue

            # corrupt with rcp probability
            if self._flip(self.rcp):
                self._write_log('rcv', 'cor', seg)
                self.stats.rev_cor += 1

                corrupted_data = self._corrupt(data)

                # ensure corruption worked
                if Segment.decode(corrupted_data)[1]:
                    print("WARNING: corruption failed to alter checksum")

                return corrupted_data
            else:
                self._write_log('rcv', 'ok', seg)
                return data
    
    def _write_log(self, type, action, seg):
        """
        Helper function to write to a log
        """
        
        # measure time
        elapsed = None
        if self.time_start == None:
            self.time_start = time.perf_counter_ns()
            elapsed = 0.0
        else:
            elapsed = (time.perf_counter_ns() - self.time_start) / 1e6
        
        # write to log
        log_str = f'{type}  {action:<3}  {elapsed:7.2f}  {seg.type():<4}  {seg.seq_num:5d}  {len(seg.data):4d}\n' 
        self.logf.write(log_str)
        self.logf.flush()
        
        print(log_str, end='')
        
    def _corrupt(self, data : bytes):
        """
        Flips 1 bit in a byte sequence
        """
        assert len(data) > self.HEADER_SZ, f"Tried to corrupt header-only data"
        corruption_idx = random.randrange(self.HEADER_SZ, len(data))
        corruption_bit = random.randrange(0, 8)
        
        if verbose: 
            print("Initial data:   " 
              + '_'.join(bin(x)[2:].zfill(8) for x in data) 
              + f" will be corrupted at "
              + f"{corruption_idx*8+corruption_bit}={corruption_idx,corruption_bit}")

        corrupted = data[:corruption_idx] \
                    + bytes((data[corruption_idx] ^ (1 << (7-corruption_bit)),)) \
                    + data[corruption_idx+1:]

        if verbose: 
            print("Corrupted data: " 
                  + '_'.join(bin(x)[2:].zfill(8) for x in corrupted))

        return corrupted
    
    def _flip(self, probability):
        """
        Simulates a Bernoulli RV
        """
        return random.random() < probability 
    
class Sender:
    """
    URP Sender
    """
    class StateControlBlock:
        """
        Sender state control
        """
        def __init__(self):
            # first unacked sequence number
            self.snd_base = 0
            
            # first unsent sequence number
            self.next_seqnum = 0
            
            # triple dup ack counter
            self.dup_acks = 0
            
            # retransmission queue
            # - invariant 1: all bytes [snd_base, next_seqnum) are in queue
            # - All segments should be of nonzero length
            self.unacked_queue = deque()

            self.state = 'closed' 
            self.lock = threading.Lock()
        
        def acquire(self):
            self.lock.acquire()

        def release(self):
            self.lock.release()
            
    class Stats:
        """
        Sender statistics
        """
        def __init__(self):
            self.original_bytes_sent = 0
            self.total_bytes_sent = 0
            self.original_segs_sent = 0
            self.total_segs_sent = 0
            self.timeouts = 0
            self.fast_retransmissions = 0
            self.dup_acks = 0
            self.cor_acks = 0
            
            # lock is only used for total_segs and total_bytes_sent, since
            # only these are accessed from multiple threads
            self.lock = threading.Lock()

        def acquire(self):
            self.lock.acquire()

        def release(self):
            self.lock.release()

    def __init__(self, textf : _io.TextIOWrapper, 
                 max_win, rto, plc : PLCModule):
        # text file to read from
        self.textf = textf
        self.plc = plc

        # transmission parameters
        self.max_win = max_win
        self.rto = rto 
        self.mss = 1000

        self.scb = Sender.StateControlBlock()
        self.stats = Sender.Stats()

        # retransmission variables
        self.rttimer = None
        self.rtlock = threading.Lock()

        # initial sequence number variables
        self.isn = random.randrange(0, SEQ_NUM_SPACE)
        self.scb.snd_base = self.isn
        self.scb.next_seqnum = self.scb.snd_base

    def run(self):
        """
        Main function to execute the sender 
        """

        self.scb.acquire()
        self.scb.state = 'syn_sent'
        self.scb.release()
        
        # initiate connection
        self.stop_wait_exchange(Segment.create(self.scb.snd_base, 'syn'))

        self.scb.acquire()
        self.scb.state = 'est'
        self.scb.release()
        
        print('Passed stop-wait')

        # Note: we do not multithread sending and receiving acks. Rather,
        # we first send out our entire window, then listen for an ack.
        # There is little advantage to multithreading here since transmission
        # is blocked until the next ack is received and the window moves
        self.scb.acquire()
        while self.scb.state != 'fin_wait':
            if self.scb.state == 'est':
                self.scb.release()
                self.transmit_window()
            else:
                self.scb.release()

            ack = self.recv()
            self.handle_ack(ack.seq_num)
            self.scb.acquire()
        self.scb.release()

        # finalise by exchanging fin segments
        self.stop_wait_exchange(Segment.create(self.scb.snd_base, 'fin'))
        
        self.scb.acquire()
        self.scb.state = 'closed'
        self.scb.release()
    
    
    def stop_wait_exchange(self, seg):
        """
        Executes a stop-wait exchange which bypasses the unacked queue 
        and uses a special retransmission system.
        Intended for special one-byte segments (SYN and FIN)
        """

        self.stats.original_segs_sent += 1
        self.send(seg)
        self._set_stop_wait_rttimer(seg)
        
        # loop waiting for the ack
        while self.recv().seq_num != wrap_add(seg.seq_num, 1):
            print(f"Failed to match to {wrap_add(seg.seq_num, 1)}")
            pass
        
        self._stop_rttimer()

        # update the control block
        self.scb.acquire()
        assert self.scb.snd_base == seg.seq_num, \
            f'scb.send_base and seqnum do not match in a stop-wait exchange'
        assert self.scb.next_seqnum == seg.seq_num, \
            f'scb.next_seqnum and seqnum do not match in a stop-wait exchange'

        self.scb.snd_base = wrap_add(self.scb.snd_base, 1)
        self.scb.next_seqnum = wrap_add(self.scb.next_seqnum, 1)
        self.scb.release()
        
    def _stop_rttimer(self):
        self.rtlock.acquire()
        if self.rttimer != None:
            self.rttimer.cancel()
        self.rtlock.release()
    
    def _set_stop_wait_rttimer(self, seg):
        print(f'_set_stop_wait_rttimer called with rto {self.rto}')
        
        self.rtlock.acquire()
        if self.rttimer != None:
            self.rttimer.cancel()
        self.rttimer = threading.Timer(self.rto / 1000, self.stop_wait_timeout, (seg,))
        self.rttimer.start()
        self.rtlock.release()

    def stop_wait_timeout(self, seg):
        print('stop_wait_timeout called')
        self.stats.timeouts += 1
        self._set_stop_wait_rttimer(seg)
        self.send(seg)
    
    def transmit_window(self):
        """
        Transmits all available window segments. 
        """
        self.scb.acquire()
        while wrap_cmp(self.scb.next_seqnum, 
                       wrap_add(self.scb.snd_base, self.max_win)) == -1:
            window_bytes_remaining = wrap_sub(
                wrap_add(self.scb.snd_base, self.max_win), self.scb.next_seqnum)
            nbytes = min(self.mss, window_bytes_remaining)

            self.scb.release()
            data = self.textf.read(nbytes)
            self.scb.acquire()

            if len(data) == 0:
                self.scb.state = 'closing'
                break
            else:
                seg = Segment.create(self.scb.next_seqnum, 'data', data.encode())
                self.scb.next_seqnum = wrap_add(self.scb.next_seqnum, len(data))

                self.scb.unacked_queue.append(seg)
                if len(self.scb.unacked_queue) == 1:
                    # If the queue was previously empty we need to start 
                    # the retransmission timer afresh
                    self._set_rttimer()

                self.scb.release()
                self.stats.original_segs_sent += 1
                self.stats.original_bytes_sent += len(seg.data)
                self.send(seg)
                self.scb.acquire()

        self.scb.release()

    def handle_ack(self, ack_seq_num):
        """
        Logic for processing an incoming ack
        """
        
        self.scb.acquire()

        # compare to current base
        if wrap_cmp(ack_seq_num, self.scb.snd_base) == -1:
            # ack was below current window base. Should not occur
            print("WARNING: ack below window base received")
            self.scb.release()
            return 
        if wrap_cmp(ack_seq_num, self.scb.next_seqnum) == 1:
            # ack is greater than any segment we've sent.
            print("WARNING: ack above window base received")
            self.scb.release()
            return 
        if ack_seq_num == self.scb.snd_base:
            # duplicate ack received
            print(f"Dup ack received for seq num {self.scb.snd_base}")
            self.stats.dup_acks += 1
            self.scb.dup_acks += 1
            if self.scb.dup_acks == 3:
                self.scb.release()
                self.triple_dup_ack()
            else:
                self.scb.release()
            return 
        
        # Check that self.scb.snd_base < ack_seq_num <= self.scb.next_seqnum
        assert wrap_cmp(self.scb.snd_base, ack_seq_num) == -1 \
               and wrap_cmp(ack_seq_num, self.scb.next_seqnum) <= 0, \
               f'ack_seq_num invariants failed'

        # this is a cumulative ack; pop any segments with endpoint before the ack
        while (
            self.scb.unacked_queue
            and wrap_cmp(self.scb.unacked_queue[0].end_seq_num(), ack_seq_num) <= 0
        ): 
            self.scb.unacked_queue.popleft()

        self.scb.snd_base = ack_seq_num
        self.scb.dup_acks = 0

        if self.scb.snd_base == self.scb.next_seqnum:
            assert not self.scb.unacked_queue, f'Queue invariants failed'
            self._stop_rttimer()
            if self.scb.state == 'closing':
                # all data segments have been acked
                self.scb.state = 'fin_wait'
        else:
            assert self.scb.unacked_queue, f'Queue invariants failed'
            seg : Segment = self.scb.unacked_queue[0]
            
            # trim current segment if ack does not fall neatly on a segment line. 
            # This should never be necessary in our protocol, but is added for generality
            trim_len = wrap_sub(ack_seq_num, seg.seq_num)
            if trim_len != 0:
                print(f'Trimming segment [{seg.seq_num}, {seg.end_seq_num()})'
                      f' due to ack {ack_seq_num}.'
                      f'{trim_len} data bytes are being trimmed')
                seg.data = seg.data[trim_len:]
                seg.seq_num = ack_seq_num

            self._set_rttimer()
            
        self.scb.release()

    def triple_dup_ack(self):
        """
        Retransmits on triple duplicate ack
        """
        print('triple_dup_ack called')
        if self.retransmit():
            self.stats.fast_retransmissions += 1

    def timeout(self):
        """
        Retransmits on timeout
        """
        if self.retransmit():
            self.stats.timeouts += 1

    def retransmit(self):
        """
        Retransmits first unacked segment.

        Returns whether retransmission was successful 
        """
        self.scb.acquire()

        # reset timer and dup ack count
        self._set_rttimer()
        self.scb.dup_acks = 0

        # get the segment to retransmit. May be None (rarely) if ack arrives
        # and clears queue just before the timer is called
        seg = None
        if self.scb.unacked_queue:
            seg = self.scb.unacked_queue[0]

        self.scb.release()

        if seg:
            self.send(seg)
            return True 
        else:
            return False

        
    def _set_rttimer(self):
        self.rtlock.acquire()
        if self.rttimer != None:
            self.rttimer.cancel()
        self.rttimer = threading.Timer(self.rto / 1000, self.timeout)
        self.rttimer.start()
        self.rtlock.release()

    def send(self, segment : Segment):
        """
        Sends a segment
        """
        
        # send may be called from a timer, so we need to take a lock
        self.stats.acquire()
        self.stats.total_segs_sent += 1
        self.stats.total_bytes_sent += len(segment.data)
        self.stats.release()
        plc.send(segment)

    def recv(self):
        """
        Receives a segment.

        Guarantees that the received segment is uncorrupted and is an ack. If it
        not an ack, an error is thrown 
        """
        while True:
            data = plc.recv()
            
            # check for corruption
            seg, no_cor = Segment.decode(data)
            if not no_cor:
                self.stats.cor_acks += 1
                continue

            # under normal operation the receiver should only send acks
            if (seg.type() != 'ACK'):
                raise RuntimeError(f'Unexpected segment type {seg.type()} received')
            
            return seg
        

### Entry Code ### 

# parse arguments
if (len(sys.argv) != 10):
    print(f"USAGE: python3 {sys.argv[0]} sender_port "
          f"receiver_port txt_file_to_send max_win rto flp rlp fcp rcp")
    exit()
sender_port = int(sys.argv[1])
receiver_port = int(sys.argv[2])
txt_file_to_send = sys.argv[3]
max_win = int(sys.argv[4])
rto = int(sys.argv[5])
flp = float(sys.argv[6])
rlp = float(sys.argv[7])
fcp = float(sys.argv[8])
rcp = float(sys.argv[9])

# initialise sockets
sender_sock = socket(AF_INET, SOCK_DGRAM)
src_addr = ('127.0.0.1', sender_port)
dest_addr = ('127.0.0.1', receiver_port)
sender_sock.bind(src_addr)

with open('sender_log.txt', 'wt') as logf, open(txt_file_to_send, 'r') as textf:
    # init PLC module
    plc = PLCModule(sender_sock, dest_addr, flp, rlp, fcp, rcp, logf)
    
    # run sender
    sender = Sender(textf, max_win, rto, plc)
    sender.run()
    
    # write to log
    logf.write(f'Original data sent:            {sender.stats.original_bytes_sent:6d}\n')
    logf.write(f'Total data sent:               {sender.stats.total_bytes_sent:6d}\n')
    logf.write(f'Original segments sent:        {sender.stats.original_segs_sent:6d}\n')
    logf.write(f'Total segments sent:           {sender.stats.total_segs_sent:6d}\n')
    logf.write(f'Timeout retransmissions:       {sender.stats.timeouts:6d}\n')
    logf.write(f'Fast retransmissions:          {sender.stats.fast_retransmissions:6d}\n')
    logf.write(f'Duplicate acks received:       {sender.stats.dup_acks:6d}\n')
    logf.write(f'Corrupted acks discarded:      {sender.stats.cor_acks:6d}\n')
    logf.write(f'PLC forward segments dropped:  {plc.stats.fwd_drp:6d}\n')
    logf.write(f'PLC forward segments corrupted:{plc.stats.fwd_cor:6d}\n')
    logf.write(f'PLC reverse segments dropped:  {plc.stats.rev_drp:6d}\n')
    logf.write(f'PLC reverse segments corrupted:{plc.stats.rev_cor:6d}\n')
