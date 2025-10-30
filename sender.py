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
    class Stats:
        def __init__(self):
            self.fwd_drp = 0
            self.fwd_cor = 0
            self.rev_drp = 0
            self.rev_cor = 0

    def __init__(self, socket : socket, address, flp, rlp, fcp, rcp, logf : _io.TextIOWrapper, header_sz = 4):
        self.socket = socket
        self.address = address
        self.flp = flp 
        self.rlp = rlp 
        self.fcp = fcp
        self.rcp = rcp 
        self.time_start = None
        self.logf = logf
        self.stats = PLCModule.Stats()
        self.HEADER_SZ = header_sz
        self.BUFSZ = 2048
    
    def send(self, seg : Segment): 
        if self.time_start == None:
            self.time_start = time.perf_counter_ns()
        
        if self._flip(self.flp):
            self._write_log('snd', 'drp', seg)
            self.stats.fwd_drp += 1
            return

        data = seg.encode()

        if self._flip(self.fcp):
            self._write_log('snd', 'cor', seg)
            self.stats.fwd_cor += 1
            self.socket.sendto(self._corrupt(data), self.address)
        else:
            self._write_log('snd', 'ok', seg)
            self.socket.sendto(data, self.address)

    def recv(self):
        data = None
        while True:
            data, incoming_address = self.socket.recvfrom(self.BUFSZ)
            if incoming_address != self.address:
                print(f"WARNING: Received data from unexpected address {incoming_address}")
                continue
            
            if self._flip(self.rlp):

                self._write_log('rcv', 'drp', Segment.decode(data))  #CAREFUL, THE SEGMENT MAY BE CORRUPTED HERE
                self.stats.rev_drp += 1
            else:
                break 

        if self._flip(self.rcp):
            corrupted_seg = Segment.decode(self._corrupt(data))
            self._write_log('rcv', 'cor', Segment.decode(data))
            self.stats.rev_cor += 1
            return corrupted_seg

        seg = Segment.decode(data)
        self._write_log('rcv', 'ok', seg)
        return seg
    
    def _write_log(self, type, action, seg):
        elapsed = 0.0
        if self.time_start == None:
            raise RuntimeError('tried to log with start time None')
        else:
            elapsed = (time.perf_counter_ns() - self.time_start) / 1e6
        
        log_str = f'{type}  {action:<3}  {elapsed:6.2f}  {seg.type():<4}  {seg.seq_num:5d}  {len(seg.data):4d}\n' 
        self.logf.write(log_str)
        self.logf.flush()
        
        print(log_str, end='')
        
    def _corrupt(self, data : bytes):
        assert len(data) > self.HEADER_SZ, f"Tried to corrupt header-only data"
        corruption_idx = random.randrange(self.HEADER_SZ, len(data))
        corruption_bit = random.randrange(0, 8)
        
        if verbose: print("Initial data:   " + '_'.join(bin(x)[2:].zfill(8) for x in data) + f" will be corrupted at {corruption_idx*8+corruption_bit}={corruption_idx,corruption_bit}")
        corrupted = data[:corruption_idx] + bytes((data[corruption_idx] ^ (1 << (7-corruption_bit)),)) + data[corruption_idx+1:]
        if verbose: print("Corrupted data: " + '_'.join(bin(x)[2:].zfill(8) for x in corrupted))

        return corrupted
    
    def _flip(self, probability):
        return random.random() < probability 
    
class Sender:
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
            self.original_bytes_sent = 0
            self.total_bytes_sent = 0
            self.original_segs_sent = 0
            self.total_segs_sent = 0
            self.timeouts = 0
            self.fast_retransmissions = 0
            self.dup_acks = 0
            self.cor_acks = 0

    def __init__(self, textf : _io.TextIOWrapper, max_win, rto, plc : PLCModule, mss = 1000):
        self.textf = textf
        self.max_win = max_win
        self.rto = rto 
        self.plc = plc
        self.scb = Sender.StateControlBlock()
        self.stats = Sender.Stats()
        self.mss = 1000

        self.rttimer = None
        self.rtlock = threading.Lock()

        self.isn = random.randrange(0, SEQ_NUM_SPACE)
        self.scb.snd_base = self.isn
        self.scb.next_seqnum = self.scb.snd_base

    def run(self):
        self.scb.acquire()
        self.scb.state = 'syn_sent'
        self.scb.release()
        
        self.stop_wait_exchange(Segment.create(self.scb.snd_base, 'syn'))

        self.scb.acquire()
        self.scb.state = 'est'
        self.scb.release()
        
        print('Passed stop-wait')

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

        # finalise
        self.stop_wait_exchange(Segment.create(self.scb.snd_base, 'fin'))
        
        self.scb.acquire()
        self.scb.state = 'closed'
        self.scb.release()
    
    
    def stop_wait_exchange(self, seg):
        """A custom stop-wait exchange which bypasses the unacked queue and uses a special retransmission system
        Intended for special one-byte segments (SYN and FIN)"""

        self.send(seg)
        self._set_stop_wait_rttimer(seg)
        

        while self.recv().seq_num != wrap_add(seg.seq_num, 1):
            print(f"Failed to match to {wrap_add(seg.seq_num, 1)}")
            pass
        
        self._stop_rttimer()

        self.scb.acquire()
        assert self.scb.snd_base == seg.seq_num, f'scb.send_base and seqnum do not match in a stop-wait exchange'
        assert self.scb.next_seqnum == seg.seq_num, f'scb.next_seqnum and seqnum do not match in a stop-wait exchange'

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
        self._set_stop_wait_rttimer(seg)
        self.send(seg)
    
    def transmit_window(self):
        self.scb.acquire()
        while wrap_cmp(self.scb.next_seqnum, wrap_add(self.scb.snd_base, self.max_win)) == -1:
            window_bytes_remaining = wrap_sub(wrap_add(self.scb.snd_base, self.max_win), self.scb.next_seqnum) # IS IT CERTAIN THAT THESE WRAP FUNCTIONS ARE CORRECT
            nbytes = max(self.mss, window_bytes_remaining)

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
                if len(self.scb.unacked_queue) == 1: # this is the first unacked segment
                    self._set_rttimer()

                self.scb.release()
                self.send(seg)
                self.scb.acquire()

        self.scb.release()

    def handle_ack(self, ack_seq_num):
        self.scb.acquire()

        if wrap_cmp(ack_seq_num, self.scb.snd_base) == -1: #!NEED TO WRAP
            print("NOTE: ack below window base received")
            self.scb.release()
            return 
        if wrap_cmp(ack_seq_num, self.scb.next_seqnum) == 1:
            print("WARNING: ack above window base received")
            self.scb.release()
            return 
        if ack_seq_num == self.scb.snd_base:
            print(f"Dup ack received for seq num {self.scb.snd_base}")
            self.scb.dup_acks += 1
            if self.scb.dup_acks == 3:
                self.scb.release()
                self.triple_dup_ack()
            else:
                self.scb.release()
            return 
        
        # We now have self.scb.snd_base < ack_seq_num <= self.scb.next_seqnum
        while self.scb.unacked_queue and wrap_cmp(self.scb.unacked_queue[0].end_seq_num(), ack_seq_num) <= 0: 
            self.scb.unacked_queue.popleft()

        # trim current segment
        self.scb.snd_base = ack_seq_num
        self.scb.dup_acks = 0

        if self.scb.snd_base == self.scb.next_seqnum:
            assert not self.scb.unacked_queue, f'Queue invariants failed'
            self._stop_rttimer()
            if self.scb.state == 'closing':
                self.scb.state = 'fin_wait'
        else:
            assert self.scb.unacked_queue, f'Queue invariants failed'
            seg : Segment = self.scb.unacked_queue[0]
            
            print('Trimming segment')
            trim_len = wrap_sub(ack_seq_num, seg.seq_num)
            if trim_len != 0:
                print(f'{trim_len} data bytes are being trimmed')
                seg.data = seg.data[trim_len:]
                seg.seq_num = ack_seq_num
                seg.generate_checksum()

            self._set_rttimer()
            
        self.scb.release()

    def triple_dup_ack(self):
        print('triple_dup_ack called')
        self.stats.fast_retransmissions += 1
        self.retransmit() 

    def timeout(self):
        self.stats.timeouts += 1
        self.retransmit()

    def retransmit(self):
        self.scb.acquire()

        self._set_rttimer()

        self.scb.dup_acks = 0
        seg = self.scb.unacked_queue[0]

        self.scb.release()

        self.send(seg)

        
    def _set_rttimer(self):
        self.rtlock.acquire()
        if self.rttimer != None:
            self.rttimer.cancel()
        self.rttimer = threading.Timer(self.rto / 1000, self.timeout) # will this work? Also is it sending in ms as required?
        self.rttimer.start()
        self.rtlock.release()

    def send(self, segment : Segment):
        plc.send(segment)

    def recv(self):
        """Guarantees that the received segment is an uncorrupted ack. If not an ack, an error is thrown"""
        while True:
            seg = plc.recv()
            if (not seg.validate()):
                self.stats.cor_acks += 1
                continue

            if (seg.type() != 'ACK'):
                raise RuntimeError(f'Unexpected segment type {seg.type()} received')
            
            return seg


        

### Entry Code ### 
if (len(sys.argv) != 10):
    print(f"USAGE: python3 {sys.argv[0]} sender_port receiver_port txt_file_to_send max_win rto flp rlp fcp rcp")
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

sender_sock = socket(AF_INET, SOCK_DGRAM)
src_addr = ('127.0.0.1', sender_port)
dest_addr = ('127.0.0.1', receiver_port)
sender_sock.bind(src_addr)

with open('sender_log.txt', 'wt') as logf, open(txt_file_to_send, 'r') as textf:
    plc = PLCModule(sender_sock, dest_addr, flp, rlp, fcp, rcp, logf)
    sender = Sender(textf, max_win, rto, plc)
    
    sender.run()
    
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

# Testing
# plc = PLCModule(None, None, 0,0,0,0)
# plc._corrupt(bytes([1,2,4,8]))
