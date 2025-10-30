import struct 

SEQ_NUM_SPACE = 1 << 16 

class InvalidSegmentError (Exception):
    pass

class Segment:
    def __init__(self, seq_num=None, ack=None, syn=None, fin=None, data=None):
        self.seq_num = seq_num 
        self.ack = ack 
        self.syn = syn 
        self.fin = fin 
        self.data = data 
    
    def encode(self):
        """Returns a byte stream representing segment"""
        self._check_complete()

        packed_seg = self._pack_no_checksum() 
        checksum = CRC16().encode(packed_seg)
        return Segment._splice_checksum(packed_seg, struct.pack('>H', checksum))


    def _pack_no_checksum(self):
        return struct.pack('!HxBH', self.seq_num, (self.ack<<2)|(self.syn<<1)|(self.fin), 0) + self.data
    
    def _generate_checksum(self):
        """Generates the checksum for the segment. Overwrites the previous checksum value"""
        self.checksum = 0
        self._check_complete()

        #!CHANGE TO PROPER
        self.checksum = len(self.data)

    # def validate(self):
    #     """Ensures that the checksum is correct"""
    #     self._check_complete()

    #     #!CHANGE TO PROPER
    #     return self.checksum == len(self.data)
    
    def type(self):
        if self.syn:
            return 'SYN'
        if self.ack:
            return 'ACK'
        if self.fin:
            return 'FIN'
        return 'DATA'
    
    def end_seq_num(self):
        """Returns the exclusive range end of the segment in the sequence number space """
        return wrap_add(self.seq_num, len(self.data))
    
    def _is_complete(self):
        return (
            self.seq_num != None and self.ack != None
            and self.syn != None and self.fin != None
            and self.data != None
            and self.ack in (0, 1) and self.syn in (0, 1) and self.fin in (0, 1)
            and self.ack + self.syn + self.fin <= 1
            and 0 <= self.seq_num and self.seq_num < (1<<16)
        )
    
    def _check_complete(self):
        if not self._is_complete():
            raise InvalidSegmentError("Segment has missing or invalid fields")
    
    @staticmethod 
    def decode(buffer : bytes): 
        """Parse a sequence of bytes into a segment. Returns a 
        tuple of the decoded segment and whether corruption was detected.
        Decoded segment is None if errors are irrecoverable (i.e. there are 
        header errors, not just payload errors). With out PLC corruption module 
        None should never be a return value.
        """

        if len(buffer) < 6:
            raise InvalidSegmentError(f"Data is too short to be a segment")
        
        data = buffer[6:]
        seq_num, pad, flags, checksum = struct.unpack('!HBBH', buffer[:6])
        checksum_valid = CRC16().verify(Segment._splice_checksum(buffer, b'\x00\x00'), checksum)

        if (flags & 0xf8) or pad != 0:
            return None, False

        ack, syn, fin = (flags>>2) & 1, (flags>>1) & 1, flags & 1 
        if (ack + syn + fin > 1):
            return None, False

        return Segment(seq_num, ack, syn, fin, data), checksum_valid
    
    @staticmethod 
    def create(seq_num, type : str, data: bytes = b''):
        """Factory method providing a nicer interface for creating segments"""
        flags = [0,0,0]
        type = type.lower()
        if type == 'ack':
            flags[0] = 1
        elif type == 'syn':
            flags[1] = 1
        elif type == 'fin':
            flags[2] = 1 
        elif type != 'data':
            raise RuntimeError('Unexpected type')
        
        return Segment(seq_num, *flags, data)
    
    @staticmethod
    def _splice_checksum(buffer : bytes, checksum : bytes):
        assert len(checksum) == 2
        return buffer[:4] + checksum + buffer[6:]


def wrap_add(s, n):
    return (s + n) % SEQ_NUM_SPACE
def wrap_sub(s, n):
    return (s - n + SEQ_NUM_SPACE) % SEQ_NUM_SPACE
def wrap_cmp(s, n):
    if abs(s - n) > SEQ_NUM_SPACE/2:
        if s < n:
            s += SEQ_NUM_SPACE
        else:
            n += SEQ_NUM_SPACE

    if s < n:
        return -1
    elif s == n:
        return 0
    else:
        return 1
    

class CRC16:
    def __init__(self, polynom = 0x16F63):
        self.polynom = polynom

    def encode(self, data : bytes):
        return self._get_remainder(data, 0)
        
    def verify(self, data, checksum):
        return self._get_remainder(data, checksum) == 0
    
    def _get_remainder(self, data, initial_remainder):
        if len(data) == 0:
            raise RuntimeError('cannot generate checksum for 0-length data')
        
        datasz = len(data)
        mdata = bytearray(data)
        mdata += struct.pack('>H', initial_remainder)
        
        byteptr = 0
        bitshift = 0
        while True:
            while byteptr != datasz and mdata[byteptr] == 0:
                byteptr += 1
                bitshift = 0
            if byteptr == datasz:
                break
            
            while (mdata[byteptr] & (1<<(7-bitshift))) == 0:
                bitshift += 1
            assert bitshift < 8, f'error in bit shift'
            
            self.xor(mdata, byteptr, bitshift)
        
        return struct.unpack('>H', mdata[-2:])[0]
    
    def xor(self, msg, byte, bitshift):
        polynom_bytes = struct.pack('>I', self.polynom<<(32-self.polynom.bit_length())>>bitshift)[:3] # drop last byte
        for i, j in zip(range(byte, byte + 3), range(0, 3)):
            msg[i] ^= polynom_bytes[j]

if __name__ == '__main__':
    # exit()

    # def segment_test(s1):
    #     print("Original", s1.seq_num, s1.ack, s1.syn, s1.fin, s1.checksum, s1.data)
    #     encoded = s1.encode()
    #     print(encoded)
    #     decoded = Segment.decode(encoded)
    #     print("Decoded", decoded.seq_num, decoded.ack, decoded.syn, decoded.fin, decoded.checksum, decoded.data)
    #     print()

    # segment_test(Segment(12, 1, 0, 1, b'\x01\x01\x01'))
    # segment_test(Segment((1<<16)-1, 0, 0, 1, b''))
    # segment_test(Segment(0, 1, 1, 1, b'\x00\x00'))
    
    crc = CRC16()

    msg = b'the big brown fox'#'1'.encode('ascii')
    checksum = crc.encode(msg)
    verify = crc.verify(msg, checksum)
    print(f'checksum={checksum:x}; passed={verify}')
    
