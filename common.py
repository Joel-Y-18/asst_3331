import struct 

class InvalidSegmentError (Exception):
    pass

class Segment:
    def __init__(self, seq_num=None, ack=None, syn=None, fin=None, data=None, checksum=None):
        self.seq_num = seq_num 
        self.ack = ack 
        self.syn = syn 
        self.fin = fin 
        self.checksum = None
        self.data = data 
    
    def encode(self, generate_checksum=True):
        """Returns a byte stream representing segment"""
        if generate_checksum:
            self.generate_checksum()
            self._check_complete()
        else:
            self._check_complete()
            if not self.validate():
                print("WARNING: Encoded segment has invalid checksum")

        return self._pack() 

    def _pack(self):
        return struct.pack('!hxBh', self.seq_num, (self.ack<<2)|(self.syn<<1)|(self.fin), self.checksum) + self.data

    def _unpack(self):
        # !FINISH
        return struct.pack('!hxBh', self.seq_num, (self.ack<<2)|(self.syn<<1)|(self.fin), self.checksum) + self.data
    
    def generate_checksum(self):
        """Generates the checksum for the segment. Overwrites the previous checksum value"""
        self.checksum = 0
        self._check_complete()

        self.checksum = len(self.data)

    def validate(self):
        """Ensures that the checksum is correct"""
        self._check_complete()

        return self.checksum == len(self.data)
    
    def _is_complete(self):
        return (
            self.seq_num != None and self.ack != None
            and self.syn != None and self.fin != None
            and self.checksum != None and self.data != None
            and self.ack in (0, 1) and self.syn in (0, 1) and self.fin in (0, 1)
            and 0 <= self.seq_num and self.seq_num < (1<<16)
        )
    
    def _check_complete(self):
        if not self._is_complete():
            raise InvalidSegmentError("Segment has missing or invalid fields")
    
    @staticmethod 
    def decode(data : bytes):
        return Segment()