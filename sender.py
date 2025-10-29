import random 
from socket import * 

random.seed()
verbose = False



class PLCModule:
    def __init__(self, socket : socket, address, flp, rlp, fcp, rcp, header_sz = 4):
        self.socket = socket
        self.address = address
        self.flp = flp 
        self.rlp = rlp 
        self.fcp = fcp
        self.rcp = rcp 
        self.HEADER_SZ = header_sz
    
    def send(self, data : bytes): 
        if self._flip(self.flp):
            return
        
        if self._flip(self.fcp):
            data = self._corrupt(data)

        self.socket.sendto(data, self.address)

    def recv(self, bufsz):
        data = None
        while True:
            data = self.socket.recvfrom(bufsz)
            if not self._flip(self.rlp):
                break 

        if self._flip(self.rcp):
            return self._corrupt(data)
        return data
        
        
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
    

# Testing
plc = PLCModule(None, None, 0,0,0,0)
plc._corrupt(bytes([1,2,4,8]))
