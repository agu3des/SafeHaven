import struct
import math

class MD5:
    def __init__(self):
        # Tabela de senhas iniciais baseadas na raiz cúbica de números primos
        self._s = [
            (7, 12, 17, 22), (5, 9, 14, 20),
            (4, 11, 16, 23), (6, 10, 15, 21)
        ]
        self._k = [int((2**32) * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]
        self._buffers = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        self._original_len = 0
        self._buffer = b""

    def _left_rotate(self, x, c):
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    def update(self, input_bytes):
        self._buffer += input_bytes
        self._original_len += len(input_bytes) * 8

        while len(self._buffer) >= 64:
            self._process_chunk(self._buffer[:64])
            self._buffer = self._buffer[64:]

    def _process_chunk(self, chunk):
        a, b, c, d = self._buffers
        x = list(struct.unpack("<16I", chunk))

        for i in range(64):
            if i < 16:
                f = (b & c) | (~b & d)
                g = i
            elif i < 32:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * i) % 16

            f = (f + a + self._k[i] + x[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + self._left_rotate(f, self._s[i // 16][i % 4])) & 0xFFFFFFFF

        self._buffers = [
            (self._buffers[0] + a) & 0xFFFFFFFF,
            (self._buffers[1] + b) & 0xFFFFFFFF,
            (self._buffers[2] + c) & 0xFFFFFFFF,
            (self._buffers[3] + d) & 0xFFFFFFFF,
        ]

    def digest(self):
        padding = b"\x80" + b"\x00" * ((56 - (len(self._buffer) + 1) % 64) % 64)
        length = struct.pack("<Q", self._original_len)
        self.update(padding + length)

        return struct.pack("<4I", *self._buffers)

    def hexdigest(self):
        return "".join(f"{byte:02x}" for byte in self.digest())

# Uso:
data = b"Hello World"
md5 = MD5()
md5.update(data)
print(md5.hexdigest())
