import struct


class SHA1:
    def __init__(self):
        self.h0 = 0x67452301
        self.h1 = 0xEFCDAB89
        self.h2 = 0x98BADCFE
        self.h3 = 0x10325476
        self.h4 = 0xC3D2E1F0
        self.unprocessed = b''
        self.message_byte_length = 0

    def update(self, arg):
        if isinstance(arg, str):
            arg = arg.encode('utf-8')
        self.message_byte_length += len(arg)
        self.unprocessed += arg

        while len(self.unprocessed) >= 64:
            self._process_chunk(self.unprocessed[:64])
            self.unprocessed = self.unprocessed[64:]

    def digest(self):
        return self._produce_digest()

    def hexdigest(self):
        return ''.join(format(x, '08x') for x in self.digest())

    def _produce_digest(self):
        message = self.unprocessed
        message += b'\x80'
        message += b'\x00' * ((56 - (self.message_byte_length + 1) % 64) % 64)
        message_bit_length = self.message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)

        while len(message) >= 64:
            self._process_chunk(message[:64])
            message = message[64:]

        return [self.h0, self.h1, self.h2, self.h3, self.h4]

    def _process_chunk(self, chunk):
        assert len(chunk) == 64

        w = list(struct.unpack('>16I', chunk))

        # Розширення оригінальних 16 32-бітних слів у 80 32-бітних слів
        for i in range(16, 80):
            w.append(self._left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

        a, b, c, d, e = self.h0, self.h1, self.h2, self.h3, self.h4

        # Основний цикл
        for i in range(80):
            if 0 <= i <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (d & (b | c))
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = ((self._left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                             a, self._left_rotate(b, 30), c, d)

        self.h0 = (self.h0 + a) & 0xffffffff
        self.h1 = (self.h1 + b) & 0xffffffff
        self.h2 = (self.h2 + c) & 0xffffffff
        self.h3 = (self.h3 + d) & 0xffffffff
        self.h4 = (self.h4 + e) & 0xffffffff

    @staticmethod
    def _left_rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff
