import struct  #empacotar e desempacotar dados binarios
import math    #funcoes matematicas
import time    #tempo de execucao

# Implementação do MD5
class MD5:
    def __init__(self): #construtor
       # Tabela de deslocamentos (s) e constantes (k)
        self._s = [ #deslocamento para cada rodada do algoritmo
            (7, 12, 17, 22), (5, 9, 14, 20),
            (4, 11, 16, 23), (6, 10, 15, 21)
        ]
        self._k = [int((2**32) * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)] #Define os deslocamentos em bits para cada uma das quatro operacoes em cada uma das 16 rodadas. Constantes baseadas na raiz cúbica de numeros primos
        #Calcula o seno do indice (i + 1)
        #Toma o valor absoluto do seno
        #Multiplica pelo valor 2^32
        #Converte para um inteiro e aplica uma mascara para garantir 32 bits
        #Adiciona o valor calculado a lista
        self._buffers = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476] #Os quatro registradores que mantem o estado intermediário do hash, iniciados com valores especificos. 32 bits 
        self._original_len = 0 #Armazena o tamanho total da mensagem em bits, essencial para o padding.
        self._buffer = b"" #Buffer que armazena os bytes da mensagem até que estejam prontos para serem processados.

    def _left_rotate(self, x, c):
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF
    #Executa uma rotação circular à esquerda de x por c bits. Exemplo: x = 1011(binário) e c = 2, resultado = 1110
    #Usa operadores de deslocamento e OR bit a bit para realizar a rotacao
    #Aplica uma máscara 0xFFFFFFFF para garantir que o resultado seja um inteiro de 32 bits

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

# Medição de tempo para implementação manual do MD5
start_time_manual = time.time()
data = b"Hello World"
md5 = MD5()
md5.update(data)
print(f"MD5 Manual: {md5.hexdigest()}")
end_time_manual = time.time()

print(f"Tempo de execução manual: {end_time_manual - start_time_manual} segundos")
