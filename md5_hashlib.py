import hashlib
import time

start_time_hashlib = time.time()
text = "Hello World"

hash_object = hashlib.md5(text.encode())

print(f"MD5 Hashlib: {hash_object.hexdigest()}")
end_time_hashlib = time.time()

print(f"Tempo de execução com hashlib: {end_time_hashlib - start_time_hashlib} segundos")