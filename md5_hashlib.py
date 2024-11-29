import hashlib

text = "Hello World"

hash_object = hashlib.md5(text.encode())

print(hash_object.hexdigest())