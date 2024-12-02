import hashlib

text = "Hello World"
text2 = input()

hash_object = hashlib.md5(text.encode())
hash_object2 = hashlib.md5(text2.encode())


print(hash_object.hexdigest())
print(hash_object2.hexdigest())