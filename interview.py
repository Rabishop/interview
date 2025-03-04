import hashlib

def hash_func(input_str):
    return hashlib.sha256(input_str.encode('utf-8')).hexdigest()

def calcHashList(inputs):
    salt = "salt-hashport-1234"
    for i, input_str in enumerate(inputs):
        print(i, input_str, hash_func(input_str + salt))

def main(arg1, arg2, arg3):
    salt = "salt-hashport-1234"
    
    hash1 = hash_func(arg1 + salt)
    expected_hash1 = "02f821cdf373e67248c1349916a11009a9d08541c268575966d2ea6c143ba6aa"
    if hash1 != expected_hash1:
        return "False1"
    
    hash2 = hash_func("foo" + salt)
    expected_hash2 = "42c2fb7c178394588d2ffbe6495b50ac7dba8886b911ffad1444e4885dd51b05"
    if hash2 != expected_hash2:
        return "False2"
    
    hash3 = hash_func(arg3 + salt)
    expected_hash3 = "0538aaaaed903470c4a58eccbea3ff62fc74368514d3d058444fa41a0b00957b"
    if hash3 != expected_hash3:
        return "False3"
    
    return True

# answer 1  



def find_input(expected_hash, salt):
    test_inputs = ["foo", "bar", "baz", "hoge", "fuga", "piyo"]
    for test in test_inputs:
        if hash_func(test + salt) == expected_hash:
            return test
    return None

print("--------------------------------question1--------------------------------")

salt = "salt-hashport-1234"
expected_hashes = [
    "02f821cdf373e67248c1349916a11009a9d08541c268575966d2ea6c143ba6aa",
    "42c2fb7c178394588d2ffbe6495b50ac7dba8886b911ffad1444e4885dd51b05",
    "0538aaaaed903470c4a58eccbea3ff62fc74368514d3d058444fa41a0b00957b"
]

for i, hash_value in enumerate(expected_hashes):
    result = find_input(hash_value, salt)
    if result:
        print(f"arg{i+1} = {result}")

print(main("fuga", "foo", "piyo"))

# answer 2

def find_hash_with_prefix(prefix="000"):
    number = 0
    while True:
        input_str = str(number)
        hash_result = hash_func(input_str)
        if hash_result.startswith(prefix):
            return input_str, hash_result
        number += 1

print("--------------------------------question2--------------------------------")
input_str, hash_result = find_hash_with_prefix("000")
print(f"input: {input_str}")
print(f"output: {hash_result}")

print(hash_func("886"))

# input: 886
# output: 000f21ac06aceb9cdd0575e82d0d85fc39bed0a7a1d71970ba1641666a44f530

# calcHashList(["foo", "bar", "baz", "hoge", "fuga", "piyo"])

a = [1, 2, 3]

