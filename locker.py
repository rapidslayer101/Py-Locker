import zlib
import enclib as enc
from os.path import exists
from time import time
from hashlib import sha512


# known vulnerabilities
# 1. The depth speed will be faster on more powerful hardware (asic devices)
# 2. The depth speed will probably be faster if p2k and to_hex are rewritten in another language

# key system
# 1. master_pass + master_pin (depth a few hours/days) = master_key
# 2. master_key + key_file_pin = key_file
# 3. master_key + unlock_pass + unlock_pin (depth a few seconds) = unlock_key

# to get unlock key
# enter key_file_pin
# enter unlock_pass
# enter unlock_pin


def make_new_key_file():
    print("\nEnter a 12 digit pin for key file (key_file_pin)")
    while True:
        key_file_pin = input("Set Pin: ")
        if len(key_file_pin) == 12:
            try:
                int(key_file_pin)
                break
            except ValueError:
                pass
        print("Pin must be 12 digits")
    key_file_salt = enc.rand_b96_str(512)
    with open(f'{key_location}key_salt', 'w') as f:
        f.write(key_file_salt)
    print("\nKey salt file created\nCalculating DPS then creating key file\nCalculating DPS(1)...")
    dps1 = enc.calculate_dps()
    print("Calculating DPS(2)...")
    dps2 = enc.calculate_dps()
    print("Calculating DPS(3)...")
    dps = (dps1+dps2+enc.calculate_dps())//3
    print(f"\nDevice loops per second: {dps}")
    start = time()
    print(f"Testing calculated value (This should take 1 second)")
    enc.pass_to_key(enc.rand_b96_str(10), enc.rand_b96_str(10), dps)
    print(f"Took: {time() - start}s")
    with open(f'{key_location}key', 'wb') as f:
        f.write(enc.enc_from_pass(str(dps), key_file_pin[:6], key_file_salt, int(key_file_pin[6:])))
    print("Key file created")
    with open(f'key_location', 'w') as f:
        f.write(key_location)


def get_key_file_data():
    with open(f'{key_location}key', 'rb') as f:
        data = f.read()
    if not exists(f'{key_location}key_salt'):
        print("Key file found but no key salt file found, key cannot be loaded, generating new key file")
    else:
        with open(f'{key_location}key_salt', 'r') as f:
            key_file_salt = f.read()
        print("Enter 12 digit key file pin (key_file_pin)")
        while True:
            try:
                while True:
                    key_file_pin = input("Pin: ")
                    if len(key_file_pin) == 12:
                        try:
                            int(key_file_pin)
                            break
                        except ValueError:
                            pass
                    print("Pin must be 12 digits")
                key_file_data = enc.dec_from_pass(data, key_file_pin[:6], key_file_salt, int(key_file_pin[6:]))
                return key_file_pin, key_file_salt, key_file_data
            except zlib.error:
                print("Incorrect password or salt")


# key file loading
while True:
    if not exists('key_location'):
        print("No key location set\n"
              "Set the location to create a new key or where an existing key file is")
        key_location = input("Enter the location: ")
        print("\n")
        if not exists(f'{key_location}key'):
            make_new_key_file()
        else:
            key_file_pin, key_file_salt, data = get_key_file_data()
            with open(f'key_location', 'w') as f:
                f.write(key_location)
        break
    else:
        try:
            with open('key_location', 'r') as f:
                key_location = f.read()
            key_file_pin, key_file_salt, data = get_key_file_data()
            break
        except FileNotFoundError:
            make_new_key_file()

print("\nKey file unlock successful")
data = data.split("\n")
if len(data) > 0:
    dps = int(data[0])

if len(data) == 1:
    print("Enter master password, minimum length of 32 characters (master_pass)")
    while True:
        master_pass = input("Set Password: ")
        if len(master_pass) > 31:
            break
        print("Password must be at least 32 characters")
    print("Enter master pin, minimum length of 16 digits (master_pin)")
    while True:
        master_pin = input("Set Pin: ")
        if len(master_pin) > 15:
            try:
                master_pin = int(master_pin)
                break
            except ValueError:
                pass
        print("Pin must be 16 digits")
    print("Enter depth time in hours, this is how long it will take to generate"
          " a new key file (longer is better) (master_depth)")
    while True:
        master_depth_t = input("Depth time: ")
        try:
            master_depth_t = float(master_depth_t)
            break
        except ValueError:
            pass
        print("Depth must be a number")
    print(f"Calculated depth: {int(round(master_depth_t*3600*dps, 0))}, IF REGENERATING KEY FILE ENTER OLD DEPTH VALUE")
    while True:
        master_depth = input("Set Depth: ")
        try:
            master_depth = int(master_depth)
            break
        except ValueError:
            pass
        print("Depth must be an integer number")
    print(f"\nDO NOT FORGET YOUR MASTER PASSWORD, MASTER PIN AND MASTER DEPTH, they are needed if the key file is lost")
    print(f"Master password: {master_pass} \nMaster pin: {master_pin} \nMaster depth: {master_depth}")
    input("\nPress enter to continue")
    print("\nGenerating master key...")
    # todo save during generate and reloader
    master_key = enc.pass_to_key_with_progress(master_pass, str(master_pin), master_depth, dps)
    print("\nMaster key generated, writing to key file")
    with open(f'{key_location}key', 'wb') as f:
        to_write = f"{dps}\n{master_key}"
        f.write(enc.enc_from_pass(to_write, key_file_pin[:6], key_file_salt, int(key_file_pin[6:])))

if len(data) == 2:
    master_key = data[1]

print("Enter unlock password (unlock_pass) and 12 digit pin (unlock_pin)")
while True:
    unlock_pass = input("Password: ")
    if len(unlock_pass) > 7:
        break
    print("Password must be at least 8 characters")
while True:
    unlock_pin = input("Pin: ")
    if len(unlock_pin) == 6:
        try:
            unlock_pin = int(unlock_pin)
            break
        except ValueError:
            pass
    print("Pin must be 6 digits")

unlock_key = enc.pass_to_key(master_key, unlock_pass, unlock_pin)
if not exists('key_hash'):
    with open('key_hash', 'w') as f:
        f.write(sha512((unlock_key+master_key+unlock_pass+str(unlock_pin)).encode()).hexdigest())
    print("No previous key hash found, generating new key hash")
else:
    with open('key_hash') as f:
        key_hash = f.read()
    if sha512((unlock_key+master_key+unlock_pass+str(unlock_pin)).encode()).hexdigest() == key_hash:
        print("Key hash match, unlock key verified")
    else:
        print("Key hash mismatch, invalid unlock key loaded")
print(f"\nUnlock key: {unlock_key}")
input()
