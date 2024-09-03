import itertools
from mnemonic import Mnemonic
from bip32utils import BIP32Key
import hashlib
import base58
import os
import cryptofuzz


# Path to the text file containing the list of words
word_list_file = "3.txt"
progress_file = "progress.txt"
result_file_path = "found_seed_phrases.txt"

# Target Bitcoin address to check against
target_address = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"


# Initialize the BIP39 mnemonic generator for English
mnemo = Mnemonic("english")

# Read the list of words from the file
with open(word_list_file, "r") as f:
    words = [line.strip() for line in f]

print("Words from file:", words)

HARDENED_OFFSET = 0x80000000  # Constant for hardened key derivation

# Function to save progress
def save_progress(index):
    with open(progress_file, "w") as f:
        f.write(str(index))

# Function to load progress
def load_progress():
    if os.path.exists(progress_file):
        with open(progress_file, "r") as f:
            return int(f.read().strip())
    return 0

# Load last progress
start_index = load_progress()
print(f"Starting from index: {start_index}")

# Open a file to log valid permutations (if needed)
with open(result_file_path, "a") as result_file:
    # Generate all permutations of the word list with the desired length (e.g., 12 words)
    for index, permutation in enumerate(itertools.permutations(words, 12)):
        if index < start_index:
            continue  # Skip permutations until we reach the last saved progress
        
        # Join the words in the permutation into a single seed phrase string
        seed_phrase = " ".join(permutation)
        
        # Convert the seed phrase to a binary seed
        seed = mnemo.to_seed(seed_phrase)
        
        # Generate the master private key using BIP32
        bip32_key = BIP32Key.fromEntropy(seed)
        
        # Derive the first Bitcoin address using BIP44 path for Bitcoin Mainnet: m/44'/0'/0'/0/0
        child_key = (
            bip32_key.ChildKey(44 + HARDENED_OFFSET)  # m/44'
                    .ChildKey(0 + HARDENED_OFFSET)   # /0'
                    .ChildKey(0 + HARDENED_OFFSET)   # /0'
                    .ChildKey(0)                     # /0
                    .ChildKey(0)                     # /0
        )
        
        # Get the public key
        public_key = child_key.PublicKey().hex()
        
        # Generate a P2PKH (legacy) Bitcoin address from the public key
        public_key_hash = hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(public_key)).digest()).digest()
        network_byte = b'\x00'  # 0x00 for Mainnet
        payload = network_byte + public_key_hash
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        address = base58.b58encode(payload + checksum).decode()

        print(f"Checking Seed Phrase: {seed_phrase}")
        print(f"Generated Address: {address}")

        # Check if the generated address matches the target address
        if address == target_address:
            print(f"Success! The seed phrase generates the target address: {target_address}")
            print(f"Seed Phrase: {seed_phrase}")
            # Write the found seed phrase to the result file
            result_file.write(seed_phrase + "\n")
            break  # Stop after finding the correct permutation
        else:
            print("This seed phrase does not generate the target address.")

        # Save progress after each check
        save_progress(index + 1)

print("Finished checking all permutations.")
