import os
import argparse
from cryptography.fernet import Fernet, InvalidToken
from colorama import Fore, Style, init
init(autoreset=True)

# Generates functions keys and saves them to a keypath
def generate_key(key_path="secret.key"):
    """Generates a key and saves it to a file."""
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)
    print(f'{Fore.GREEN}Key generated and saved to {key_path}')
    return key

# Loads the key from a file
def load_key(key_path="secret.key"):
    """Loads the key from a file."""
    if os.path.exists(key_path):
        with open(key_path, "rb") as key_file:
            key = key_file.read()
    else:
        print(f'{Fore.YELLOW}Key file "{key_path}" not found. Generating a new key...')
        key = generate_key(key_path)
    return key

# Deals with the encryption side of the program
def handle_encryption(args, f: Fernet):
    """Encrypts a string based on provided arguments."""
    encrypted_message = f.encrypt(args.string.encode())
    os.makedirs(args.output, exist_ok=True)
    file_path = os.path.join(args.output, args.name)
    with open(file_path, 'wb') as file:
        file.write(encrypted_message)
    print(f'{Fore.GREEN}Successfully encrypted the string and saved to {Style.BRIGHT}{file_path}')

# Deals with the decryption side of the program
def handle_decryption(args, f: Fernet):
    """Decrypts a file based on provided arguments."""
    file_path = os.path.join(args.output, args.name)
    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Input file not found at '{file_path}'")
        return

    try:
        decrypted_data = f.decrypt(encrypted_data)
        print(f"{Fore.CYAN}Decrypted Message: {Style.BRIGHT}{decrypted_data.decode()}")
    except InvalidToken:
        print(f"{Fore.RED}Decryption failed. The key is incorrect or the data is corrupted.")

# Main function
# Contains terminal commands
# Segmented into encrypted and decrypted arguments
def main():
    parser = argparse.ArgumentParser(
        description='A tool to encrypt strings or decrypt files.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Creates a subparser to handle distinct commands: 'encrypt' and 'decrypt'.
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    #  Encrypt Parser
    # In the CLI it would look like 'Crypt.py encrypt...'
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a string and save it to a file.')
    encrypt_parser.add_argument('-s', '--string', required=True, help='The string you want to encrypt.')
    encrypt_parser.add_argument('-n', '--name', required=True, help='Name of the output file.')
    encrypt_parser.add_argument('-o', '--output', default='.', help='Output directory.')
    encrypt_parser.add_argument('-k', '--key', default='secret.key', help='Path to the key file.')

    #  Decrypt Parser
    # In the CLI it would look like 'Crypt.py decrypt...'
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file.')
    decrypt_parser.add_argument('-n', '--name', required=True, help='Name of the file to decrypt.')
    decrypt_parser.add_argument('-o', '--output', default='.', help='Directory where the file is located.')
    decrypt_parser.add_argument('-k', '--key', default='secret.key', help='Path to the key file.')

    args = parser.parse_args()

    key = load_key(args.key)
    f = Fernet(key)

    if args.command == 'encrypt':
        handle_encryption(args, f)
    elif args.command == 'decrypt':
        handle_decryption(args, f)

if __name__ == '__main__':
    main()