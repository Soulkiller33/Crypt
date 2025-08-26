# Crypt: Simple Command-Line Encryption Tool

`Crypt` is a simple, command-line tool written in Python for encrypting strings and decrypting files using strong symmetric-key encryption. It leverages the `cryptography` library to ensure secure operations and provides a user-friendly interface for quick and easy use.

## Features

- **Secure Encryption**: Utilizes the `Fernet` implementation from the `cryptography` library for authenticated symmetric encryption.
- **Automatic Key Management**: Automatically generates and saves an encryption key if one doesn't exist.
- **Simple CLI**: A clear and intuitive command-line interface with distinct `encrypt` and `decrypt` commands.
- **User-Friendly Output**: Uses `colorama` for colored terminal output, making messages easy to read.
- **Flexible**: Allows customization of output file names, directories, and key file paths.

## Requirements

- Python 3.x
- `cryptography` library
- `colorama` library
re
## Installation

1.  **Clone the repository or download the script:**
    Make sure you have `Crypt.py` on your local machine.

2.  **Install the required packages:**
    Open your terminal or command prompt and run the following command to install the necessary libraries:
    ```bash
    pip install cryptography colorama
    ```

## Usage

The script is run from the command line and has two main sub-commands: `encrypt` and `decrypt`.

### Key Management

The first time you run the script, it will automatically generate a key file named `secret.key` in the current directory (or the path you specify with the `-k` option).

> **⚠️ Important:**
> **Do not lose this key!** If the `secret.key` file is lost, you will not be able to decrypt any data encrypted with it.
> **Keep your key secure!** Anyone with access to your key can decrypt your data.

---

### Encrypting a String

To encrypt a string, use the `encrypt` command. You must provide the string and a name for the output file.

**Syntax:**
`python Crypt.py encrypt -s "your secret message" -n <output_filename>`

**Example:**
```bash
# This will encrypt the string and save it to a file named "message.dat"
python Crypt.py encrypt -s "Meet me at midnight" -n message.dat
```

You can also specify an output directory:
```bash
# This will save the encrypted file in a 'secrets' folder
python Crypt.py encrypt -s "Top secret info" -n classified.dat -o ./secrets
```

---

### Decrypting a File

To decrypt a file, use the `decrypt` command. You must provide the name of the file to decrypt. The decrypted message will be printed to the console.

**Syntax:**
`python Crypt.py decrypt -n <filename_to_decrypt>`

**Example:**
```bash
# This will decrypt "message.dat" using the "secret.key" in the same directory
python Crypt.py decrypt -n message.dat
```

If the file is in another directory, specify it with the `-o` option:
```bash
# This will look for "classified.dat" in the 'secrets' folder
python Crypt.py decrypt -n classified.dat -o ./secrets
```

If you are using a key with a different name or path, use the `-k` option for both encryption and decryption:
```bash
# Encrypt using a custom key
python Crypt.py encrypt -s "My data" -n data.enc -k my_app.key

# Decrypt using the same custom key
python Crypt.py decrypt -n data.enc -k my_app.key
```