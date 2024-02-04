from FileDecryptor import FileDecryptor

PATH_TO_ENCRYPTED = "init.lua"

if __name__ == '__main__':
    decryptor = FileDecryptor("")
    decryptor.decrypt_file(PATH_TO_ENCRYPTED)