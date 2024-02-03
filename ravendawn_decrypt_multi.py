from FileDecryptor import FileDecryptor

if __name__ == '__main__':
    data_path = 'data'
    decryptor = FileDecryptor(data_path)
    decryptor.decrypt_all_files()