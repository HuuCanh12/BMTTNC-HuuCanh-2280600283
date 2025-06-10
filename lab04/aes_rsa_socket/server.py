from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading
import hashlib

# --- Cài đặt Server ---
# Khởi tạo socket của server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Gắn socket với địa chỉ và cổng
server_socket.bind(('localhost', 12345))
# Lắng nghe kết nối đến, tối đa 5 kết nối trong hàng đợi
server_socket.listen(5)
print("Server is listening on localhost:12345")

# Tạo cặp khoá RSA cho server
server_key = RSA.generate(2048)

# Danh sách để lưu thông tin các client đã kết nối
clients = []

# --- Các hàm mã hoá và giải mã ---

def encrypt_message(key, message):
    """Mã hoá tin nhắn bằng AES."""
    cipher = AES.new(key, AES.MODE_CBC)
    # Pad tin nhắn để đủ độ dài khối, sau đó mã hoá
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    # Trả về vector khởi tạo (iv) và bản mã
    return cipher.iv + ciphertext

def decrypt_message(key, encrypted_message):
    """Giải mã tin nhắn bằng AES."""
    # Tách iv từ bản mã
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Giải mã và loại bỏ padding
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode('utf-8')

# --- Hàm xử lý cho từng client ---

def handle_client(client_socket, client_address):
    """
    Hàm này sẽ được chạy trong một thread riêng cho mỗi client.
    Nó xử lý việc trao đổi khoá và giao tiếp tin nhắn.
    """
    print(f"Connected with {client_address}")
    client_info = None  # Khởi tạo để dùng trong khối finally

    try:
        # 1. Gửi khoá công khai của server cho client
        client_socket.send(server_key.publickey().export_key(format='PEM'))

        # 2. Nhận khoá công khai của client
        client_received_key = RSA.import_key(client_socket.recv(2048))

        # 3. Tạo khoá đối xứng AES cho phiên làm việc này
        aes_key = get_random_bytes(16)

        # 4. Mã hoá khoá AES bằng khoá công khai của client và gửi đi
        cipher_rsa = PKCS1_OAEP.new(client_received_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        client_socket.send(encrypted_aes_key)

        # 5. Thêm client vào danh sách chung
        client_info = (client_socket, aes_key)
        clients.append(client_info)

        # 6. Bắt đầu vòng lặp nhận và gửi tin nhắn
        while True:
            # Nhận tin nhắn đã mã hoá từ client
            encrypted_message = client_socket.recv(1024)
            # Nếu không nhận được dữ liệu, client đã ngắt kết nối
            if not encrypted_message:
                break

            # Giải mã tin nhắn
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            
            # Nếu client gửi 'exit', thoát vòng lặp
            if decrypted_message.lower() == "exit":
                break

            print(f"Received from {client_address}: {decrypted_message}")

            # Gửi tin nhắn nhận được tới tất cả các client khác
            broadcast_message = f"<{client_address[0]}:{client_address[1]}> {decrypted_message}"
            for client, key in clients:
                # Không gửi lại cho chính client đã gửi tin
                if client != client_socket:
                    try:
                        encrypted = encrypt_message(key, broadcast_message)
                        client.send(encrypted)
                    except Exception as e:
                        print(f"Error sending to a client: {e}")

    except Exception as e:
        print(f"An error occurred with {client_address}: {e}")
    finally:
        # Dọn dẹp khi client ngắt kết nối hoặc có lỗi
        if client_info in clients:
            clients.remove(client_info)
        client_socket.close()
        print(f"Connection with {client_address} closed")


# --- Vòng lặp chính của Server ---

def accept_connections():
    """Vòng lặp vô tận để chấp nhận kết nối mới từ client."""
    while True:
        try:
            # Chấp nhận một kết nối mới
            client_socket, client_address = server_socket.accept()
            # Tạo một thread mới để xử lý client này
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
        except KeyboardInterrupt:
            print("\nServer is shutting down.")
            break
        except Exception as e:
            print(f"Server error: {e}")
            break
            
    # Đóng tất cả các socket client còn lại khi server tắt
    for client, key in clients:
        client.close()
    server_socket.close()


if __name__ == "__main__":
    accept_connections()

