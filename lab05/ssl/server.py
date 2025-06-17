import socket
import ssl
import threading

# Thông tin server
server_address = ('localhost', 12345)

# Danh sách các client đã kết nối
clients = []

def handle_client(client_socket):
    # Thêm client vào danh sách
    clients.append(client_socket)

    print("Đã kết nối với:", client_socket.getpeername())

    try:
        # Nhận và gửi dữ liệu
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            print("Nhận:", data.decode('utf-8'))

            # Gửi dữ liệu đến tất cả các client khác
            for client in clients:
                if client != client_socket:
                    try:
                        client.send(data)
                    except:
                        clients.remove(client)

    except Exception as e: # Catch specific exception for better debugging
        print(f"Lỗi xử lý client {client_socket.getpeername()}: {e}")
        clients.remove(client_socket)
    finally:
        print("Đã ngắt kết nối:", client_socket.getpeername())
        if client_socket in clients: # Ensure client_socket is still in clients before removing
            clients.remove(client_socket)
        client_socket.close()

# Tạo socket server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reusing the address
server_socket.bind(server_address)
server_socket.listen(5)

print("Server đang chờ kết nối...")

# Lắng nghe các kết nối
while True:
    client_socket, client_address = server_socket.accept()

    # Tạo SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) # Use PROTOCOL_TLS_SERVER for server-side

    try:
        context.load_cert_chain(certfile="./certificates/server-cert.crt",
                                keyfile="./certificates/server-key.key")
    except FileNotFoundError as e:
        print(f"Lỗi: Không tìm thấy chứng chỉ hoặc khóa: {e}")
        print("Vui lòng đảm bảo các tệp 'server-cert.crt' và 'server-key.key' nằm trong thư mục 'certificates'.")
        client_socket.close()
        continue # Continue to the next iteration to listen for new connections

    # Thiết lập kết nối SSL
    try:
        ssl_socket = context.wrap_socket(client_socket, server_side=True)
    except ssl.SSLError as e:
        print(f"Lỗi SSL khi wrap socket: {e}")
        client_socket.close()
        continue

    # Bắt đầu một luồng xử lý cho mỗi client
    client_thread = threading.Thread(target=handle_client, args=(
        ssl_socket,))
    client_thread.start()