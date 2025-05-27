class PlayFairCipher:
    def __init__(self):
        pass

    def create_playfair_matrix(self, key):
        # Chuyển "J" thành "I" trong khóa
        key = key.replace("J", "I")
        key = key.upper()
        key_set = set(key)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        
        # Lọc các chữ cái còn lại không có trong khóa, đảm bảo 'J' không được thêm vào nếu 'I' đã có
        remaining_letters = [
            letter for letter in alphabet if letter not in key_set and letter != 'J'
        ]
        
        matrix_elements = []
        # Thêm các ký tự từ khóa vào ma trận, loại bỏ trùng lặp và 'J'
        for char in key:
            if char not in matrix_elements and char != 'J':
                matrix_elements.append(char)

        # Thêm các chữ cái còn lại vào ma trận
        for letter in remaining_letters:
            if letter not in matrix_elements: # Đảm bảo không trùng lặp nếu key có chứa 'I'
                matrix_elements.append(letter)
            if len(matrix_elements) == 25:
                break
        
        # Chuyển danh sách 1D thành ma trận 5x5
        playfair_matrix = [matrix_elements[i:i+5] for i in range(0, len(matrix_elements), 5)]
        return playfair_matrix

    def find_letter_coords(self, matrix, letter):
        # Chuyển "J" thành "I" khi tìm kiếm tọa độ
        if letter == "J":
            letter = "I"
        for row in range(len(matrix)):
            for col in range(len(matrix[row])):
                if matrix[row][col] == letter:
                    return row, col
        return -1, -1 # Trả về -1,-1 nếu không tìm thấy (trường hợp lỗi)

    def playfair_encrypt(self, plain_text, matrix):
        # Chuẩn bị văn bản đầu vào: chuyển "J" thành "I", viết hoa, loại bỏ ký tự không phải chữ cái
        processed_text = ""
        for char in plain_text.upper():
            if 'A' <= char <= 'Z':
                if char == 'J':
                    processed_text += 'I'
                else:
                    processed_text += char
        
        # Xử lý các cặp ký tự trùng lặp và độ dài lẻ
        prepared_text = ""
        i = 0
        while i < len(processed_text):
            prepared_text += processed_text[i]
            if i + 1 < len(processed_text):
                if processed_text[i] == processed_text[i+1]:
                    prepared_text += "X" # Chèn 'X' nếu hai ký tự liền kề giống nhau
                else:
                    prepared_text += processed_text[i+1]
                    i += 1
            i += 1
        
        # Nếu độ dài chuỗi sau xử lý là lẻ, thêm 'X' vào cuối
        if len(prepared_text) % 2 != 0:
            prepared_text += "X"

        encrypted_text = ""
        for i in range(0, len(prepared_text), 2):
            pair = prepared_text[i:i+2]
            
            row1, col1 = self.find_letter_coords(matrix, pair[0])
            row2, col2 = self.find_letter_coords(matrix, pair[1])

            # Xử lý trường hợp không tìm thấy ký tự (có thể do lỗi đầu vào hoặc ma trận)
            if row1 == -1 or row2 == -1:
                # Có thể log lỗi hoặc bỏ qua cặp này tùy theo yêu cầu
                continue

            if row1 == row2: # Cùng hàng
                encrypted_text += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
            elif col1 == col2: # Cùng cột
                encrypted_text += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
            else: # Tạo hình chữ nhật
                encrypted_text += matrix[row1][col2] + matrix[row2][col1]
        return encrypted_text
    
    def playfair_decrypt(self, cipher_text, matrix):
        cipher_text = cipher_text.upper()
        
        # Bước 1: Giải mã từng cặp ký tự
        temp_decrypted_text = ""
        for i in range(0, len(cipher_text), 2):
            pair = cipher_text[i:i+2]
            row1, col1 = self.find_letter_coords(matrix, pair[0])
            row2, col2 = self.find_letter_coords(matrix, pair[1])

            # Xử lý trường hợp không tìm thấy ký tự
            if row1 == -1 or row2 == -1:
                continue

            if row1 == row2: # Cùng hàng
                temp_decrypted_text += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
            elif col1 == col2: # Cùng cột
                temp_decrypted_text += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
            else: # Tạo hình chữ nhật
                temp_decrypted_text += matrix[row1][col2] + matrix[row2][col1]

        # Bước 2: Loại bỏ ký tự 'X' được thêm vào và khôi phục bản rõ gốc
        final_decrypted_text = ""
        i = 0
        while i < len(temp_decrypted_text):
            # Kiểm tra nếu 'X' được chèn giữa hai ký tự giống nhau (ví dụ: 'AXA' -> 'AA')
            # Điều kiện: ký tự hiện tại và ký tự sau 'X' giống nhau
            if (i + 2 < len(temp_decrypted_text) and 
                temp_decrypted_text[i+1] == 'X' and 
                temp_decrypted_text[i] == temp_decrypted_text[i+2]):
                
                final_decrypted_text += temp_decrypted_text[i]
                i += 2 # Bỏ qua 'X' và ký tự thứ ba (là bản sao của ký tự đầu tiên)
            else:
                final_decrypted_text += temp_decrypted_text[i]
                i += 1
        
        # Bước 3: Loại bỏ 'X' ở cuối cùng nếu nó là ký tự đệm
        # (Chỉ loại bỏ nếu nó là 'X' và làm cho độ dài chuỗi là số lẻ,
        # giả định 'X' luôn được thêm vào để làm chẵn độ dài)
        if len(final_decrypted_text) > 0 and final_decrypted_text[-1] == 'X':
            # Kiểm tra xem 'X' có phải là ký tự cuối cùng của một cặp được thêm vào để làm chẵn không
            # Nếu độ dài của bản rõ ban đầu là lẻ, thì 'X' này là đệm.
            # Cách đơn giản nhất là loại bỏ nếu nó ở cuối và không có cặp sau nó.
            # Một cách chính xác hơn là kiểm tra xem nó có phải là kết quả của việc thêm 'X' để làm chẵn độ dài hay không.
            # Trong Playfair, 'X' thường được thêm vào cuối để làm chẵn số lượng ký tự.
            # Nếu bản rõ ban đầu có độ dài lẻ, ký tự cuối cùng sẽ là 'X' đệm.
            # Chúng ta có thể giả định rằng nếu 'X' là ký tự cuối cùng, nó là đệm.
            final_decrypted_text = final_decrypted_text[:-1]

        return final_decrypted_text