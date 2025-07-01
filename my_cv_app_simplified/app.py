import os
import json
import base64
from flask import Flask, request, jsonify, render_template, send_from_directory, abort

# Thư viện Cryptography cho mã hóa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# --- Cấu hình ứng dụng ---
UPLOAD_FOLDER = 'uploaded_files'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Danh sách IP được phép (chỉ để thử nghiệm)
ALLOWED_IPS = ['127.0.0.1', '::1']

# Mật khẩu cứng cho khóa bí mật (Chỉ dùng cho ví dụ đơn giản này!)
# Vui lòng thay đổi thành mật khẩu MẠNH của bạn!
# Trong môi trường thực tế, KHÔNG BAO GIỜ hardcode như thế này.
FIXED_PRIVATE_KEY_PASSWORD = b"my_super_secret_password_123"

# --- Tải hoặc Tạo cặp khóa RSA ---
private_key = None
public_key = None

def load_or_generate_keys():
    global private_key, public_key
    
    private_key_path = "private_key.pem"
    public_key_path = "public_key.pem"

    # Kiểm tra nếu khóa đã tồn tại
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        try:
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=FIXED_PRIVATE_KEY_PASSWORD,
                    backend=default_backend()
                )
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            print("Khóa RSA đã được tải thành công từ các tệp hiện có.")
            return True
        except Exception as e:
            print(f"Lỗi khi tải khóa từ tệp: {e}. Có thể mật khẩu sai hoặc tệp bị hỏng. Đang tạo lại khóa.")
            # Nếu lỗi, xóa các tệp bị lỗi và tiếp tục tạo mới
            if os.path.exists(private_key_path): os.remove(private_key_path)
            if os.path.exists(public_key_path): os.remove(public_key_path)
    
    # Tạo khóa nếu chưa tồn tại hoặc bị lỗi
    print("Đang tạo cặp khóa RSA mới...")
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(FIXED_PRIVATE_KEY_PASSWORD)
            ))
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Cặp khóa RSA mới đã được tạo và lưu thành công.")
        return True
    except Exception as e:
        print(f"LỖI KHỞI TẠO: Không thể tạo hoặc lưu khóa RSA: {e}")
        return False

# Gọi hàm này khi khởi động ứng dụng
if not load_or_generate_keys():
    print("Ứng dụng không thể khởi động do lỗi khóa RSA. Vui lòng kiểm tra.")
    exit(1)


# --- Hàm Mã hóa và Giải mã HYBRID (Toàn bộ dữ liệu lớn bằng AES, khóa AES bằng RSA) ---

def encrypt_payload_hybrid(data_bytes: bytes):
    """
    Mã hóa một payload (dữ liệu bất kỳ) bằng AES-256 GCM.
    Khóa AES và IV được mã hóa bằng RSA public key.
    Trả về (encrypted_aes_key_iv_b64, ciphertext_b64, tag_b64)
    """
    try:
        aes_key = os.urandom(32) # 256-bit key
        iv = os.urandom(12)      # 96-bit IV
        
        # Mã hóa dữ liệu bằng AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data_bytes) + encryptor.finalize()
        tag = encryptor.tag

        # Mã hóa khóa AES và IV bằng RSA Public Key
        key_iv_combined = aes_key + iv
        encrypted_key_iv_combined = public_key.encrypt(
            key_iv_combined,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return (
            base64.b64encode(encrypted_key_iv_combined).decode('utf-8'),
            base64.b64encode(ciphertext).decode('utf-8'),
            base64.b64encode(tag).decode('utf-8')
        )
    except Exception as e:
        print(f"Lỗi khi mã hóa payload: {e}")
        return None, None, None

def decrypt_payload_hybrid(encrypted_key_iv_combined_b64: str, ciphertext_b64: str, tag_b64: str):
    """
    Giải mã một payload bằng cách giải mã khóa AES và IV trước (bằng RSA private key),
    sau đó dùng AES để giải mã nội dung.
    """
    try:
        # Giải mã khóa AES và IV kết hợp bằng RSA Private Key
        encrypted_key_iv_combined = base64.b64decode(encrypted_key_iv_combined_b64)
        key_iv_combined = private_key.decrypt(
            encrypted_key_iv_combined,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aes_key = key_iv_combined[:32]
        iv = key_iv_combined[32:]

        # Giải mã dữ liệu bằng AES-GCM
        ciphertext = base64.b64decode(ciphertext_b64)
        tag = base64.b64decode(tag_b64)

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except Exception as e:
        print(f"Lỗi khi giải mã payload: {e}")
        return None

# --- Route chính để phục vụ HTML ---
@app.route('/')
def index():
    return render_template('index.html')

# --- Route để gửi CV ---
@app.route('/upload_cv', methods=['POST'])
def upload_cv():
    client_ip = request.remote_addr
    print(f"Nhận yêu cầu tải lên từ IP: {client_ip}")

    if client_ip not in ALLOWED_IPS:
        print(f"IP {client_ip} không được phép.")
        return jsonify({"error": "Địa chỉ IP của bạn không được phép gửi CV."}), 403

    if 'cvFile' not in request.files or not request.form.get('fullName') or not request.form.get('email'):
        return jsonify({"error": "Vui lòng cung cấp đầy đủ thông tin và tệp CV."}), 400

    cv_file = request.files['cvFile']
    full_name = request.form['fullName']
    email = request.form['email']
    phone = request.form.get('phone', '')

    if cv_file.filename == '':
        return jsonify({"error": "Tên tệp CV không hợp lệ."}), 400

    # Đọc nội dung tệp CV
    cv_content = cv_file.read()

    # Chuẩn bị Metadata
    metadata_payload = {
        "full_name": full_name,
        "email": email,
        "phone": phone,
        "original_filename": cv_file.filename,
        "client_ip": client_ip,
    }
    
    # Mã hóa NỘI DUNG CV và METADATA
    encrypted_key_iv_cv, encrypted_cv_content, tag_cv = encrypt_payload_hybrid(cv_content)
    encrypted_key_iv_meta, encrypted_metadata_content, tag_meta = encrypt_payload_hybrid(
        json.dumps(metadata_payload).encode('utf-8')
    )

    if any(item is None for item in [encrypted_key_iv_cv, encrypted_cv_content, tag_cv,
                                    encrypted_key_iv_meta, encrypted_metadata_content, tag_meta]):
        return jsonify({"error": "Lỗi máy chủ khi mã hóa dữ liệu."}), 500

    # Lưu trữ các thành phần đã mã hóa vào một file JSON duy nhất
    file_id = os.urandom(16).hex()
    combined_encrypted_file_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.json_enc")

    encrypted_data_bundle = {
        "cv_ciphertext": encrypted_cv_content,
        "cv_key_iv_bundle": encrypted_key_iv_cv,
        "cv_tag": tag_cv,
        "meta_ciphertext": encrypted_metadata_content,
        "meta_key_iv_bundle": encrypted_key_iv_meta,
        "meta_tag": tag_meta
    }

    try:
        with open(combined_encrypted_file_path, 'w') as f:
            json.dump(encrypted_data_bundle, f)
    except IOError as e:
        print(f"Lỗi hệ thống khi lưu tệp: {e}")
        return jsonify({"error": "Lỗi máy chủ khi lưu trữ CV."}), 500

    print(f"CV từ {email} (IP: {client_ip}) đã được nhận, mã hóa và lưu với ID: {file_id}")
    return jsonify({
        "message": "CV của bạn đã được gửi và mã hóa thành công!",
        "file_id": file_id
    }), 200

# --- Route để tải và giải mã CV ---
@app.route('/download_cv/<file_id>', methods=['GET'])
def download_cv(file_id):
    combined_encrypted_file_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.json_enc")

    if not os.path.exists(combined_encrypted_file_path):
        print(f"Không tìm thấy CV với ID: {file_id}")
        abort(404, description="CV không tìm thấy hoặc đã bị xóa.")

    try:
        with open(combined_encrypted_file_path, 'r') as f:
            encrypted_data_bundle = json.load(f)

        # Lấy các thành phần mã hóa từ bundle
        encrypted_cv_content = encrypted_data_bundle.get("cv_ciphertext")
        encrypted_key_iv_cv = encrypted_data_bundle.get("cv_key_iv_bundle")
        tag_cv = encrypted_data_bundle.get("cv_tag")

        encrypted_metadata_content = encrypted_data_bundle.get("meta_ciphertext")
        encrypted_key_iv_meta = encrypted_data_bundle.get("meta_key_iv_bundle")
        tag_meta = encrypted_data_bundle.get("meta_tag")

        if not all([encrypted_cv_content, encrypted_key_iv_cv, tag_cv,
                     encrypted_metadata_content, encrypted_key_iv_meta, tag_meta]):
            return jsonify({"error": "Dữ liệu mã hóa không đầy đủ trong file lưu trữ."}), 500

        # Giải mã Metadata để lấy tên file gốc
        decrypted_metadata_bytes = decrypt_payload_hybrid(
            encrypted_key_iv_meta, encrypted_metadata_content, tag_meta
        )
        if decrypted_metadata_bytes is None:
            return jsonify({"error": "Không thể giải mã thông tin CV. Kiểm tra khóa hoặc dữ liệu hỏng."}), 500
        
        metadata = json.loads(decrypted_metadata_bytes.decode('utf-8'))
        original_filename = metadata.get("original_filename", f"cv_{file_id}.bin")

        # Giải mã nội dung CV
        decrypted_cv_content = decrypt_payload_hybrid(
            encrypted_key_iv_cv, encrypted_cv_content, tag_cv
        )
        if decrypted_cv_content is None:
            return jsonify({"error": "Không thể giải mã nội dung CV. Kiểm tra khóa hoặc dữ liệu hỏng."}), 500

        # Gửi file đã giải mã về client
        from flask import make_response
        response = make_response(decrypted_cv_content)
        response.headers["Content-Disposition"] = f"attachment; filename={original_filename}"
        response.headers["Content-Type"] = "application/octet-stream"
        return response

    except json.JSONDecodeError:
        print(f"Lỗi JSON khi đọc file mã hóa tổng hợp cho ID: {file_id}")
        return jsonify({"error": "Định dạng file lưu trữ không hợp lệ."}), 500
    except Exception as e:
        print(f"Lỗi không xác định khi tải xuống/giải mã CV ID {file_id}: {e}")
        return jsonify({"error": f"Lỗi máy chủ: {e}"}), 500

if __name__ == '__main__':
    print("\n--- Ứng dụng Gửi CV An Toàn đã khởi động ---")
    print(f"Địa chỉ truy cập: http://127.0.0.1:5000/")
    print(f"Thư mục lưu trữ CV đã mã hóa: {UPLOAD_FOLDER}")
    print(f"IP được phép: {', '.join(ALLOWED_IPS)}")
    print("\n!!! LƯU Ý QUAN TRỌNG: Mật khẩu khóa bí mật đang được HARDCODE trong app.py. ")
    print("                 Trong sản phẩm, hãy sử dụng biến môi trường hoặc hệ thống quản lý bí mật. !!!")
    print("--------------------------------------------------------------------------------------------------\n")
app.run(debug=True, host='0.0.0.0', port=5000)