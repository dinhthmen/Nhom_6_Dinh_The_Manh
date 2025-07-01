from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

def generate_rsa_keys():
    """
    Tạo cặp khóa RSA (công khai và bí mật) và lưu vào các tệp .pem.
    Khóa bí mật được mã hóa bằng mật khẩu.
    """
    print("Đang tạo cặp khóa RSA...")

    # Tạo khóa bí mật RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Giá trị công khai tiêu chuẩn
        key_size=2048,          # Kích thước khóa 2048-bit (khuyến nghị cho bảo mật)
        backend=default_backend()
    )

    # Lấy khóa công khai từ khóa bí mật
    public_key = private_key.public_key()

    # Nhập mật khẩu cho khóa bí mật
    # RẤT QUAN TRỌNG: Hãy chọn một mật khẩu mạnh và GHI NHỚ nó!
    # Mật khẩu này sẽ cần thiết khi tải khóa bí mật trong app.py
    password = input("Vui lòng nhập mật khẩu MẠNH cho khóa bí mật của bạn: ").encode('utf-8')
    confirm_password = input("Vui lòng xác nhận mật khẩu: ").encode('utf-8')

    if password != confirm_password:
        print("Lỗi: Mật khẩu xác nhận không khớp. Vui lòng thử lại.")
        return

    # Lưu khóa bí mật vào tệp .pem (được mã hóa)
    try:
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            ))
        print("private_key.pem đã được tạo thành công.")
    except Exception as e:
        print(f"Lỗi khi lưu private_key.pem: {e}")
        return

    # Lưu khóa công khai vào tệp .pem
    try:
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("public_key.pem đã được tạo thành công.")
    except Exception as e:
        print(f"Lỗi khi lưu public_key.pem: {e}")
        return

    print("Quá trình tạo khóa RSA hoàn tất.")

if __name__ == "__main__":
    generate_rsa_keys()