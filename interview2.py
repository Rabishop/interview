import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class EncryptionWithSalt:
    def __init__(self, salt: str, iv: str):
        """
        コンストラクタ
        :param salt: ソルト文字列
        :param iv: 初期化ベクトル（16進数文字列）
        """
        self.salt = salt
        self.algorithm = 'aes-256-cbc'  # 使用するアルゴリズム
        self.key_length = 32  # AES-256の鍵長（32バイト）
        self.iv_length = 16   # 初期化ベクトルの長さ（16バイト）
        self.digest = 'sha256'  # ハッシュ関数

        # 16進数文字列の場合の検証
        if len(iv) != self.iv_length * 2:
            raise ValueError(f"IVの長さが無効です。期待される長さ: {self.iv_length * 2}文字, 実際の長さ: {len(iv)}文字")
        self.iv = bytes.fromhex(iv)

    def derive_key(self, password: str):
        """
        :param password: パスワード
        :return: 導出された鍵（バイト列）またはFalse
        """
        # パスワードの長さチェック
        if len(password) < 8:
            return None
        # ソルトとパスワードを連結
        combined = self.salt + password
        # SHA-256ハッシュを計算
        hash_obj = hashlib.sha256(combined.encode('utf-8'))
        return hash_obj.digest()

    def encrypt(self, plaintext: str, password: str):
        """
        平文を暗号化する

        :param plaintext: 暗号化するテキスト
        :param password: パスワード
        :return: 暗号文（16進数文字列）またはFalse
        """
        key = self.derive_key(password)
        if not key:
            return False

        # 暗号化オブジェクトの作成
        cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # パディングを適用（PKCS7）
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        # 暗号化
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        # 16進数文字列に変換して返す
        return encrypted.hex()

    def decrypt(self, ciphertext: str, password: str):
        """
        暗号文を復号化する

        :param ciphertext: 暗号文（16進数文字列）
        :param password: パスワード
        :return: 復号化された平文またはFalse
        """
        key = self.derive_key(password)
        if not key:
            return False

        try:
            # 暗号化オブジェクトの作成
            cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv), backend=default_backend())
            decryptor = cipher.decryptor()

            # 暗号文をバイト列に変換
            encrypted_bytes = bytes.fromhex(ciphertext)

            # 復号化
            decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()

            # パディングを除去
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

            return decrypted.decode('utf-8')
        except Exception as e:
            # 復号化に失敗した場合はFalseを返す
            return False

class TestEncryptionWithSalt:
    def test_encrypt(self):
        salt = "1234"
        fixed_iv = '000102030405060708090a0b0c0d0e0f'
        encryption = EncryptionWithSalt(salt, fixed_iv)
        plaintext = "hello world"
        password = "password"

        ciphertext = encryption.encrypt(plaintext, password)
        expected_ciphertext = "69ffd2a4a4f3c46a15cd7154c3ebb02c"
        assert ciphertext == expected_ciphertext, f"testEncrypt Failed: Expected {expected_ciphertext}, got {ciphertext}"

    def test_decrypt(self):
        salt = "5678"
        fixed_iv = '000102030405060708090a0b0c0d0e0f'
        expected_plaintext = "hello world"
        password = "password"
        encryption = EncryptionWithSalt(salt, fixed_iv)
        # 以下を記述
        
        ciphertext = encryption.encrypt(expected_plaintext, password)
        decrypted_text = encryption.decrypt(ciphertext, password)
        print("ciphertext:", ciphertext)
        print("decrypted_text:", decrypted_text)
        
        assert decrypted_text == expected_plaintext, f"testDecrypt Failed: Expected {expected_plaintext}, got {decrypted_text}"

    def testDeriveKey(self):
        salt = "abcd"
        fixed_iv = '000102030405060708090a0b0c0d0e0f'
        expected_plaintext = "hello world"
        password1 = "passwor"
        password2 = "password"
        password3 = "password1"
        encryption = EncryptionWithSalt(salt, fixed_iv)
        # 以下を記述
        
        ciphertext1 = encryption.encrypt(expected_plaintext, password1)
        print("ciphertext1:", ciphertext1)
        if ciphertext1 == False:
            print("password1 is too short")

        ciphertext2 = encryption.encrypt(expected_plaintext, password2)
        print("ciphertext2:", ciphertext2)
        if ciphertext2 == False:
            print("password2 is too short")

        ciphertext3 = encryption.encrypt(expected_plaintext, password3)
        print("ciphertext3:", ciphertext3)
        if ciphertext3 == False:
            print("password3 is too short")


def main():
    test = TestEncryptionWithSalt()
    
    test.test_encrypt()
    print("--------------------------------question1--------------------------------")
    test.test_decrypt()
    print("--------------------------------question2--------------------------------")
    test.testDeriveKey()
    print("\nAll tests completed successfully.")

main()