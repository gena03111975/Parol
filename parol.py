import re
import hashlib

def check_password_strength(password):
    if len(password) < 8:
        return False, "Пароль должен содержать не менее 8 символов."
    if not re.search(r"[A-Z]", password):
        return False, "Пароль должен содержать хотя бы одну прописную букву."
    if not re.search(r"[a-z]", password):
        return False, "Пароль должен содержать хотя бы одну строчную букву."
    if not re.search(r"\d", password):
        return False, "Пароль должен содержать хотя бы одну цифру."
    return True, "Пароль достаточно сложный."

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

password = input("Введите пароль: ")
is_strong, message = check_password_strength(password)
print(message)

if is_strong:
    hashed_password = hash_password(password)
    print(f"Хэш-значение пароля: {hashed_password}")
