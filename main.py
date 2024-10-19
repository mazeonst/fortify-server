from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Integer, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
import hashlib
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

DATABASE_URL = "sqlite:///./test.db"

# Создаем подключение к базе данных
engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Определяем модель пользователя
class User(Base):
    __tablename__ = "users"
    seed_hash = Column(String, primary_key=True, index=True)
    passwords = relationship("Password", back_populates="user")

# Определяем модель пароля
class Password(Base):
    __tablename__ = "passwords"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    seed_hash = Column(String, ForeignKey("users.seed_hash"))
    password_name = Column(String, index=True)
    password_value = Column(String)
    service = Column(String)
    email = Column(String)
    username = Column(String)
    user = relationship("User", back_populates="passwords")

# Создаем таблицы
Base.metadata.create_all(bind=engine)

# Создаем FastAPI приложение
app = FastAPI()

# Функция для хэширования сид-фразы
def hash_seed(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()

# Функция для генерации случайной сид-фразы
def generate_seed(length: int = 16) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Функция для генерации ключа шифрования из seed-фразы
def generate_key_from_seed(seed: str) -> bytes:
    seed_hash = hashlib.sha256(seed.encode()).digest()
    return seed_hash[:32]  # Используем первые 32 байта хэша

# Функция для шифрования данных
def encrypt_data(data: str, key: bytes) -> bytes:
    iv = os.urandom(16)  # Инициализационный вектор (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Выравниваем данные до длины кратной 16 байтам (блочное шифрование)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    # Шифруем данные
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Возвращаем IV + зашифрованные данные
    return iv + encrypted_data

# Функция для расшифровки данных
def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    iv = encrypted_data[:16]  # Первые 16 байт — это IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Расшифровываем данные
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    # Убираем добавленное выравнивание
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return data.decode()

class SeedRequest(BaseModel):
    seed: str

# Pydantic модель для данных пользователя
class PasswordData(BaseModel):
    password_name: str
    password_value: str
    service: str
    email: str
    username: str

@app.post("/register")
async def register_user():
    seed = generate_seed()
    seed_hash = hash_seed(seed)
    db = SessionLocal()
    try:
        # Проверяем, существует ли пользователь
        existing_user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Пользователь с такой сид-фразой уже существует")
        # Создаем нового пользователя
        new_user = User(seed_hash=seed_hash)
        db.add(new_user)
        db.commit()
        return {"message": "Пользователь зарегистрирован", "seed": seed}
    finally:
        db.close()

@app.post("/login")
async def login_user(seed_data: SeedRequest):
    seed = seed_data.seed
    seed_hash = hash_seed(seed)
    db = SessionLocal()
    try:
        # Проверяем, существует ли пользователь
        user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        return {"message": "Вход выполнен"}
    finally:
        db.close()


@app.get("/get_passwords")
async def get_passwords(seed: str):
    seed_hash = hash_seed(seed)
    print(f"Хэш для сид-фразы {seed}: {seed_hash}")  # Вывод хэша для проверки
    db = SessionLocal()
    try:
        # Проверяем, существует ли пользователь
        user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if not user:
            print("Пользователь не найден для сид-хэша:", seed_hash)  # Логирование
            raise HTTPException(status_code=404, detail="Пользователь не найден")

        # Получаем все пароли пользователя
        passwords = db.query(Password).filter(Password.seed_hash == seed_hash).all()
        print(f"Найдено паролей: {len(passwords)}")  # Выводим количество найденных паролей

        # Расшифровываем пароли перед отправкой
        decrypted_passwords = []
        for pwd in passwords:
            try:
                encrypted_password_bytes = bytes.fromhex(pwd.password_value)
                print(f"Зашифрованный пароль (hex): {pwd.password_value}")  # Вывод зашифрованных данных

                decrypted_password_value = decrypt_data(encrypted_password_bytes, generate_key_from_seed(seed))
                print(f"Расшифрованный пароль: {decrypted_password_value}")  # Вывод расшифрованного пароля

                decrypted_passwords.append({
                    "password_name": pwd.password_name,
                    "password_value": decrypted_password_value,
                    "service": pwd.service,
                    "email": pwd.email,
                    "username": pwd.username
                })
            except ValueError as e:
                print(f"Ошибка при расшифровке пароля {pwd.password_name}: {str(e)}")
                continue

        return {"passwords": decrypted_passwords}
    finally:
        db.close()


@app.get("/get_passwords")
async def get_passwords(seed: str):
    seed_hash = hash_seed(seed)
    db = SessionLocal()
    try:
        # Проверяем, существует ли пользователь
        user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")

        # Генерация ключа шифрования из seed-фразы
        encryption_key = generate_key_from_seed(seed)

        # Получаем все зашифрованные пароли пользователя и сортируем их по порядковому номеру в обратном порядке
        passwords = db.query(Password).filter(Password.seed_hash == seed_hash).order_by(Password.id.desc()).all()

        # Расшифровываем пароли перед отправкой
        decrypted_passwords = []
        for pwd in passwords:
            try:
                # Преобразуем из hex в байты для расшифровки
                encrypted_password_bytes = bytes.fromhex(pwd.password_value)
                decrypted_password_value = decrypt_data(encrypted_password_bytes, encryption_key)
                decrypted_passwords.append({
                    "password_name": pwd.password_name,
                    "password_value": decrypted_password_value,
                    "service": pwd.service,
                    "email": pwd.email,
                    "username": pwd.username
                })
            except ValueError as e:
                # Логгируем или игнорируем пароли с некорректными данными
                print(f"Ошибка при расшифровке пароля {pwd.password_name}: {str(e)}")
                continue

        return {"passwords": decrypted_passwords}
    finally:
        db.close()

@app.post("/delete_password")
async def delete_password(seed: str = Body(...), password_name: str = Body(...)):
    seed_hash = hash_seed(seed)
    db = SessionLocal()
    try:
        # Проверяем, существует ли пользователь
        user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")

        # Проверяем, существует ли пароль
        password = db.query(Password).filter(Password.seed_hash == seed_hash, Password.password_name == password_name).first()
        if not password:
            raise HTTPException(status_code=404, detail="Пароль не найден")

        # Удаляем пароль из базы данных
        db.delete(password)
        db.commit()
        return {"message": "Пароль успешно удален"}
    finally:
        db.close()
