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

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    seed_hash = Column(String, primary_key=True, index=True)
    passwords = relationship("Password", back_populates="user")

class UpdatePasswordData(BaseModel):
    password_name: str
    new_password_value: str
    service: str
    email: str
    username: str

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

Base.metadata.create_all(bind=engine)

app = FastAPI()

def hash_seed(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()

def generate_seed(word_count: int = 12) -> str:
    with open("english_words.txt", "r") as file:
        words = [word.strip() for word in file.read().split(',')]
    seed_words = random.sample(words, word_count)

    return ' '.join(seed_words)

def generate_key_from_seed(seed: str) -> bytes:
    seed_hash = hashlib.sha256(seed.encode()).digest()
    return seed_hash[:32]

def encrypt_data(data: str, key: bytes) -> bytes:
    iv = os.urandom(16)  # Инициализационный вектор (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_data

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return data.decode()

class SeedRequest(BaseModel):
    seed: str

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
        existing_user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Пользователь с такой сид-фразой уже существует")
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
        user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        return {"message": "Вход выполнен"}
    finally:
        db.close()

@app.post("/save_password")
async def save_password(seed: str = Body(...), password_data: PasswordData = Body(...)):
    seed_hash = hash_seed(seed)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")

        encryption_key = generate_key_from_seed(seed)

        encrypted_password = encrypt_data(password_data.password_value, encryption_key)

        encrypted_password_hex = encrypted_password.hex()

        password_count = db.query(Password).filter(Password.seed_hash == seed_hash).count()
        password_name = f"Password_{password_count + 1}"

        new_password = Password(
            seed_hash=seed_hash,
            password_name=password_name,
            password_value=encrypted_password_hex,
            service=password_data.service,
            email=password_data.email,
            username=password_data.username
        )
        db.add(new_password)
        db.commit()
        print("Сохраненные данные:", new_password)
        return {"message": "Пароль сохранен", "password_name": password_name}
    finally:
        db.close()


@app.get("/get_passwords")
async def get_passwords(seed: str):
    seed_hash = hash_seed(seed)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")

        encryption_key = generate_key_from_seed(seed)

        passwords = db.query(Password).filter(Password.seed_hash == seed_hash).order_by(Password.id.desc()).all()

        decrypted_passwords = []
        for password in passwords:
            try:
                encrypted_password_bytes = bytes.fromhex(password.password_value)
                decrypted_password_value = decrypt_data(encrypted_password_bytes, encryption_key)
                print("Полученные данные из БД:", password.username)
                decrypted_passwords.append({
                    "password_name": password.password_name,
                    "password_value": decrypted_password_value,
                    "service": password.service,
                    "email": password.email,
                    "username": password.username
                })
            except ValueError as e:
                print(f"Ошибка при расшифровке пароля {password.password_name}: {str(e)}")
                continue

        return {"passwords": decrypted_passwords}
    finally:
        db.close()

@app.post("/delete_password")
async def delete_password(seed: str = Body(...), password_name: str = Body(...)):
    seed_hash = hash_seed(seed)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")

        password = db.query(Password).filter(
            Password.seed_hash == seed_hash,
            Password.password_name == password_name
        ).first()
        if not password:
            raise HTTPException(status_code=404, detail="Пароль не найден")

        db.delete(password)
        db.commit()

        all_passwords = db.query(Password) \
            .filter(Password.seed_hash == seed_hash) \
            .order_by(Password.id.asc()) \
            .all()

        for index, p in enumerate(all_passwords, start=1):
            p.password_name = f"Password_{index}"
        db.commit()

        return {"message": "Пароль успешно удален"}
    finally:
        db.close()

@app.post("/update_password")
async def update_password(seed: str = Body(...), password_data: UpdatePasswordData = Body(...)):
    seed_hash = hash_seed(seed)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")

        password = db.query(Password).filter(
            Password.seed_hash == seed_hash, Password.password_name == password_data.password_name
        ).first()

        if not password:
            raise HTTPException(status_code=404, detail="Пароль не найден")

        encryption_key = generate_key_from_seed(seed)
        encrypted_password = encrypt_data(password_data.new_password_value, encryption_key)
        encrypted_password_hex = encrypted_password.hex()
        password.password_value = encrypted_password_hex
        password.service = password_data.service
        password.email = password_data.email
        password.username = password_data.username
        db.commit()

        return {"message": "Пароль успешно обновлен"}
    finally:
        db.close()

@app.get("/export_passwords")
async def export_passwords(seed: str):
    seed_hash = hash_seed(seed)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        encryption_key = generate_key_from_seed(seed)
        passwords = db.query(Password).filter(Password.seed_hash == seed_hash).all()

        decrypted_passwords = []
        for password in passwords:
            try:
                encrypted_password_bytes = bytes.fromhex(password.password_value)
                decrypted_password_value = decrypt_data(encrypted_password_bytes, encryption_key)
                decrypted_passwords.append(f"Service: {password.service}\nUsername: {password.username}\nEmail: {password.email}\nPassword: {decrypted_password_value}\n")
            except ValueError as e:
                continue

        return {"passwords": "\n\n".join(decrypted_passwords)}
    finally:
        db.close()
