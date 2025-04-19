from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Integer, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
import hashlib
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding, hashes
from base64 import b64encode, b64decode
import os

DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    seed_hash = Column(String, primary_key=True, index=True)
    passwords = relationship("Password", back_populates="user")

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

def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)

def generate_key_from_seed(seed: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(seed.encode())

def hash_seed(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()

def generate_seed(length: int = 16) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_key_from_seed(seed: str) -> bytes:
    seed_hash = hashlib.sha256(seed.encode()).digest()
    return seed_hash[:32]

def encrypt_data(data: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return b64encode(iv + encrypted_data).decode()

    encrypted_password = encrypt_data(password_data.password_value, encryption_key)

    encrypted_password_base64 = encrypted_password

    new_password = Password(
        seed_hash=seed_hash,
        password_name=password_name,
        password_value=encrypted_password_base64,
        service=password_data.service,
        email=password_data.email,
        username=password_data.username
    )


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

        encrypted_password_base64 = encrypted_password

        password_count = db.query(Password).filter(Password.seed_hash == seed_hash).count()
        password_name = f"Password_{password_count + 1}"

        new_password = Password(
            seed_hash=seed_hash,
            password_name=password_name,
            password_value=encrypted_password_base64,
            service=password_data.service,
            email=password_data.email,
            username=password_data.username
        )
        db.add(new_password)
        db.commit()
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
        for pwd in passwords:
            try:
                encrypted_password_bytes = b64decode(pwd.password_value)
                decrypted_password_value = decrypt_data(encrypted_password_bytes, encryption_key)
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

@app.post("/delete_password")
async def delete_password(seed: str = Body(...), password_name: str = Body(...)):
    seed_hash = hash_seed(seed)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.seed_hash == seed_hash).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")

        password = db.query(Password).filter(Password.seed_hash == seed_hash, Password.password_name == password_name).first()
        if not password:
            raise HTTPException(status_code=404, detail="Пароль не найден")

        db.delete(password)
        db.commit()
        return {"message": "Пароль успешно удален"}
    finally:
        db.close()
