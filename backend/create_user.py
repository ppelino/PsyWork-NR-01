# backend/create_user.py
from passlib.hash import pbkdf2_sha256
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey
import os

# ==== Config do DB (igual ao app.py) ====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_URL = f"sqlite:///{os.path.join(BASE_DIR, 'nr01.db')}"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()

# ==== Modelos mínimos ====
class Company(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True)
    name = Column(String)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    pwd_hash = Column(String, nullable=False)
    role = Column(String, default="admin")
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)

def main():
    print("=== Criar novo usuário ===")
    email = input("E-mail: ").strip()
    senha = input("Senha : ").strip()
    role  = input("Role (admin/user) [admin]: ").strip() or "admin"

    db = SessionLocal()
    try:
        # usa a primeira empresa existente
        comp = db.query(Company).first()
        if not comp:
            print("❌ Nenhuma company encontrada. Entre no sistema (demo) ao menos 1x para criar os dados iniciais.")
            return

        # checa se já existe
        exists = db.query(User).filter_by(email=email).first()
        if exists:
            print("❌ Já existe um usuário com esse e-mail.")
            return

        user = User(
            email=email,
            pwd_hash=pbkdf2_sha256.hash(senha),
            role=role,
            company_id=comp.id
        )
        db.add(user)
        db.commit()
        print(f"✅ Usuário criado: {email} (role={role})")
    finally:
        db.close()

if __name__ == "__main__":
    main()
