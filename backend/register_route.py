from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, sessionmaker, declarative_base
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from passlib.hash import pbkdf2_sha256
import os

# === Config do banco (igual ao app.py, mas independente) ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_URL = os.getenv("DATABASE_URL")
if DB_URL:
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
else:
    DB_URL = f"sqlite:///{os.path.join(BASE_DIR, 'nr01.db')}"

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()

# === Modelos mínimos só para cadastro ===
class Company(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    cnpj = Column(String, nullable=True)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    pwd_hash = Column(String, nullable=False)
    role = Column(String, default="admin")
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)


router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/register")
def register_company(data: dict, db: Session = Depends(get_db)):
    """
    Rota pública de cadastro de empresa + usuário admin inicial.
    """
    name = data.get("name")
    cnpj = data.get("cnpj")
    email = data.get("email")
    password = data.get("password")

    if not all([name, email, password]):
        raise HTTPException(status_code=400, detail="Dados incompletos")

    if db.query(User).filter_by(email=email).first():
        raise HTTPException(status_code=400, detail="Usuário já existe")

    company = Company(name=name, cnpj=cnpj)
    db.add(company)
    db.commit()
    db.refresh(company)

    user = User(
        email=email,
        pwd_hash=pbkdf2_sha256.hash(password),
        role="admin",
        company_id=company.id,
    )
    db.add(user)
    db.commit()

    return {"ok": True, "message": "Empresa cadastrada com sucesso"}

