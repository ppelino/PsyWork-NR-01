# backend/register_route.py
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from passlib.hash import pbkdf2_sha256
from itsdangerous import TimestampSigner
from pydantic import BaseModel
from datetime import datetime
from app import SessionLocal, Company, User  # importa o modelo já existente

router = APIRouter()
signer = TimestampSigner("dev-secret")  # pode usar os mesmos valores do app.py


class RegisterIn(BaseModel):
    email: str
    password: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/api/register")
def register_user(data: RegisterIn, db: Session = Depends(get_db)):
    # Evita duplicação de e-mail
    if db.query(User).filter_by(email=data.email).first():
        raise HTTPException(400, "E-mail já cadastrado.")

    # Cria automaticamente a empresa demo
    company = Company(
        name=f"Empresa de {data.email.split('@')[0]}",
        cnpj="00.000.000/0000-00",
        plan="demo",
        response_limit=10000,
    )
    db.add(company)
    db.commit()

    # Cria o usuário administrador
    user = User(
        email=data.email,
        pwd_hash=pbkdf2_sha256.hash(data.password),
        role="admin",
        company_id=company.id,
    )
    db.add(user)
    db.commit()

    return {
        "ok": True,
        "message": "Cadastro realizado com sucesso! Agora você já pode fazer login.",
        "company": company.name,
        "email": user.email,
    }
