from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from passlib.hash import pbkdf2_sha256

from app import SessionLocal, Company, User  # importa do app.py (mesmo pacote)

router = APIRouter()

class RegisterIn(BaseModel):
    company: str
    cnpj: str | None = None
    email: EmailStr
    password: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/register")
def register(data: RegisterIn, db: Session = Depends(get_db)):
    # se já existir usuário
    if db.query(User).filter_by(email=data.email).first():
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")

    # cria empresa
    comp = Company(name=data.company, cnpj=data.cnpj or "", plan="demo", response_limit=10000)
    db.add(comp)
    db.commit()
    db.refresh(comp)

    # cria usuário admin
    user = User(
        email=data.email,
        pwd_hash=pbkdf2_sha256.hash(data.password),
        role="admin",
        company_id=comp.id
    )
    db.add(user)
    db.commit()

    return {"ok": True, "company_id": comp.id, "email": user.email}
