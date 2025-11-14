from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from passlib.hash import pbkdf2_sha256

from app import SessionLocal, Company, User

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
    É chamada pela tela de 'Cadastre-se'.
    """
    name = data.get("name")
    cnpj = data.get("cnpj")
    email = data.get("email")
    password = data.get("password")

    if not all([name, email, password]):
        raise HTTPException(status_code=400, detail="Dados incompletos")

    # Evita criar usuário duplicado
    if db.query(User).filter_by(email=email).first():
        raise HTTPException(status_code=400, detail="Usuário já existe")

    # Cria empresa
    company = Company(name=name, cnpj=cnpj)
    db.add(company)
    db.commit()
    db.refresh(company)

    # Cria usuário admin vinculado à nova empresa
    user = User(
        email=email,
        pwd_hash=pbkdf2_sha256.hash(password),
        role="admin",
        company_id=company.id,
    )
    db.add(user)
    db.commit()

    return {"ok": True, "message": "Empresa cadastrada com sucesso"}
