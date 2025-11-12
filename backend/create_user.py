import argparse
import os, json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.hash import pbkdf2_sha256
from backend.app import Base, Company, User, DB_URL, SessionLocal


def create_user(email, password, company_name, cnpj, role):
    db = SessionLocal()
    company = db.query(Company).filter_by(name=company_name).first()
    if not company:
        company = Company(name=company_name, cnpj=cnpj, plan="demo", response_limit=10000)
        db.add(company)
        db.commit()
    user = db.query(User).filter_by(email=email).first()
    if user:
        print(f"⚠️ Usuário '{email}' já existe.")
        return
    pwd_hash = pbkdf2_sha256.hash(password)
    user = User(email=email, pwd_hash=pwd_hash, role=role, company_id=company.id)
    db.add(user)
    db.commit()
    print(f"✅ Usuário criado com sucesso!\n  E-mail: {email}\n  Empresa: {company_name}\n  Cargo: {role}")
    db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Criar usuário admin ou comum para o Avalia NR01.")
    parser.add_argument("--email", required=True, help="E-mail do usuário")
    parser.add_argument("--password", required=True, help="Senha do usuário")
    parser.add_argument("--company", required=True, help="Nome da empresa")
    parser.add_argument("--cnpj", required=False, default="00.000.000/0001-00", help="CNPJ da empresa")
    parser.add_argument("--role", required=False, default="admin", choices=["admin", "user"], help="Função do usuário")
    args = parser.parse_args()
    create_user(args.email, args.password, args.company, args.cnpj, args.role)
