#!/usr/bin/env python
import os, sys, argparse, csv, io, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app import SessionLocal, Company, User, Campaign, Response  # type: ignore
from passlib.hash import pbkdf2_sha256

def create_user(email, password, company=None, cnpj=None, company_id=None):
    db = SessionLocal()
    try:
        if company_id:
            comp = db.query(Company).filter_by(id=company_id).first()
            if not comp: raise SystemExit(f"Empresa id={company_id} não encontrada.")
        else:
            comp = db.query(Company).filter_by(name=company).first() if company else None
            if not comp:
                comp = Company(name=company or "EMPRESA", cnpj=cnpj or None, plan="demo", response_limit=10000)
                db.add(comp); db.commit()
                print(f"Criada empresa id={comp.id} nome={comp.name}")
        if db.query(User).filter_by(email=email).first(): raise SystemExit("E-mail já existe.")
        user = User(email=email, pwd_hash=pbkdf2_sha256.hash(password), role="admin", company_id=comp.id)
        db.add(user); db.commit()
        print(f"Usuário criado: {user.email} (company_id={comp.id})")
    finally:
        db.close()

def change_password(email, password):
    db = SessionLocal()
    try:
        u = db.query(User).filter_by(email=email).first()
        if not u: raise SystemExit("Usuário não encontrado.")
        u.pwd_hash = pbkdf2_sha256.hash(password); db.commit(); print("Senha atualizada.")
    finally:
        db.close()

def list_users():
    db = SessionLocal()
    try:
        for u in db.query(User).all():
            print(f"{u.id}\t{u.email}\trole={u.role}\tcompany_id={u.company_id}")
    finally:
        db.close()

def list_campaigns():
    db = SessionLocal()
    try:
        for c in db.query(Campaign).order_by(Campaign.id.desc()).all():
            print(f"{c.id}\t{c.title}\tcompany_id={c.company_id}\tactive={c.active}\ttoken={c.token}")
    finally:
        db.close()

def deactivate_campaign(cid:int):
    db = SessionLocal()
    try:
        c = db.query(Campaign).filter_by(id=cid).first()
        if not c: raise SystemExit("Campanha não encontrada.")
        c.active = False; db.commit(); print("Campanha desativada.")
    finally:
        db.close()

def export_csv(campaign_id:int, out:str):
    db = SessionLocal()
    try:
        items = db.query(Response).filter_by(campaign_id=campaign_id).all()
        if not items: open(out,"w",encoding="utf-8").write(""); print("Sem respostas; CSV vazio."); return
        first = json.loads(items[0].answers)
        headers = ["created_at","sector","ghe","ges","environment"] + [f"Q{k}" for k in sorted(map(int,first.keys()))]
        import csv
        with open(out,"w",newline="",encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=headers); w.writeheader()
            for it in items:
                ans = json.loads(it.answers)
                row={"created_at":it.created_at.isoformat(),"sector":it.sector,"ghe":it.ghe,"ges":it.ges,"environment":it.environment}
                for k,v in ans.items(): row[f"Q{int(k)}"]=v
                w.writerow(row)
        print(f"CSV exportado em {out}")
    finally:
        db.close()

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("create-user")
    s1.add_argument("--email", required=True)
    s1.add_argument("--password", required=True)
    s1.add_argument("--company")
    s1.add_argument("--cnpj")
    s1.add_argument("--company-id", type=int)

    s2 = sub.add_parser("change-password")
    s2.add_argument("--email", required=True)
    s2.add_argument("--password", required=True)

    sub.add_parser("list-users")
    sub.add_parser("list-campaigns")

    s5 = sub.add_parser("deactivate-campaign")
    s5.add_argument("--id", type=int, required=True)

    s6 = sub.add_parser("export-csv")
    s6.add_argument("--campaign-id", type=int, required=True)
    s6.add_argument("--out", required=True)

    a = p.parse_args()
    if a.cmd=="create-user": create_user(a.email,a.password,a.company,a.cnpj,a.company_id)
    elif a.cmd=="change-password": change_password(a.email,a.password)
    elif a.cmd=="list-users": list_users()
    elif a.cmd=="list-campaigns": list_campaigns()
    elif a.cmd=="deactivate-campaign": deactivate_campaign(a.id)
    elif a.cmd=="export-csv": export_csv(a.campaign_id,a.out)

if __name__ == "__main__":
    main()
