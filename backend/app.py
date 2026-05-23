from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean, Text
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from datetime import datetime
from passlib.hash import pbkdf2_sha256
from itsdangerous import TimestampSigner, BadSignature
import os, secrets, json

# ==========================
# PLANOS FIXOS
# ==========================
PLAN_LIMITS = {
    "demo": {
        "label": "Demo",
        "campaign_limit": 1,
        "response_limit": 20
    },
    "basico": {
        "label": "Básico",
        "campaign_limit": 3,
        "response_limit": 100
    },
    "profissional": {
        "label": "Profissional",
        "campaign_limit": 10,
        "response_limit": 1000
    },
    "premium": {
        "label": "Premium",
        "campaign_limit": None,
        "response_limit": None
    }
}


def normalize_plan(plan):
    plan = (plan or "demo").lower().strip()
    if plan not in PLAN_LIMITS:
        return "demo"
    return plan


def get_plan_limits(plan):
    return PLAN_LIMITS[normalize_plan(plan)]


# ==========================
# Token
# ==========================
signer = TimestampSigner(os.environ.get("NR01_SECRET", "dev-secret"))

# ==========================
# Banco
# ==========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_URL = os.environ.get("DB_URL") or os.environ.get("DATABASE_URL")

if not DB_URL:
    raise Exception("DB_URL ou DATABASE_URL não configurado no ambiente")

engine = create_engine(DB_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()


# ==========================
# Modelos
# ==========================
class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    cnpj = Column(String, nullable=True)
    plan = Column(String, default="demo")
    response_limit = Column(Integer, default=20)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    pwd_hash = Column(String, nullable=False)
    role = Column(String, default="admin")
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    company = relationship("Company")


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    title = Column(String, nullable=False)
    token = Column(String, unique=True, index=True)
    start_at = Column(DateTime, default=datetime.utcnow)
    end_at = Column(DateTime, nullable=True)
    active = Column(Boolean, default=True)
    meta = Column(Text, default="{}")


class Question(Base):
    __tablename__ = "questions"

    id = Column(Integer, primary_key=True)
    dimension = Column(String, nullable=False)
    text = Column(String, nullable=False)


class Response(Base):
    __tablename__ = "responses"

    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    sector = Column(String, nullable=True)
    ghe = Column(String, nullable=True)
    ges = Column(String, nullable=True)
    environment = Column(String, nullable=True)
    answers = Column(Text)
    notes = Column(Text, default="")


Base.metadata.create_all(engine)
def seed_questions_if_empty():
    db = SessionLocal()
    try:
        total = db.query(Question).count()

        if total == 0:
            questions_path = os.path.join(BASE_DIR, "questions.json")

            if os.path.exists(questions_path):
                dataset = json.loads(
                    open(questions_path, "r", encoding="utf-8").read()
                )

                for q in dataset:
                    db.add(Question(dimension=q[0], text=q[1]))

                db.commit()

    finally:
        db.close()


seed_questions_if_empty()


# ==========================
# Seed
# ==========================
ADMIN_EMAIL = os.environ.get("NR01_ADMIN_EMAIL")
ADMIN_PASSWORD = os.environ.get("NR01_ADMIN_PASSWORD")


def seed():
    db = SessionLocal()

    try:
        comp = db.query(Company).first()

        if not comp:
            comp = Company(
                name="DEMO LTDA",
                cnpj="00.000.000/0000-00",
                plan="demo",
                response_limit=20
            )

            db.add(comp)
            db.commit()
            db.refresh(comp)

            questions_path = os.path.join(BASE_DIR, "questions.json")

            if os.path.exists(questions_path):
                dataset = json.loads(
                    open(questions_path, "r", encoding="utf-8").read()
                )

                for q in dataset:
                    db.add(Question(dimension=q[0], text=q[1]))

                db.commit()

        if ADMIN_EMAIL and ADMIN_PASSWORD:
            user = db.query(User).filter_by(email=ADMIN_EMAIL).first()

            if not user:
                user = User(
                    email=ADMIN_EMAIL,
                    pwd_hash=pbkdf2_sha256.hash(ADMIN_PASSWORD),
                    role="admin",
                    company_id=comp.id
                )

                db.add(user)
                db.commit()

    finally:
        db.close()


if os.environ.get("ENABLE_SEED") == "true":
    seed()


# ==========================
# App
# ==========================
app = FastAPI(title="AVALIA NR01")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONT = os.path.join(os.path.dirname(__file__), "../frontend")
app.mount("/frontend", StaticFiles(directory=FRONT), name="frontend")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/frontend/index.html")


# ==========================
# Dependências
# ==========================
def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def auth_user(request: Request, db: Session = Depends(get_db)):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")

    if not token:
        raise HTTPException(401, "unauthorized")

    try:
        payload = signer.unsign(token, max_age=60 * 60 * 24 * 7).decode()
        data = json.loads(payload)
    except BadSignature:
        raise HTTPException(401, "invalid token")

    user = db.query(User).filter_by(id=data["uid"]).first()

    if not user:
        raise HTTPException(401, "not found")

    return user


def require_admin(user):
    if user.role != "admin":
        raise HTTPException(403, "Acesso negado")

    return True


# ==========================
# Schemas
# ==========================
class LoginIn(BaseModel):
    email: str
    password: str


class CompanyIn(BaseModel):
    name: str
    cnpj: str | None = None
    plan: str | None = "demo"


class CampaignIn(BaseModel):
    title: str
    start_at: datetime | None = None
    end_at: datetime | None = None
    meta: dict | None = {}


class PublicResponseIn(BaseModel):
    token: str
    sector: str | None = None
    ghe: str | None = None
    ges: str | None = None
    environment: str | None = None
    answers: dict
    notes: str | None = ""


class AdminCompanyIn(BaseModel):
    name: str
    cnpj: str | None = None
    plan: str | None = "demo"


class AdminCompanyUpdate(BaseModel):
    name: str | None = None
    cnpj: str | None = None
    plan: str | None = None


class AdminUserCompanyUpdate(BaseModel):
    company_id: int
class AdminUserCreate(BaseModel):
    email: str
    password: str
    role: str = "user"
    company_id: int

# ==========================
# Health
# ==========================
@app.get("/api/health")
def health():
    return {"ok": True}


# ==========================
# Login
# ==========================
@app.post("/api/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=data.email).first()

    if not user or not pbkdf2_sha256.verify(data.password, user.pwd_hash):
        raise HTTPException(401, "Credenciais inválidas")

    token = signer.sign(
        json.dumps(
            {
                "uid": user.id,
                "cid": user.company_id
            }
        ).encode()
    ).decode()

    return {
        "token": token,
        "role": user.role,
        "company_id": user.company_id,
        "email": user.email
    }


# ==========================
# Empresa do usuário
# ==========================
@app.post("/api/company")
def update_company(data: CompanyIn, user=Depends(auth_user), db: Session = Depends(get_db)):
    comp = db.query(Company).filter_by(id=user.company_id).first()

    if not comp:
        raise HTTPException(404, "Empresa não encontrada")

    plan = normalize_plan(data.plan)
    limits = get_plan_limits(plan)

    comp.name = data.name
    comp.cnpj = data.cnpj
    comp.plan = plan
    comp.response_limit = limits["response_limit"] if limits["response_limit"] is not None else 999999999

    db.commit()

    return {"ok": True}


# ==========================
# Questões
# ==========================
@app.get("/api/questions")
def get_questions(user=Depends(auth_user), db: Session = Depends(get_db)):
    qs = db.query(Question).all()

    return [
        {
            "id": q.id,
            "dimension": q.dimension,
            "text": q.text
        }
        for q in qs
    ]


# ==========================
# Campanha pública
# ==========================
@app.get("/api/public/campaign/{token}")
def public_campaign_info(token: str, db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter_by(token=token, active=True).first()

    if not camp:
        raise HTTPException(404, "Campanha não encontrada/ativa")

    comp = db.query(Company).filter_by(id=camp.company_id).first()

    return {
        "title": camp.title,
        "company": comp.name if comp else None,
        "start_at": camp.start_at,
        "end_at": camp.end_at,
        "token": camp.token,
    }


@app.get("/api/public/questions/{token}")
def public_questions(token: str, db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter_by(token=token, active=True).first()

    if not camp:
        raise HTTPException(404, "Campanha não encontrada/ativa")

    qs = db.query(Question).all()

    return [
        {
            "id": q.id,
            "dimension": q.dimension,
            "text": q.text
        }
        for q in qs
    ]


# ==========================
# Campanhas
# ==========================
@app.post("/api/campaigns")
def create_campaign(inp: CampaignIn, user=Depends(auth_user), db: Session = Depends(get_db)):
    company = db.query(Company).filter_by(id=user.company_id).first()

    if not company:
        raise HTTPException(404, "Empresa não encontrada")

    plan = normalize_plan(company.plan)
    limits = get_plan_limits(plan)

    total_campaigns = db.query(Campaign).filter_by(company_id=company.id).count()

    if limits["campaign_limit"] is not None and total_campaigns >= limits["campaign_limit"]:
        raise HTTPException(
            403,
            f"Limite de campanhas atingido para o plano {limits['label']}. "
            f"Este plano permite até {limits['campaign_limit']} campanha(s)."
        )

    company.plan = plan
    company.response_limit = limits["response_limit"] if limits["response_limit"] is not None else 999999999

    token = secrets.token_urlsafe(12)

    camp = Campaign(
        company_id=user.company_id,
        title=inp.title,
        token=token,
        start_at=inp.start_at or datetime.utcnow(),
        end_at=inp.end_at,
        active=True,
        meta=json.dumps(inp.meta or {})
    )

    db.add(camp)
    db.commit()
    db.refresh(camp)

    return {
        "id": camp.id,
        "token": token,
        "plan": plan,
        "campaign_limit": limits["campaign_limit"],
        "response_limit": limits["response_limit"]
    }


@app.get("/api/campaigns")
def list_campaigns(user=Depends(auth_user), db: Session = Depends(get_db)):
    camps = (
        db.query(Campaign)
        .filter_by(company_id=user.company_id)
        .order_by(Campaign.id.desc())
        .all()
    )

    return [
        {
            "id": c.id,
            "title": c.title,
            "token": c.token,
            "active": c.active,
            "start_at": c.start_at,
            "end_at": c.end_at
        }
        for c in camps
    ]


@app.delete("/api/campaigns/{campaign_id}")
def delete_campaign(campaign_id: int, user=Depends(auth_user), db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter_by(
        id=campaign_id,
        company_id=user.company_id
    ).first()

    if not camp:
        raise HTTPException(404, "Campanha não encontrada")

    db.query(Response).filter_by(campaign_id=camp.id).delete()
    db.delete(camp)
    db.commit()

    return {"ok": True}


# ==========================
# Resposta pública com bloqueio de plano
# ==========================
@app.post("/api/public/respond")
def public_respond(data: PublicResponseIn, db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter_by(token=data.token, active=True).first()

    if not camp:
        raise HTTPException(404, "Campanha não encontrada/ativa")

    comp = db.query(Company).filter_by(id=camp.company_id).first()

    if not comp:
        raise HTTPException(404, "Empresa não encontrada")

    plan = normalize_plan(comp.plan)
    limits = get_plan_limits(plan)

    total = (
        db.query(Response)
        .join(Campaign, Campaign.id == Response.campaign_id)
        .filter(Campaign.company_id == comp.id)
        .count()
    )

    if limits["response_limit"] is not None and total >= limits["response_limit"]:
        raise HTTPException(
            403,
            f"Limite de respostas atingido para o plano {limits['label']}. "
            f"Este plano permite até {limits['response_limit']} respostas."
        )

    r = Response(
        campaign_id=camp.id,
        sector=data.sector,
        ghe=data.ghe,
        ges=data.ges,
        environment=data.environment,
        answers=json.dumps(data.answers),
        notes=data.notes or ""
    )

    db.add(r)
    db.commit()

    return {"ok": True}


# ==========================
# Summary
# ==========================
@app.get("/api/summary/{campaign_id}")
def summary(campaign_id: int, user=Depends(auth_user), db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter_by(
        id=campaign_id,
        company_id=user.company_id
    ).first()

    if not camp:
        raise HTTPException(404, "Campanha não encontrada")

    qs = {
        q.id: (q.dimension, q.text)
        for q in db.query(Question).all()
    }

    items = db.query(Response).filter_by(campaign_id=camp.id).all()

    dim_scores = {}
    n = 0
    rows = []

    for it in items:
        ans = json.loads(it.answers)
        n += 1

      for qid, score in ans.items():
    question = qs.get(int(qid))

    if question:
        dim = question[0]
    else:
        dim = f"Questão {qid}"

    dim_scores.setdefault(dim, []).append(float(score)) 

        rows.append({
            "created_at": it.created_at.isoformat(),
            "sector": it.sector,
            "ghe": it.ghe,
            "ges": it.ges,
            "environment": it.environment,
            **{
                f"Q{qid}": score
                for qid, score in ans.items()
            }
        })

    avg = {
        d: (sum(v) / len(v) if v else 0)
        for d, v in dim_scores.items()
    }

    actions = []

    for d, score in avg.items():
        if score < 2.5:
            actions.append({
                "dimension": d,
                "priority": "Alta",
                "suggestion": f"Implementar medidas imediatas para {d.lower()}."
            })
        elif score < 3.5:
            actions.append({
                "dimension": d,
                "priority": "Média",
                "suggestion": f"Plano de melhoria para {d.lower()} com responsáveis e prazos."
            })
        else:
            actions.append({
                "dimension": d,
                "priority": "Manter",
                "suggestion": f"Manter boas práticas em {d.lower()} e monitorar periodicamente."
            })

    return {
        "count": n,
        "average": avg,
        "actions": actions,
        "rows": rows,
        "campaign": {
            "id": camp.id,
            "title": camp.title,
            "token": camp.token
        }
    }


# ==========================
# Export CSV
# ==========================
@app.get("/api/export/{campaign_id}")
def export_csv(campaign_id: int, user=Depends(auth_user), db: Session = Depends(get_db)):
    import csv
    import io
    import json as _json

    camp = db.query(Campaign).filter_by(
        id=campaign_id,
        company_id=user.company_id
    ).first()

    if not camp:
        raise HTTPException(404, "Campanha não encontrada")

    items = db.query(Response).filter_by(campaign_id=camp.id).all()

    output = io.StringIO()

    if not items:
        return JSONResponse({"csv": ""})

    first = _json.loads(items[0].answers)

    headers = [
        "created_at",
        "sector",
        "ghe",
        "ges",
        "environment"
    ] + [
        f"Q{k}"
        for k in sorted(map(int, first.keys()))
    ]

    writer = csv.DictWriter(output, fieldnames=headers)
    writer.writeheader()

    for it in items:
        ans = _json.loads(it.answers)

        row = {
            "created_at": it.created_at.isoformat(),
            "sector": it.sector,
            "ghe": it.ghe,
            "ges": it.ges,
            "environment": it.environment
        }

        for k, v in ans.items():
            row[f"Q{int(k)}"] = v

        writer.writerow(row)

    return JSONResponse({"csv": output.getvalue()})


# ==========================
# Admin - Empresas
# ==========================
@app.get("/api/admin/companies")
def admin_list_companies(user=Depends(auth_user), db: Session = Depends(get_db)):
    require_admin(user)

    companies = db.query(Company).order_by(Company.id.desc()).all()

    result = []

    for c in companies:
        plan = normalize_plan(c.plan)
        limits = get_plan_limits(plan)

        result.append({
            "id": c.id,
            "name": c.name,
            "cnpj": c.cnpj,
            "plan": plan,
            "plan_label": limits["label"],
            "campaign_limit": limits["campaign_limit"],
            "response_limit": limits["response_limit"],
            "current_campaigns": db.query(Campaign).filter_by(company_id=c.id).count(),
            "current_responses": (
                db.query(Response)
                .join(Campaign, Campaign.id == Response.campaign_id)
                .filter(Campaign.company_id == c.id)
                .count()
            )
        })

    return result


@app.post("/api/admin/companies")
def admin_create_company(data: AdminCompanyIn, user=Depends(auth_user), db: Session = Depends(get_db)):
    require_admin(user)

    plan = normalize_plan(data.plan)
    limits = get_plan_limits(plan)

    company = Company(
        name=data.name,
        cnpj=data.cnpj,
        plan=plan,
        response_limit=limits["response_limit"] if limits["response_limit"] is not None else 999999999
    )

    db.add(company)
    db.commit()
    db.refresh(company)

    return {"ok": True, "company_id": company.id}


@app.put("/api/admin/companies/{company_id}")
def admin_update_company(company_id: int, data: AdminCompanyUpdate, user=Depends(auth_user), db: Session = Depends(get_db)):
    require_admin(user)

    company = db.query(Company).filter_by(id=company_id).first()

    if not company:
        raise HTTPException(404, "Empresa não encontrada")

    if data.name is not None:
        company.name = data.name

    if data.cnpj is not None:
        company.cnpj = data.cnpj

    if data.plan is not None:
        plan = normalize_plan(data.plan)
        limits = get_plan_limits(plan)

        company.plan = plan
        company.response_limit = limits["response_limit"] if limits["response_limit"] is not None else 999999999

    db.commit()
    db.refresh(company)

    return {"ok": True}


@app.delete("/api/admin/companies/{company_id}")
def admin_delete_company(company_id: int, user=Depends(auth_user), db: Session = Depends(get_db)):
    require_admin(user)

    company = db.query(Company).filter_by(id=company_id).first()

    if not company:
        raise HTTPException(404, "Empresa não encontrada")

    users_count = db.query(User).filter_by(company_id=company_id).count()
    campaigns_count = db.query(Campaign).filter_by(company_id=company_id).count()

    if users_count > 0 or campaigns_count > 0:
        raise HTTPException(
            400,
            "Não é possível excluir empresa com usuários ou campanhas vinculadas"
        )

    db.delete(company)
    db.commit()

    return {"ok": True}
# ==========================
# Admin - Usuários
# ==========================
@app.post("/api/admin/users")
def admin_create_user(data: AdminUserCreate, user=Depends(auth_user), db: Session = Depends(get_db)):
    require_admin(user)

    email = data.email.strip().lower()

    if not email or not data.password:
        raise HTTPException(
            400,
            "E-mail e senha são obrigatórios"
        )

    existing = db.query(User).filter_by(email=email).first()

    if existing:
        raise HTTPException(
            400,
            "Já existe usuário com este e-mail"
        )

    company = db.query(Company).filter_by(id=data.company_id).first()

    if not company:
        raise HTTPException(
            404,
            "Empresa não encontrada"
        )

    role = (data.role or "user").lower().strip()

    if role not in ["admin", "user", "gestor"]:
        role = "user"

    new_user = User(
        email=email,
        pwd_hash=pbkdf2_sha256.hash(data.password),
        role=role,
        company_id=data.company_id
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "ok": True,
        "user": {
            "id": new_user.id,
            "email": new_user.email,
            "role": new_user.role,
            "company_id": new_user.company_id
        }
    }
@app.get("/api/admin/users")
def admin_list_users(user=Depends(auth_user), db: Session = Depends(get_db)):
    require_admin(user)

    users = db.query(User).order_by(User.id.desc()).all()

    result = []

    for u in users:
        result.append({
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "company_id": u.company_id,
            "company_name": u.company.name if u.company else None
        })

    return result


@app.put("/api/admin/users/{user_id}/company")
def admin_update_user_company(user_id: int, data: AdminUserCompanyUpdate, user=Depends(auth_user), db: Session = Depends(get_db)):
    require_admin(user)

    target_user = db.query(User).filter_by(id=user_id).first()

    if not target_user:
        raise HTTPException(404, "Usuário não encontrado")

    company = db.query(Company).filter_by(id=data.company_id).first()

    if not company:
        raise HTTPException(404, "Empresa não encontrada")

    target_user.company_id = data.company_id

    db.commit()

    return {"ok": True}


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, user=Depends(auth_user), db: Session = Depends(get_db)):
    require_admin(user)

    target_user = db.query(User).filter_by(id=user_id).first()

    if not target_user:
        raise HTTPException(404, "Usuário não encontrado")

    if target_user.id == user.id:
        raise HTTPException(
            400,
            "Você não pode excluir o próprio usuário logado"
        )

    db.delete(target_user)
    db.commit()

    return {"ok": True}
