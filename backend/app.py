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


# === Assinatura de token ===
signer = TimestampSigner(os.environ.get("NR01_SECRET", "dev-secret"))

# === Base de dados ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# === Base de dados ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# URL do Postgres no Supabase (via Pooler)
DB_URL = "postgresql+psycopg://postgres:Edson_DB_2024@db.cpjjeltdrtqxl djzdnh.supabase.co:5432/postgres"

engine = create_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()

# === Modelos ===
class Company(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    cnpj = Column(String, nullable=True)
    plan = Column(String, default="demo")
    response_limit = Column(Integer, default=10000)


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
    answers = Column(Text)  # JSON
    notes = Column(Text, default="")

Base.metadata.create_all(engine)

# === Semente demo (opcional) ===
def seed():
    db = SessionLocal()
    try:
        if not db.query(Company).first():
            comp = Company(
                name="DEMO LTDA",
                cnpj="00.000.000/0000-00",
                plan="demo",
                response_limit=10000
            )
            db.add(comp)
            db.commit()

            # === ADMIN PROFISSIONAL PADRÃO ===
            user = User(
                email="engbrazdatainsightengenharia@gmail.com",
                pwd_hash=pbkdf2_sha256.hash("Edson_DB_1975"),
                role="admin",
                company_id=comp.id
            )
            db.add(user)

            # Carregar perguntas
            dataset = json.loads(
                open(os.path.join(BASE_DIR, 'questions.json'), 'r', encoding='utf-8').read()
            )
            for q in dataset:
                db.add(Question(dimension=q[0], text=q[1]))

            db.commit()
    finally:
        db.close()
seed()

# === App & middlewares ===
app = FastAPI(title="AVALIA NR01")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # em produção você pode restringir para o domínio do Netlify
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Importa e pluga as rotas de cadastro (registro de empresa/usuário) ===
#from .register_route import router as register_router
#app.include_router(register_router, prefix="/api", tags=["public"])

# === Static /frontend ===
FRONT = os.path.join(os.path.dirname(__file__), "../frontend")
app.mount("/frontend", StaticFiles(directory=FRONT), name="frontend")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/frontend/index.html")

# === Dependências e auth ===
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

# === Schemas ===
class LoginIn(BaseModel):
    email: str
    password: str


class CompanyIn(BaseModel):
    name: str
    cnpj: str | None = None
    plan: str | None = "demo"
    response_limit: int | None = 10000


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


# === Healthcheck (útil no Render) ===
@app.get("/api/health")
def health():
    return {"ok": True}

# === Login ===
@app.post("/api/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=data.email).first()
    if not user or not pbkdf2_sha256.verify(data.password, user.pwd_hash):
        raise HTTPException(401, "Credenciais inválidas")
    token = signer.sign(json.dumps({"uid": user.id, "cid": user.company_id}).encode()).decode()
    return {"token": token, "role": user.role, "company_id": user.company_id, "email": user.email}

# === Empresa (update) ===
@app.post("/api/company")
def update_company(data: CompanyIn, user=Depends(auth_user), db: Session = Depends(get_db)):
    comp = db.query(Company).filter_by(id=user.company_id).first()
    if not comp:
        raise HTTPException(404, "Empresa não encontrada")
    comp.name = data.name
    comp.cnpj = data.cnpj
    comp.plan = data.plan or comp.plan
    comp.response_limit = data.response_limit or comp.response_limit
    db.commit()
    return {"ok": True}

# === Questões (admin) ===
@app.get("/api/questions")
def get_questions(user=Depends(auth_user), db: Session = Depends(get_db)):
    qs = db.query(Question).all()
    return [{"id": q.id, "dimension": q.dimension, "text": q.text} for q in qs]

# === Rotas públicas para a pesquisa (de acordo com Programa NR01 pronto) ===
@app.get("/api/public/campaign/{token}")
def public_campaign_info(token: str, db: Session = Depends(get_db)):
    """
    Retorna informações básicas da campanha para o survey público.
    """
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
    """
    Lista as questões para o formulário público validando o token da campanha.
    """
    camp = db.query(Campaign).filter_by(token=token, active=True).first()
    if not camp:
        raise HTTPException(404, "Campanha não encontrada/ativa")

    qs = db.query(Question).all()
    return [
        {"id": q.id, "dimension": q.dimension, "text": q.text}
        for q in qs
    ]

# === Campanhas ===
@app.post("/api/campaigns")
def create_campaign(inp: CampaignIn, user=Depends(auth_user), db: Session = Depends(get_db)):
    token = secrets.token_urlsafe(12)
    camp = Campaign(
        company_id=user.company_id,
        title=inp.title,
        token=token,
        start_at=inp.start_at or datetime.utcnow(),
        end_at=inp.end_at,
        meta=json.dumps(inp.meta or {})
    )
    db.add(camp)
    db.commit()
    return {"id": camp.id, "token": token}


@app.get("/api/campaigns")
def list_campaigns(user=Depends(auth_user), db: Session = Depends(get_db)):
    camps = (
        db.query(Campaign)
        .filter_by(company_id=user.company_id)
        .order_by(Campaign.id.desc())
        .all()
    )
    return [
        {"id": c.id, "title": c.title, "token": c.token, "active": c.active,
         "start_at": c.start_at, "end_at": c.end_at}
        for c in camps
    ]

# === Resposta pública ===
@app.post("/api/public/respond")
def public_respond(data: PublicResponseIn, db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter_by(token=data.token, active=True).first()
    if not camp:
        raise HTTPException(404, "Campanha não encontrada/ativa")

    comp = db.query(Company).filter_by(id=camp.company_id).first()
    total = (
        db.query(Response)
        .join(Campaign, Campaign.id == Response.campaign_id)
        .filter(Campaign.company_id == comp.id)
        .count()
    )
    if total >= (comp.response_limit or 10000):
        raise HTTPException(403, "Limite de respostas atingido para o plano atual")

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

# === Resumo/Export ===
@app.get("/api/summary/{campaign_id}")
def summary(campaign_id: int, user=Depends(auth_user), db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter_by(id=campaign_id, company_id=user.company_id).first()
    if not camp:
        raise HTTPException(404, "Campanha não encontrada")

    qs = {q.id: (q.dimension, q.text) for q in db.query(Question).all()}
    items = db.query(Response).filter_by(campaign_id=camp.id).all()

    dim_scores = {}
    n = 0
    rows = []
    for it in items:
        ans = json.loads(it.answers)
        n += 1
        for qid, score in ans.items():
            dim = qs[int(qid)][0]
            dim_scores.setdefault(dim, []).append(float(score))
        rows.append({
            "created_at": it.created_at.isoformat(),
            "sector": it.sector, "ghe": it.ghe, "ges": it.ges, "environment": it.environment,
            **{f"Q{qid}": score for qid, score in ans.items()}
        })
    avg = {d: (sum(v) / len(v) if v else 0) for d, v in dim_scores.items()}

    actions = []
    for d, score in avg.items():
        if score < 2.5:
            actions.append({"dimension": d, "priority": "Alta",
                            "suggestion": f"Implementar medidas imediatas para {d.lower()} (treinamento, revisão de processos, reforço de recursos, mediação de conflitos)."})
        elif score < 3.5:
            actions.append({"dimension": d, "priority": "Média",
                            "suggestion": f"Plano de melhoria para {d.lower()} com responsáveis e prazos; comunicar metas e acompanhar trimestralmente."})
        else:
            actions.append({"dimension": d, "priority": "Manter",
                            "suggestion": f"Manter boas práticas em {d.lower()} e monitorar com reavaliações semestrais."})

    return {"count": n, "average": avg, "actions": actions, "rows": rows,
            "campaign": {"id": camp.id, "title": camp.title, "token": camp.token}}

@app.get("/api/export/{campaign_id}")
def export_csv(campaign_id: int, user=Depends(auth_user), db: Session = Depends(get_db)):
    import csv, io, json as _json
    camp = db.query(Campaign).filter_by(id=campaign_id, company_id=user.company_id).first()
    if not camp:
        raise HTTPException(404, "Campanha não encontrada")
    items = db.query(Response).filter_by(campaign_id=camp.id).all()

    output = io.StringIO()
    if not items:
        return JSONResponse({"csv": ""})

    first = _json.loads(items[0].answers)
    headers = ["created_at", "sector", "ghe", "ges", "environment"] + [f"Q{k}" for k in sorted(map(int, first.keys()))]
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
