from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from sqlmodel import Session
from database import init_db, engine
from models import User
from schemas import SignupSchema

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/")
def root():
    return {"message": "Hello, FastAPI is running!"}

@app.post("/signup")
def signup(data: SignupSchema):
    try:
        with Session(engine) as session:
            existing_user = session.query(User).filter(User.email == data.email).first()
            if existing_user:
                raise HTTPException(status_code=400, detail="Email already registered")

            new_user = User(
                name=data.name,
                email=data.email,
                password=data.password
            )

            session.add(new_user)
            session.commit()
            session.refresh(new_user)

            return {
                "message": f"User {data.name} signed up successfully!",
                "email": data.email,
            }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database connection error: {str(e)}")
