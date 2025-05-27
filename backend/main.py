from fastapi import FastAPI, Depends, HTTPException
from backend.database import SessionLocal, engine
from sqlalchemy.orm import Session
from backend.models import Base, User, Workout, Nutrition
from backend.schemas import UserCreate, WorkoutCreate, NutritionCreate
from backend.auth import get_password_hash, verify_password, create_access_token
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI

app = FastAPI()

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Статические файлы (фронтенд)
app.mount("/", StaticFiles(directory="frontend", html=True), name="static")

# Корневой эндпоинт
@app.get("/")
async def home():
    return {"message": "Главная страница API"}

# Пример другого эндпоинта
@app.get("/test")
async def test():
    return {"data": "Тест успешен!"}

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    return {"message": "User created"}

@app.post("/workouts")
async def create_workout(workout: WorkoutCreate, db: Session = Depends(get_db)):
    db_workout = Workout(**workout.dict())
    db.add(db_workout)
    db.commit()
    return db_workout

@app.get("/workouts")
async def get_workouts(user_id: int, db: Session = Depends(get_db)):
    return db.query(Workout).filter(Workout.user_id == user_id).all()