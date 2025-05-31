from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
import os
from typing import List
from sqlalchemy import Boolean, ForeignKey, DateTime, Interval
from datetime import datetime, timedelta, timezone
import time
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi.staticfiles import StaticFiles

# Конфигурация
SECRET_KEY = os.getenv('SECRET_KEY', '')
ALGORITHM = os.getenv('ALGORITHM', 'HS256')
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Настройка SQLite базы данных
DATABASE_URL = "sqlite:///./app.db"
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

scheduler = BackgroundScheduler()

# Модель пользователя
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    full_name = Column(String, nullable=True)

class Exercise(Base):
    __tablename__ = 'exercises'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String)
    is_custom = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class WorkoutPlan(Base):
    __tablename__ = 'workout_plans'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    name = Column(String, nullable=False)

class WorkoutPlanExercise(Base):
    __tablename__ = 'workout_plan_exercises'
    id = Column(Integer, primary_key=True, index=True)
    plan_id = Column(Integer, ForeignKey('workout_plans.id'))
    exercise_id = Column(Integer, ForeignKey('exercises.id'))
    duration = Column(Integer, nullable=True)  # В секундах
    auto_continue = Column(Boolean, default=True)
    order = Column(Integer, default=0)
    completed = Column(Boolean, default=False)

class ActiveWorkout(Base):
    __tablename__ = 'active_workouts'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    plan_id = Column(Integer, ForeignKey('workout_plans.id'))
    current_exercise_id = Column(Integer, ForeignKey('workout_plan_exercises.id'))
    start_time = Column(DateTime, default=datetime.utcnow)
    paused = Column(Boolean, default=False)
    completed = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# Pydantic схемы
class UserCreate(BaseModel):
    email: str
    password: str
    full_name: str | None = None

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str | None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None

class UserListItem(BaseModel):
    id: int
    email: str
    full_name: str | None

    class Config:
        from_attributes = True

class ExerciseCreate(BaseModel):
    name: str
    description: str | None = None
    is_custom: bool = False

    class Config:
        from_attributes = True

class ExerciseResponse(ExerciseCreate):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

class WorkoutPlanCreate(BaseModel):
    name: str

    class Config:
        from_attributes = True

class PlanExerciseCreate(BaseModel):
    exercise_id: int
    duration: int | None = None  # В секундах
    auto_continue: bool = True
    order: int

    class Config:
        from_attributes = True

class ActiveWorkoutStart(BaseModel):
    plan_id: int

    class Config:
        from_attributes = True

class ActiveWorkoutUpdate(BaseModel):
    paused: bool | None = None
    completed: bool | None = None

    class Config:
        from_attributes = True

class WorkoutPlanResponse(BaseModel):
    id: int
    name: str
    user_id: int

    class Config:
        from_attributes = True

class WorkoutPlanExerciseResponse(BaseModel):
    id: int
    plan_id: int
    exercise_id: int
    duration: int | None
    auto_continue: bool
    order: int
    completed: bool

    class Config:
        from_attributes = True

class ActiveWorkoutResponse(BaseModel):
    id: int
    user_id: int
    plan_id: int
    current_exercise_id: int | None
    start_time: datetime
    paused: bool
    completed: bool

    class Config:
        from_attributes = True

# Настройка шифрования
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Инициализация приложения
app = FastAPI()

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Определяем схему аутентификации
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@app.on_event("startup")
async def startup_event():
    if not scheduler.running:
        scheduler.start()
        print("Scheduler started")

# Остановка планировщика при выключении приложения
@app.on_event("shutdown")
async def shutdown_event():
    if scheduler.running:
        scheduler.shutdown()
        print("Scheduler stopped")

# Dependency для работы с БД
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Функция для получения текущего пользователя
async def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise credentials_exception
    return user

### Эндпоинты API ###

# Регистрация пользователя
@app.post("/register", response_model=UserResponse, status_code=201)
def register(user: UserCreate, db: Session = Depends(get_db)):
    # Проверка существования email
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    db_user = User(
        email=user.email,
        hashed_password=hashed_password,
        full_name=user.full_name
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Авторизация
@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# Получение текущего пользователя
@app.get("/users/me", response_model=UserResponse)
def read_user_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/users", response_model=List[UserListItem])
def get_users(db: Session = Depends(get_db), 
              current_user: User = Depends(get_current_user)):
    """
    Получить список всех пользователей (только для администраторов)
    """
    # В реальном приложении здесь должна быть проверка ролей
    # if not current_user.is_admin:
    #     raise HTTPException(status_code=403, detail="Forbidden")
    
    users = db.query(User).all()
    return users

@app.post("/exercises", response_model=ExerciseResponse)
def create_exercise(exercise: ExerciseCreate, 
                   db: Session = Depends(get_db),
                   current_user: User = Depends(get_current_user)):
    # Проверка существования упражнения
    if db.query(Exercise).filter(
        Exercise.name == exercise.name,
        Exercise.user_id == current_user.id
    ).first():
        raise HTTPException(400, "Exercise already exists")
    
    db_exercise = Exercise(
        name=exercise.name,
        description=exercise.description,
        is_custom=exercise.is_custom,
        user_id=current_user.id
    )
    
    db.add(db_exercise)
    db.commit()
    db.refresh(db_exercise)
    
    # Возвращаем объект, преобразованный через Pydantic
    return db_exercise

@app.get("/exercises", response_model=list[ExerciseResponse])
def get_exercises(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        # Проверка аутентификации
        if not current_user:
            raise HTTPException(401, "Unauthorized")
        
        # Получаем упражнения текущего пользователя
        exercises = db.query(Exercise).filter(Exercise.user_id == current_user.id).all()
        
        # Если нет упражнений - возвращаем пустой список
        if not exercises:
            return []
        
        return exercises
    
    except Exception as e:
        raise HTTPException(500, f"Server error: {str(e)}")

# Управление планами тренировок
@app.post("/workout-plans", response_model=WorkoutPlanResponse)  # Исправлено здесь
def create_workout_plan(plan: WorkoutPlanCreate,
                       db: Session = Depends(get_db),
                       current_user: User = Depends(get_current_user)):
    db_plan = WorkoutPlan(
        name=plan.name,
        user_id=current_user.id
    )
    db.add(db_plan)
    db.commit()
    db.refresh(db_plan)
    return db_plan

@app.post("/workout-plans/{plan_id}/exercises")
def add_exercise_to_plan(plan_id: int,
                        exercise: PlanExerciseCreate,
                        db: Session = Depends(get_db),
                        current_user: User = Depends(get_current_user)):
    db_plan = db.query(WorkoutPlan).filter(
        WorkoutPlan.id == plan_id,
        WorkoutPlan.user_id == current_user.id
    ).first()
    
    if not db_plan:
        raise HTTPException(404, "Plan not found")
    
    plan_exercise = WorkoutPlanExercise(
        plan_id=plan_id,
        exercise_id=exercise.exercise_id,
        duration=exercise.duration,
        auto_continue=exercise.auto_continue,
        order=exercise.order
    )
    
    db.add(plan_exercise)
    db.commit()
    return {"message": "Exercise added to plan"}

# Управление активной тренировкой
@app.post("/active-workouts", response_model=ActiveWorkoutResponse)  # Исправлено
def start_workout(workout: ActiveWorkoutStart,
                 db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    # Проверка существования плана
    plan = db.query(WorkoutPlan).filter(
        WorkoutPlan.id == workout.plan_id,
        WorkoutPlan.user_id == current_user.id
    ).first()
    
    if not plan:
        raise HTTPException(404, "Workout plan not found")
    
    # Получаем первое упражнение в плане
    first_exercise = db.query(WorkoutPlanExercise).filter(
        WorkoutPlanExercise.plan_id == workout.plan_id
    ).order_by(WorkoutPlanExercise.order).first()
    
    if not first_exercise:
        raise HTTPException(400, "Workout plan has no exercises")
    
    active_workout = ActiveWorkout(
        user_id=current_user.id,
        plan_id=workout.plan_id,
        current_exercise_id=first_exercise.id
    )
    
    
    db.add(active_workout)
    db.commit()
    db.refresh(active_workout)
    return active_workout

@app.patch("/active-workouts/{workout_id}")
def update_workout_status(workout_id: int,
                         update_data: ActiveWorkoutUpdate,
                         db: Session = Depends(get_db),
                         current_user: User = Depends(get_current_user)):
    workout = db.query(ActiveWorkout).filter(
        ActiveWorkout.id == workout_id,
        ActiveWorkout.user_id == current_user.id
    ).first()
    
    if not workout:
        raise HTTPException(404, "Active workout not found")
    
    if update_data.paused is not None:
        workout.paused = update_data.paused
    
    if update_data.completed is not None:
        workout.completed = update_data.completed
    
    db.commit()
    return {"message": "Workout updated"}

@app.post("/active-workouts/{workout_id}/start-exercise/{exercise_id}")
def start_exercise(
    workout_id: int,
    exercise_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Получаем упражнение
    exercise = db.query(WorkoutPlanExercise).filter(
        WorkoutPlanExercise.id == exercise_id,
        WorkoutPlan.user_id == current_user.id
    ).first()
    
    if not exercise:
        raise HTTPException(404, "Exercise not found")
    
    # Если у упражнения есть длительность - запускаем таймер
    if exercise.duration:
        job_id = f"exercise_{exercise_id}_{workout_id}"

        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
        
        # Удаляем предыдущую задачу если была
        try:
            scheduler.remove_job(job_id)
        except:
            pass
        
        # Добавляем новую задачу
        scheduler.add_job(
            complete_exercise,
            'interval',
            seconds=exercise.duration,
            args=[exercise.id],
            id=job_id
        )
        print(f"Started timer for exercise {exercise_id} ({exercise.duration}s)")
    
    # Обновляем текущее упражнение в активной тренировке
    # ... ваш код обновления активной тренировки ...
    
    return {"message": "Exercise started"}

@app.post("/active-workouts/{workout_id}/pause")
def pause_workout(
    workout_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)  # Добавлена аутентификация
):
    try:
        # Находим активную тренировку текущего пользователя
        active_workout = db.query(ActiveWorkout).filter(
            ActiveWorkout.id == workout_id,
            ActiveWorkout.user_id == current_user.id  # Проверка владельца
        ).first()
        
        if not active_workout:
            raise HTTPException(status_code=404, detail="Active workout not found")
        
        # Приостанавливаем все задачи для этой тренировки
        job_prefix = f"exercise_"
        job_suffix = f"_{workout_id}"
        paused_jobs = []
        
        for job in scheduler.get_jobs():
            if job.id.startswith(job_prefix) and job.id.endswith(job_suffix):
                scheduler.pause_job(job.id)
                paused_jobs.append(job.id)
        
        # Обновляем статус тренировки в БД
        active_workout.paused = True
        db.commit()
        
        return {
            "message": "Workout paused",
            "paused_jobs": paused_jobs,
            "workout_status": "paused"
        }
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

def complete_exercise(exercise_id: int):
    try:
        db = SessionLocal()
        
        exercise = db.query(WorkoutPlanExercise).get(exercise_id)
        if not exercise:
            return
        
        # Помечаем упражнение как выполненное
        exercise.completed = True
        
        # Находим активную тренировку
        active_workout = db.query(ActiveWorkout).filter(
            ActiveWorkout.current_exercise_id == exercise_id
        ).first()
        
        if active_workout:
            # Находим следующее упражнение
            next_exercise = db.query(WorkoutPlanExercise).filter(
                WorkoutPlanExercise.plan_id == active_workout.plan_id,
                WorkoutPlanExercise.order > exercise.order,
                WorkoutPlanExercise.completed == False
            ).order_by(WorkoutPlanExercise.order).first()
            
            if next_exercise:
                active_workout.current_exercise_id = next_exercise.id
                # Автоматически запускаем таймер для следующего упражнения
                if next_exercise.duration:
                    manage_exercise_timer(
                        active_workout.id,
                        next_exercise.id,
                        next_exercise.duration
                    )
            else:
                active_workout.completed = True
        
        db.commit()
        return True
    
    except Exception as e:
        print(f"Error completing exercise: {str(e)}")
        return False
    finally:
        db.close()

# Обслуживание фронтенда

app.mount("/", StaticFiles(directory="frontendtest", html=True), name="frontendtest") #заменить на frontendtest для теста