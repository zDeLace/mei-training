from sqlalchemy import Column, Integer, String, JSON, Date, ForeignKey
from backend.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    
class Workout(Base):
    __tablename__ = "workouts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    date = Column(Date)
    exercises = Column(JSON)  # Хранение в формате {"name": "Приседания", "sets": 4, ...}

class Nutrition(Base):
    __tablename__ = "nutrition"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    date = Column(Date)
    calories = Column(Integer)
    proteins = Column(Integer)
    fats = Column(Integer)
    carbs = Column(Integer)