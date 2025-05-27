from pydantic import BaseModel
from datetime import date

class UserCreate(BaseModel):
    email: str
    password: str

class WorkoutCreate(BaseModel):
    date: date
    exercises: list[dict]  # Список упражнений

class NutritionCreate(BaseModel):
    date: date
    calories: int
    proteins: int
    fats: int
    carbs: int