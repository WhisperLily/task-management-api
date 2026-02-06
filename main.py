from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import psycopg2
from psycopg2.extras import RealDictCursor
import os

# Configuration
SECRET_KEY = "your-secret-key-here-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

app = FastAPI(title="Task Management API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'database': 'task_management',
    'user': 'your_user',
    'password': 'your_password'
}

# Pydantic models
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None

class User(BaseModel):
    id: int
    email: str
    username: str
    full_name: Optional[str]
    created_at: datetime

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    priority: str = "medium"  # low, medium, high
    due_date: Optional[datetime] = None

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None  # pending, in_progress, completed
    due_date: Optional[datetime] = None

class Task(BaseModel):
    id: int
    user_id: int
    title: str
    description: Optional[str]
    priority: str
    status: str
    due_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime

# Database functions
def get_db_connection():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

def init_db():
    """Initialize database tables"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(100) UNIQUE NOT NULL,
            full_name VARCHAR(255),
            hashed_password VARCHAR(255) NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Tasks table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            priority VARCHAR(20) DEFAULT 'medium',
            status VARCHAR(20) DEFAULT 'pending',
            due_date TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create index on user_id for faster queries
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id)
    """)
    
    conn.commit()
    cur.close()
    conn.close()

# Password and token functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    
    if user is None:
        raise credentials_exception
    return user

# Authentication endpoints
@app.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    """Register a new user"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Check if user exists
    cur.execute("SELECT id FROM users WHERE email = %s OR username = %s", 
                (user.email, user.username))
    if cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Email or username already registered")
    
    # Create user
    hashed_password = get_password_hash(user.password)
    cur.execute(
        """INSERT INTO users (email, username, full_name, hashed_password) 
           VALUES (%s, %s, %s, %s) RETURNING *""",
        (user.email, user.username, user.full_name, hashed_password)
    )
    new_user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    
    return new_user

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login and get access token"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM users WHERE username = %s", (form_data.username,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    
    if not user or not verify_password(form_data.password, user['hashed_password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['id']}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(data={"sub": user['id']})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """Get current user"""
    return current_user

# Task endpoints
@app.post("/tasks", response_model=Task, status_code=status.HTTP_201_CREATED)
async def create_task(task: TaskCreate, current_user: dict = Depends(get_current_user)):
    """Create a new task"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute(
        """INSERT INTO tasks (user_id, title, description, priority, due_date) 
           VALUES (%s, %s, %s, %s, %s) RETURNING *""",
        (current_user['id'], task.title, task.description, task.priority, task.due_date)
    )
    new_task = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    
    return new_task

@app.get("/tasks", response_model=List[Task])
async def get_tasks(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get all tasks for current user with optional filters"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    query = "SELECT * FROM tasks WHERE user_id = %s"
    params = [current_user['id']]
    
    if status:
        query += " AND status = %s"
        params.append(status)
    
    if priority:
        query += " AND priority = %s"
        params.append(priority)
    
    query += " ORDER BY created_at DESC"
    
    cur.execute(query, params)
    tasks = cur.fetchall()
    cur.close()
    conn.close()
    
    return tasks

@app.get("/tasks/{task_id}", response_model=Task)
async def get_task(task_id: int, current_user: dict = Depends(get_current_user)):
    """Get a specific task"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM tasks WHERE id = %s AND user_id = %s", 
                (task_id, current_user['id']))
    task = cur.fetchone()
    cur.close()
    conn.close()
    
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return task

@app.put("/tasks/{task_id}", response_model=Task)
async def update_task(
    task_id: int, 
    task_update: TaskUpdate, 
    current_user: dict = Depends(get_current_user)
):
    """Update a task"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Check task exists and belongs to user
    cur.execute("SELECT * FROM tasks WHERE id = %s AND user_id = %s", 
                (task_id, current_user['id']))
    existing_task = cur.fetchone()
    
    if not existing_task:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Task not found")
    
    # Build update query
    update_fields = []
    params = []
    
    if task_update.title is not None:
        update_fields.append("title = %s")
        params.append(task_update.title)
    if task_update.description is not None:
        update_fields.append("description = %s")
        params.append(task_update.description)
    if task_update.priority is not None:
        update_fields.append("priority = %s")
        params.append(task_update.priority)
    if task_update.status is not None:
        update_fields.append("status = %s")
        params.append(task_update.status)
    if task_update.due_date is not None:
        update_fields.append("due_date = %s")
        params.append(task_update.due_date)
    
    update_fields.append("updated_at = CURRENT_TIMESTAMP")
    params.extend([task_id, current_user['id']])
    
    query = f"UPDATE tasks SET {', '.join(update_fields)} WHERE id = %s AND user_id = %s RETURNING *"
    
    cur.execute(query, params)
    updated_task = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    
    return updated_task

@app.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_task(task_id: int, current_user: dict = Depends(get_current_user)):
    """Delete a task"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("DELETE FROM tasks WHERE id = %s AND user_id = %s RETURNING id", 
                (task_id, current_user['id']))
    deleted = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    
    if not deleted:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return None

@app.get("/tasks/stats/summary")
async def get_task_statistics(current_user: dict = Depends(get_current_user)):
    """Get task statistics for current user"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT 
            COUNT(*) as total_tasks,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN priority = 'high' THEN 1 ELSE 0 END) as high_priority,
            SUM(CASE WHEN due_date < CURRENT_TIMESTAMP AND status != 'completed' THEN 1 ELSE 0 END) as overdue
        FROM tasks
        WHERE user_id = %s
    """, (current_user['id'],))
    
    stats = cur.fetchone()
    cur.close()
    conn.close()
    
    return stats

@app.on_event("startup")
async def startup():
    init_db()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)