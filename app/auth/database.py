import sqlite3
import logging
from datetime import datetime
from typing import Optional, List
from contextlib import contextmanager

from app.auth.config import auth_settings

logger = logging.getLogger(__name__)

class UserDatabase:
    """Simple SQLite database for user management"""
    
    def __init__(self):
        self.db_file = auth_settings.DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                # Users table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        full_name TEXT,
                        hashed_password TEXT NOT NULL,
                        is_active BOOLEAN DEFAULT 1,
                        is_admin BOOLEAN DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        failed_login_attempts INTEGER DEFAULT 0,
                        locked_until TIMESTAMP
                    )
                """)
                
                # API Keys table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS api_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key_name TEXT NOT NULL,
                        api_key TEXT UNIQUE NOT NULL,
                        user_id INTEGER,
                        is_active BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_used TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                """)
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """Get database connection with context manager"""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        try:
            yield conn
        finally:
            conn.close()
    
    def create_user(self, username: str, email: str, hashed_password: str, 
                   full_name: Optional[str] = None, is_admin: bool = False) -> Optional[int]:
        """Create a new user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users (username, email, full_name, hashed_password, is_admin)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, email, full_name, hashed_password, is_admin))
                conn.commit()
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[dict]:
        """Get user by username"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get user by username: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[dict]:
        """Get user by ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get user by ID: {e}")
            return None
    
    def update_last_login(self, user_id: int):
        """Update user's last login timestamp"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users 
                    SET last_login = CURRENT_TIMESTAMP, failed_login_attempts = 0 
                    WHERE id = ?
                """, (user_id,))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update last login: {e}")
    
    def increment_failed_login(self, user_id: int):
        """Increment failed login attempts"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users 
                    SET failed_login_attempts = failed_login_attempts + 1 
                    WHERE id = ?
                """, (user_id,))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to increment failed login: {e}")
    
    def get_all_users(self) -> List[dict]:
        """Get all users"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get all users: {e}")
            return []
    
    def create_api_key(self, key_name: str, api_key: str, user_id: Optional[int] = None) -> bool:
        """Create a new API key"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO api_keys (key_name, api_key, user_id)
                    VALUES (?, ?, ?)
                """, (key_name, api_key, user_id))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to create API key: {e}")
            return False
    
    def validate_api_key(self, api_key: str) -> Optional[dict]:
        """Validate API key and return associated user info"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ak.*, u.username, u.is_admin, u.is_active 
                    FROM api_keys ak
                    LEFT JOIN users u ON ak.user_id = u.id
                    WHERE ak.api_key = ? AND ak.is_active = 1
                """, (api_key,))
                row = cursor.fetchone()
                
                if row:
                    # Update last used timestamp
                    cursor.execute("""
                        UPDATE api_keys 
                        SET last_used = CURRENT_TIMESTAMP 
                        WHERE api_key = ?
                    """, (api_key,))
                    conn.commit()
                    
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to validate API key: {e}")
            return None

# Create database instance
user_db = UserDatabase()