from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import os

Base = declarative_base()
SessionLocal = None
_engine = None

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    tasks = relationship('Task', back_populates='user')

    # Flask-Login required attributes
    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class Task(Base):
    __tablename__ = 'tasks'
    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship('User', back_populates='tasks')


def db_init(app):
    global _engine, SessionLocal
    db_path = app.config.get('DATABASE', 'app.db')
    _engine = create_engine(f'sqlite:///{db_path}', connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(bind=_engine)
    Base.metadata.create_all(_engine)


def get_db_session():
    global SessionLocal
    if SessionLocal is None:
        db_path = os.environ.get('DATABASE', 'app.db')
        engine = create_engine(f'sqlite:///{db_path}', connect_args={"check_same_thread": False})
        SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()