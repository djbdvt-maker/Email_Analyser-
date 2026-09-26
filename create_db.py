import os
os.environ["DATABASE_URL"] = "sqlite:///./hopzero.db"
from app.database import Base, engine
from app.models import *
Base.metadata.create_all(bind=engine)
print("DB created!")
