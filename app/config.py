import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

APP_NAME = os.getenv(
    "APP_NAME",
    "Zaalima Zero Trust Identity Provider"
)