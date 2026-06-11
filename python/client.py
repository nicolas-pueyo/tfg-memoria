# client.py
import os
from dotenv import load_dotenv
from pycti import OpenCTIApiClient
import threading

load_dotenv()

class ApiClient:
    # Patrón Singleton para crear UN SOLO cliente API
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized") and self._initialized:
            return

        self.url = os.getenv("OPENCTI_URL")
        self.token = os.getenv("OPENCTI_TOKEN")

        if not self.url or not self.token:
            raise RuntimeError("Faltan variables OPENCTI_URL o OPENCTI_TOKEN en .env")

        self.api = OpenCTIApiClient(self.url, self.token)

        print(f"[INFO] ApiClient creado contra {self.url}")

        self._initialized = True
