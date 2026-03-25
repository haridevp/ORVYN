from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"message": "AI Pentest Running 🚀"}

@app.get("/health")
def health():
    return {"status": "ok"}