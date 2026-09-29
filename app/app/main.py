from fastapi import FastAPI

app = FastAPI(
    title="Project Mongrel",
    description="Telegram-first AI security analyst.",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "project": "Project Mongrel",
        "status": "online",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }
