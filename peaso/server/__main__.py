import os
import uvicorn

if __name__ == "__main__":
    uvicorn.run("peaso.server:create_app", factory=True, host=os.getenv("PEASO_BIND", "127.0.0.1"), port=int(os.getenv("PEASO_PORT", "8000")), access_log=False)
