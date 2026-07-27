"""Compatibility entrypoint for the packaged application."""

from app.main import *  # noqa: F401,F403


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=False)
