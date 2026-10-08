"""AWS Lambda entry point (API Gateway HTTP API -> FastAPI)."""

from mangum import Mangum

from .api import app

handler = Mangum(app, lifespan="off")
