"""Optional hosted ASGI entrypoint. Requires the [hosted] dependency extra."""
from mangum import Mangum
from .app import create_app

handler = Mangum(create_app(), lifespan="off")
