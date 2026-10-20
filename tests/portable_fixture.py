"""Load existing repository test fixtures without changing production imports."""
import importlib.util
from pathlib import Path


def load_fixture(filename):
    for directory in (Path(__file__).resolve().parent, Path.cwd() / "tests"):
        path = directory / filename
        if path.is_file():
            spec = importlib.util.spec_from_file_location("portable_fixture_" + path.stem, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise FileNotFoundError(f"Repository test fixture {filename} not found")
