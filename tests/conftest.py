import sys
from pathlib import Path

# Add the project root to sys.path so that tests can import modules
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
