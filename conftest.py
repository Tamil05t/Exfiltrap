import sys
import pathlib

# Make the project root importable (``import exfiltrap``) no matter where
# pytest is invoked from.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
