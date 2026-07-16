import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

from portintel.cli.parser import main

if __name__ == "__main__":
    main()
