#!/usr/bin/env python3
"""Build the Go C archive and its header without writing into the source tree."""
from pathlib import Path
import subprocess
import sys


def main():
    source, archive, header = (Path(arg).resolve() for arg in sys.argv[1:])
    subprocess.run(
        ['go', 'build', '-buildmode=c-archive', '-o', str(archive), 'logger.go'],
        cwd=source,
        check=True,
    )
    archive.with_suffix('.h').replace(header)


if __name__ == '__main__':
    main()
