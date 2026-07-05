"""
CLI entry point for power users.
  ctf-lens file.png           — standard analysis
  ctf-lens file.png --deep    — extended checks
  ctf-lens file.png --xor     — + XOR brute-force
  ctf-lens                    — interactive TUI
"""

import sys
import argparse

from .output import __version__, print_results, print_status
from .core import analyze


def main() -> None:
    parser = argparse.ArgumentParser(
        prog        = 'ctf-lens',
        description = f'ctf-lens v{__version__} — static analysis tool for CTF files',
        add_help    = True,
    )
    parser.add_argument(
        'filepath',
        nargs   = '?',           # optional — omitting it launches the TUI
        default = None,
        help    = 'Path to the file to analyse',
    )
    parser.add_argument('--deep',    action='store_true', help='Extended analysis (slower)')
    parser.add_argument('--xor',     action='store_true', help='Brute-force XOR keys 0x01–0xFF')
    parser.add_argument('--version', action='version',    version=f'ctf-lens {__version__}')

    args = parser.parse_args()

    # No filepath → launch interactive TUI
    if args.filepath is None:
        from .tui import run
        run()
        return

    # Filepath given → direct analysis (power-user mode)
    print_status(f'[dim]Analysing: {args.filepath}[/dim]')
    if args.xor:
        print_status('[dim]XOR brute-force enabled (keys 0x01–0xFF)[/dim]')

    try:
        result = analyze(
            args.filepath,
            deep           = args.deep,
            xor_bruteforce = args.xor,
        )
        print_results(result)
    except (FileNotFoundError, ValueError, PermissionError) as e:
        print_status(f'[red]Error: {e}[/red]')
        sys.exit(1)
    except KeyboardInterrupt:
        print_status('\n[yellow]Interrupted.[/yellow]')
        sys.exit(0)
    except Exception as e:
        print_status(f'[red]Unexpected error: {e}[/red]')
        raise
