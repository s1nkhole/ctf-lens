"""
CLI entry point for power users.
  ctf-lens file.png                  — standard analysis
  ctf-lens file.png --deep           — extended checks
  ctf-lens file.png --xor            — + XOR attacks (single-byte, repeating-key, known-plaintext)
  ctf-lens file.bin --extract out/   — save carved files, trailing data and decoded layers
  ctf-lens file.png --json           — machine-readable result on stdout
  ctf-lens file.png -q --exit-code   — print flags only; exit status 10 when one is found
  ctf-lens                           — interactive TUI

Exit status: 0 = analysed (or no flag with --exit-code), 10 = flag found (--exit-code only),
1 = error (missing file, bad option value, ...), 2 = invalid command line.
"""

import os
import sys
import json
import argparse

from .output import __version__, print_results, print_status
from .core import analyze
from .config import PEEL_MAX_DEPTH

EXIT_FLAG_FOUND = 10


def _build_parser() -> argparse.ArgumentParser:
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
    parser.add_argument('--xor',     action='store_true',
                        help='XOR attacks: single-byte brute force, repeating-key recovery, flag-prefix crib')
    parser.add_argument('--flag-format', metavar='REGEX',
                        help=r"Extra flag regex, e.g. 'MYCTF\{[^}]+\}' (checked before the built-in prefixes)")
    parser.add_argument('--depth',   type=int, default=PEEL_MAX_DEPTH, metavar='N',
                        help=f'Max decoding-chain length, base64 → hex → … (default {PEEL_MAX_DEPTH}; 0 = off)')
    parser.add_argument('--wordlist', metavar='FILE',
                        help='Password list for encrypted ZIPs (added to the built-in CTF list)')
    parser.add_argument('--extract', metavar='DIR',
                        help='Save carved files, data after EOF and decoded binary layers into DIR')
    parser.add_argument('--json',    action='store_true', help='Print the result as JSON on stdout')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Print only the flags found, one per line (pipe-friendly)')
    parser.add_argument('--exit-code', action='store_true',
                        help=f'Exit with status {EXIT_FLAG_FOUND} when a flag was found')
    parser.add_argument('--version', action='version',    version=f'ctf-lens {__version__}')
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    # No filepath → launch interactive TUI
    if args.filepath is None:
        from .tui import run
        run()
        return

    if args.depth < 0:
        parser.error('--depth must be >= 0')

    # Status lines go to stderr; in --json / --quiet mode stay silent so pipes are clean.
    chatty = not (args.json or args.quiet)
    if chatty:
        print_status(f'[dim]Analysing: {args.filepath}[/dim]')
        if args.xor:
            print_status('[dim]XOR attacks enabled (single-byte, repeating-key, known-plaintext)[/dim]')

    try:
        result = analyze(
            args.filepath,
            deep           = args.deep,
            xor_bruteforce = args.xor,
            flag_format    = args.flag_format,
            peel_depth     = args.depth,
            wordlist       = args.wordlist,
            extract_dir    = args.extract,
        )
    except (FileNotFoundError, ValueError, PermissionError) as e:
        print_status(f'[red]Error: {e}[/red]')
        sys.exit(1)
    except KeyboardInterrupt:
        print_status('\n[yellow]Interrupted.[/yellow]')
        sys.exit(0)
    except Exception as e:
        print_status(f'[red]Unexpected error: {e}[/red]')
        raise

    try:
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        elif args.quiet:
            for flag in result.flags():
                print(flag)
        else:
            print_results(result)
        sys.stdout.flush()
    except BrokenPipeError:
        # Reader closed early (`ctf-lens x --json | head`): not an error. Point stdout at
        # /dev/null so the interpreter's exit-time flush does not raise a second time.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())

    if args.exit_code and result.flags():
        sys.exit(EXIT_FLAG_FOUND)
