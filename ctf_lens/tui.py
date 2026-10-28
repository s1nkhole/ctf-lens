"""
Interactive TUI for ctf-lens.
Launched when no arguments are passed (ctf-lens without flags).
Uses Rich for rendering; keyboard navigation via simple input() prompts
(no mouse, no curses — works on Windows cmd, PowerShell, and any Linux terminal).
"""

from __future__ import annotations
import sys

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False

from .output import __version__

console = Console() if _RICH else None

# ── ASCII banner ──────────────────────────────────────────────────────────────

_BANNER = r"""
  ██████╗████████╗███████╗      ██╗     ███████╗███╗   ██╗███████╗
 ██╔════╝╚══██╔══╝██╔════╝      ██║     ██╔════╝████╗  ██║██╔════╝
 ██║        ██║   █████╗        ██║     █████╗  ██╔██╗ ██║███████╗
 ██║        ██║   ██╔══╝        ██║     ██╔══╝  ██║╚██╗██║╚════██║
 ╚██████╗   ██║   ██║           ███████╗███████╗██║ ╚████║███████║
  ╚═════╝   ╚═╝   ╚═╝           ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
"""

# ── Capability overview shown on launch ───────────────────────────────────────

_WHAT_IT_DOES = """\
[bold cyan]ctf-lens[/bold cyan] is a static analysis tool for CTF challenge files.
Drop a file on it and it will automatically:

  [green]•[/green] Detect the file type from magic bytes (PNG, JPEG, ELF, ZIP, WAV, PCAP …)
  [green]•[/green] Search for [bold]flags[/bold] directly (28 CTF platform prefixes, or your own via --flag-format)
  [green]•[/green] Decode [bold]Base64, Hex, ROT13, URL-encoding, HTML entities,
    binary code, Morse code[/bold]
  [green]•[/green] Detect [bold]LSB steganography[/bold] per image/audio channel
  [green]•[/green] Analyse [bold]PNG chunks, JPEG markers, EXIF, ID3 tags[/bold]
  [green]•[/green] Carve [bold]embedded files[/bold] from any binary
  [green]•[/green] Try [bold]Caesar (ROT1–25), Atbash, Vigenère[/bold] on text
  [green]•[/green] Unpack and inspect [bold]ZIP, GZIP, BZIP2[/bold] archives
  [green]•[/green] Brute-force [bold]single-byte XOR[/bold] keys (--xor flag)
  [green]•[/green] Scan [bold]ELF / PE[/bold] binaries for interesting strings
  [green]•[/green] Find [bold]credentials and flags in PCAP[/bold] traffic
"""

_SUPPORTED_FORMATS = [
    ('Images',      'PNG  JPEG  BMP  TIFF  GIF  WEBP'),
    ('Audio',       'WAV  MP3  FLAC  OGG'),
    ('Archives',    'ZIP  GZIP  BZIP2  XZ  7ZIP  RAR'),
    ('Executables', 'ELF  EXE/DLL  Java .class  Mach-O'),
    ('Documents',   'PDF  DOC'),
    ('Network',     'PCAP  PCAPNG'),
    ('Crypto',      'PEM  DER'),
    ('Text',        'TXT  any printable file'),
]

# ── Main menu items ───────────────────────────────────────────────────────────

_MENU_ITEMS = [
    ('1', 'Analyse a file',          'Standard analysis — flags, encodings, stego, carving'),
    ('2', 'Deep analysis',           'All of the above + extended cipher checks (slower)'),
    ('3', 'XOR brute-force',         'Standard + single-byte XOR key sweep (0x01–0xFF)'),
    ('4', 'Deep + XOR',              'Full analysis with extended checks and XOR sweep'),
    ('5', 'What can ctf-lens do?',   'Show full capabilities and supported file formats'),
    ('q', 'Quit',                    ''),
]


# ── Rendering helpers ─────────────────────────────────────────────────────────

def _print_banner() -> None:
    if not _RICH:
        print(_BANNER)
        print(f'ctf-lens v{__version__}  —  CTF file analysis tool\n')
        return
    console.print(f'[bold cyan]{_BANNER}[/bold cyan]')
    console.print(
        f'[dim]v{__version__}  —  CTF file static analysis tool[/dim]\n',
        justify='center',
    )


def _print_menu() -> None:
    if not _RICH:
        print('Choose an option:\n')
        for key, label, desc in _MENU_ITEMS:
            suffix = f'  — {desc}' if desc else ''
            print(f'  [{key}] {label}{suffix}')
        print()
        return

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column('key',   style='bold yellow', width=4)
    t.add_column('label', style='bold white',  width=26)
    t.add_column('desc',  style='dim')

    for key, label, desc in _MENU_ITEMS:
        t.add_row(f'[{key}]', label, desc)

    console.print(Panel(t, title='[bold]Main menu[/bold]', box=box.ROUNDED, border_style='cyan'))


def _print_capabilities() -> None:
    if not _RICH:
        print('\nctf-lens capabilities:\n')
        import re
        print(re.sub(r'\[/?[a-z_ ]+\]', '', _WHAT_IT_DOES))
        print('\nSupported formats:')
        for category, fmts in _SUPPORTED_FORMATS:
            print(f'  {category:14} {fmts}')
        return

    console.print()
    console.rule('[bold cyan]ctf-lens capabilities[/bold cyan]')
    console.print(Panel(_WHAT_IT_DOES, box=box.ROUNDED, border_style='dim'))

    fmt_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    fmt_table.add_column('category', style='bold cyan', width=16)
    fmt_table.add_column('formats',  style='dim white')
    for category, fmts in _SUPPORTED_FORMATS:
        fmt_table.add_row(category, fmts)

    console.print(Panel(
        fmt_table,
        title='[bold]Supported formats[/bold]',
        box=box.ROUNDED,
        border_style='dim',
    ))
    console.print()


def _prompt_file() -> str | None:
    """
    Ask the user for a file path.
    Works with drag & drop (terminal pastes the path automatically)
    and manual typing. Returns None if the user cancels.
    """
    if _RICH:
        console.print()
        console.print('[bold]Drag & drop a file into this terminal window[/bold]')
        console.print('[dim]or type the path manually, then press Enter.[/dim]')
        console.print('[dim](leave blank to go back)[/dim]\n')
        console.print('[cyan]File path: [/cyan]', end='')
    else:
        print('\nDrag & drop a file or type the path (blank = back):')
        print('File path: ', end='')

    try:
        path = input().strip().strip('"').strip("'")   # strip quotes added by some shells
    except (EOFError, KeyboardInterrupt):
        return None

    return path if path else None


def _prompt_choice(prompt: str = 'Choice') -> str:
    if _RICH:
        console.print(f'\n[cyan]{prompt}:[/cyan] ', end='')
    else:
        print(f'\n{prompt}: ', end='')
    try:
        return input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return 'q'


# ── Main TUI loop ─────────────────────────────────────────────────────────────

def run() -> None:
    """
    Entry point for the interactive TUI.
    Called when ctf-lens is launched without arguments.
    """
    from .core import analyze
    from .output import print_results, print_status

    _print_banner()

    while True:
        _print_menu()
        choice = _prompt_choice('Select option')

        if choice == 'q':
            if _RICH:
                console.print('\n[dim]Goodbye.[/dim]\n')
            else:
                print('\nGoodbye.\n')
            sys.exit(0)

        if choice == '5':
            _print_capabilities()
            continue

        if choice not in ('1', '2', '3', '4'):
            if _RICH:
                console.print('[yellow]Unknown option. Try again.[/yellow]')
            else:
                print('Unknown option. Try again.')
            continue

        # ── File selection ────────────────────────────────────────────────
        filepath = _prompt_file()
        if not filepath:
            continue

        deep          = choice in ('2', '4')
        xor_bruteforce = choice in ('3', '4')

        if _RICH:
            console.print(f'\n[dim]Analysing: {filepath}[/dim]')
            if deep:
                console.print('[dim]Deep mode enabled.[/dim]')
            if xor_bruteforce:
                console.print('[dim]XOR brute-force enabled (keys 0x01–0xFF).[/dim]')
        else:
            print(f'\nAnalysing: {filepath}')

        try:
            result = analyze(filepath, deep=deep, xor_bruteforce=xor_bruteforce)
            print_results(result)
        except FileNotFoundError as e:
            if _RICH:
                console.print(f'[red]File not found: {e}[/red]')
            else:
                print(f'File not found: {e}')
        except (ValueError, PermissionError) as e:
            if _RICH:
                console.print(f'[red]Error: {e}[/red]')
            else:
                print(f'Error: {e}')
        except KeyboardInterrupt:
            if _RICH:
                console.print('\n[yellow]Interrupted.[/yellow]')
            else:
                print('\nInterrupted.')

        # ── After analysis: stay in loop, show menu again ─────────────────
        if _RICH:
            console.print('\n[dim]Press Enter to return to the menu…[/dim]', end='')
        else:
            print('\nPress Enter to return to the menu…', end='')
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)
