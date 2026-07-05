"""
Result rendering: rich (coloured) and plain-text fallback.
"""

import re

from .models import AnalysisResult, SEVERITY_COLOR, SEVERITY_ICON

__version__ = '0.3.0'

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False

console = Console() if _RICH_AVAILABLE else None

MAX_DISPLAY_LINES  = 10
MAX_DECODED_DISPLAY = 8


def print_status(msg: str) -> None:
    """Print a status/warning message (used by core.analyze for file-size warnings)."""
    if _RICH_AVAILABLE and console:
        console.print(msg)
    else:
        clean = re.sub(r'\[/?[a-z_ ]+\]', '', msg)
        print(clean)


def print_results(result: AnalysisResult) -> None:
    if not _RICH_AVAILABLE:
        _print_plain(result)
        return

    console.print()
    console.rule(f'[bold cyan]ctf-lens v{__version__}[/bold cyan]')

    # ── File info header ──────────────────────────────────────────────────
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column('', style='dim', width=12)
    t.add_column('')
    t.add_row('File',    result.filepath)
    t.add_row('Type',    f'[bold]{result.filetype}[/bold] ({result.filecategory})')
    t.add_row('Size',    f'{result.filesize:,} bytes ({result.filesize / 1024:.1f} KB)')
    t.add_row('Entropy', f'{result.entropy:.3f} / 8.0')
    t.add_row('MD5',     result.md5)
    t.add_row('SHA256',  result.sha256[:48] + '…')
    console.print(t)

    # ── Summary ───────────────────────────────────────────────────────────
    highs   = [f for f in result.findings if f.severity == 'HIGH']
    mediums = [f for f in result.findings if f.severity == 'MEDIUM']
    infos   = [f for f in result.findings if f.severity in ('LOW', 'INFO')]

    summary = (
        f'[bold red]🔴 Critical: {len(highs)}[/bold red]  '
        f'[bold yellow]🟡 Medium: {len(mediums)}[/bold yellow]  '
        f'[dim]⚪ Info: {len(infos)}[/dim]'
    )
    console.print(Panel(summary, box=box.ROUNDED))

    if not result.findings:
        console.print('[dim]Nothing suspicious found.[/dim]')
        return

    # ── Findings ──────────────────────────────────────────────────────────
    for finding in result.findings:
        color = SEVERITY_COLOR[finding.severity]
        icon  = SEVERITY_ICON[finding.severity]
        tech  = f'  [dim italic]{finding.technique}[/dim italic]' if finding.technique else ''

        console.print(f'\n{icon} [{color}][bold]{finding.title}[/bold][/{color}]{tech}')
        console.print(f'   {finding.description}')
        if finding.data:
            for line in finding.data.splitlines()[:MAX_DISPLAY_LINES]:
                console.print(f'   [dim]{line}[/dim]')
            remaining = len(finding.data.splitlines()) - MAX_DISPLAY_LINES
            if remaining > 0:
                console.print(f'   [dim]… {remaining} more lines[/dim]')
        if finding.hint:
            console.print(f'   [green]💡 {finding.hint}[/green]')

    # ── Decoded section ───────────────────────────────────────────────────
    if result.decoded:
        console.print()
        console.rule('[bold]Automatically decoded[/bold]')
        for d in result.decoded:
            icon = '🚩' if d.severity == 'HIGH' else '•'
            tech = f'  [dim italic]{d.technique}[/dim italic]' if d.technique else ''
            console.print(f'\n{icon} [cyan][bold]{d.title}[/bold][/cyan]{tech}')
            console.print(f'   {d.description}')
            if d.data:
                for line in d.data.splitlines()[:MAX_DECODED_DISPLAY]:
                    console.print(f'   [dim]{line}[/dim]')
            if d.hint:
                console.print(f'   [green]💡 {d.hint}[/green]')

    console.print()


def _print_plain(result: AnalysisResult) -> None:
    print(f'\n{"=" * 60}')
    print(f'ctf-lens v{__version__}')
    print(f'{"=" * 60}')
    print(f'File:    {result.filepath}')
    print(f'Type:    {result.filetype} ({result.filecategory})')
    print(f'Size:    {result.filesize:,} bytes')
    print(f'Entropy: {result.entropy:.3f} / 8.0')
    print(f'MD5:     {result.md5}')
    print(f'SHA256:  {result.sha256[:48]}…')
    print()

    for finding in result.findings:
        print(f'[{finding.severity}] {finding.title}')
        print(f'  {finding.description}')
        if finding.data:
            for line in finding.data.splitlines()[:MAX_DISPLAY_LINES]:
                print(f'  {line}')
        if finding.hint:
            print(f'  💡 {finding.hint}')
        print()

    if result.decoded:
        print('\n--- Decoded ---')
        for d in result.decoded:
            print(f'[{d.severity}] {d.title}')
            print(f'  {d.description}')
            if d.data:
                for line in d.data.splitlines()[:MAX_DECODED_DISPLAY]:
                    print(f'  {line}')
            if d.hint:
                print(f'  💡 {d.hint}')
            print()
