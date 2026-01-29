#!/usr/bin/env python3

import sys
import json
import socket
import subprocess
import requests
import re
import textwrap
from bs4 import BeautifulSoup
from pathlib import Path
from dataclasses import dataclass
from typing import List
from random import choice

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich.live import Live

# ============================================================
# CONFIG
# ============================================================

APP_NAME = "Darkelf OSINT AI"
OLLAMA_MODEL = "llama3"
DDG_LITE = "https://html.duckduckgo.com/html/"
IPINFO_API = "https://ipinfo.io"  # API Service for IP/Domain Lookups
BASE_DIR = Path("cases")
BASE_DIR.mkdir(exist_ok=True)

console = Console()
online = False
score = 0

ASCII_ART = r"""
██████╗  █████╗ ██████╗ ██╗  ██╗███████╗██╗     ███████╗
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║     ██╔════╝
██║  ██║███████║██████╔╝█████╔╝ █████╗  ██║     █████╗  
██║  ██║██╔══██║██╔══██╗██╔═██╗ ██╔══╝  ██║     ██╔══╝  
██████╔╝██║  ██║██║  ██║██║  ██╗███████╗███████╗██╗
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝══╝
"""

# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str

# ============================================================
# NETWORK CHECKS
# ============================================================

def new_session():
    """Create a new HTTP session with specific headers."""
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://duckduckgo.com/"
    })
    return s
    
def check_online():
    """Check the system's online status."""
    global online
    try:
        new_session().get("https://duckduckgo.com", timeout=5)
        online = True
    except requests.RequestException:
        online = False

def net_status():
    """Return online/offline status as a nicely formatted string."""
    return "[green]ONLINE[/green]" if online else "[red]OFFLINE[/red]"

# ============================================================
# AI ENGINE
# ============================================================

def ai_stream(prompt: str, mode="OSINT", return_text=False):
    """Stream AI results using the Ollama command, optionally returning full text."""

    identity = (
        "You are Darkelf OSINT AI.\n"
        "You specialize in open-source intelligence, attribution, "
        "metadata analysis, timelines, and threat research.\n\n"
        "Rules:\n"
        "- Be precise\n"
        "- Avoid speculation\n"
        "- Explain reasoning step-by-step\n"
        f"Output Mode: {mode}\n"
    )

    full_prompt = identity + "\n" + prompt
    cmd = ["ollama", "run", OLLAMA_MODEL, full_prompt]

    text = Text()
    collected_output = ""  # 🔐 Capture AI output here

    with Live(text, refresh_per_second=8, console=console):
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            for line in proc.stdout:
                text.append(line)
                collected_output += line

            proc.wait()

            if proc.returncode != 0:
                error_msg = proc.stderr.read()
                console.print(f"[red]AI Error:[/red] {error_msg}")

        except Exception as e:
            console.print(f"[red]Failed to execute AI command: {e}[/red]")

    if return_text:
        return collected_output
        
# ============================================================
# DUCKDUCKGO SEARCH (WORKING METHOD)
# ============================================================

def ddg_search(query: str, max_results=8) -> List[SearchResult]:
    console.print("[dim]Searching DuckDuckGo (live)...[/dim]")
    s = new_session()
    r = s.post(DDG_LITE, data={"q": query}, timeout=10)
    soup = BeautifulSoup(r.text, "html.parser")

    results = []
    for res in soup.select(".result__body")[:max_results]:
        title = res.select_one(".result__title")
        link = res.select_one("a")
        snippet = res.select_one(".result__snippet")

        if not title or not link:
            continue

        results.append(
            SearchResult(
                title=title.get_text(strip=True),
                url=link["href"],
                snippet=snippet.get_text(strip=True) if snippet else ""
            )
        )
    return results
    
def fetch_page_text(url: str, max_chars=4000) -> str:
    try:
        r = new_session().get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")

        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        text = soup.get_text(separator="\n")
        text = re.sub(r"\n{2,}", "\n", text)

        return text[:max_chars]
    except Exception as e:
        return f"Failed to fetch page content: {e}"

def clean_snippet(text: str, max_len=220) -> str:
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len] + ("…" if len(text) > max_len else "")


def format_page_text(text: str, width=90) -> str:
    paragraphs = []
    for block in text.split("\n"):
        block = block.strip()
        if len(block) < 40:
            continue
        paragraphs.append(textwrap.fill(block, width=width))
    return "\n\n".join(paragraphs)

def show_results(results: List[SearchResult]):
    """Display DuckDuckGo search results and handle user interactions."""
    if not results:
        console.print("[bold red]NO RESULTS FOUND[/bold red]")
        Prompt.ask("Press Enter to continue", default="")
        return

    # Render results table
    table = Table(
        title="DuckDuckGo Search Results",
        border_style="green",
        show_lines=True
    )
    table.add_column("#", width=3, justify="right")
    table.add_column("Title", style="cyan", no_wrap=True)
    table.add_column("URL", overflow="fold", style="blue")
    table.add_column("Snippet", overflow="fold", style="dim")

    for i, result in enumerate(results, 1):
        table.add_row(
            str(i),
            result.title,
            result.url,
            clean_snippet(result.snippet)
        )

    console.print(table)
    console.print(
        "[dim]Options: <number>=view page | a<number>=AI analyze | q=back[/dim]"
    )

    while True:
        cmd = Prompt.ask("Action").strip().lower()

        if cmd == "q":
            return

        # -------- VIEW PAGE CONTENT (READER MODE) --------
        elif cmd.isdigit():
            idx = int(cmd) - 1
            if 0 <= idx < len(results):
                page_text = fetch_page_text(results[idx].url)
                formatted = format_page_text(page_text)

                console.print(
                    Panel(
                        formatted[:2500] if formatted else "No readable content extracted.",
                        title=f"Reader View: {results[idx].title}",
                        subtitle=results[idx].url,
                        border_style="cyan",
                        padding=(1, 2)
                    )
                )
            else:
                console.print("[red]Invalid selection[/red]")

        # -------- AI ANALYZE PAGE --------
        elif cmd.startswith("a") and cmd[1:].isdigit():
            idx = int(cmd[1:]) - 1
            if 0 <= idx < len(results):
                page_text = fetch_page_text(results[idx].url)

                ai_stream(
                    f"""
You are an OSINT analyst.

URL:
{results[idx].url}

Extracted Page Content:
{page_text}

Analyze:
- Attribution indicators
- Identity clues
- Platform or actor type
- OSINT relevance
- Potential investigative pivots
""",
                    mode="ATTRIBUTION"
                )
            else:
                console.print("[red]Invalid selection[/red]")

        else:
            console.print("[yellow]Invalid command[/yellow]")

# ============================================================
# OPTION 3: USERNAME ENUMERATION
# ============================================================

def username_enum():
    u = Prompt.ask("Username").strip()

    table = Table(
        title=f"Username OSINT Enumeration: {u}",
        border_style="cyan"
    )
    table.add_column("Platform")
    table.add_column("URL")
    table.add_column("Status")
    table.add_column("Signal")

    platforms = {
        "GitHub": f"https://github.com/{u}",
        "Twitter/X": f"https://twitter.com/{u}",
        "Reddit": f"https://www.reddit.com/user/{u}",
        "Keybase": f"https://keybase.io/{u}",
        "Pastebin": f"https://pastebin.com/u/{u}",
    }

    findings = []

    for platform, url in platforms.items():
        try:
            r = new_session().get(url, timeout=6)

            if r.status_code == 200 and len(r.text) > 500:
                status = "[green]LIVE[/green]"
                signal = "Profile Exists"
                snippet = r.text[:1200]
                findings.append(f"{platform}: LIVE → {url}")

            elif r.status_code in [301, 302]:
                status = "[yellow]REDIRECT[/yellow]"
                signal = "Possible Account"
                snippet = ""
                findings.append(f"{platform}: REDIRECT → {url}")

            elif r.status_code == 404:
                status = "[red]NOT FOUND[/red]"
                signal = "No Account"
                snippet = ""

            else:
                status = "[yellow]UNKNOWN[/yellow]"
                signal = f"HTTP {r.status_code}"
                snippet = ""

        except Exception as e:
            status = "[red]ERROR[/red]"
            signal = "Connection Failed"
            snippet = ""

        table.add_row(platform, url, status, signal)

    console.print(table)

    # --- AI ANALYSIS ---
    if findings and Prompt.ask("Run Darkelf OSINT AI attribution analysis? (y/n)").lower() == "y":
        ai_stream(
            f"""
You are an OSINT analyst.

Username investigated: {u}

Confirmed findings:
{chr(10).join(findings)}

Analyze:
- Username reuse patterns
- Platform clustering
- Likelihood of single-actor control
- Operational security risks
- Threat or doxxing potential

Provide a confidence score (0–100).
""",
            mode="ATTRIBUTION"
        )

# ============================================================
# OPTION 4: DOMAIN/IP ENRICHMENT
# ============================================================

def domain_ip_enrich():
    """Fetch IP/domain information and analyze it."""
    target = Prompt.ask("Enter a domain or IP").strip().rstrip("/")
    if not target:
        console.print("[red]Invalid input. Please enter a valid domain or IP.[/red]")
        return

    try:
        ip = socket.gethostbyname(target)
        console.print(f"[green]Resolved IP:[/green] {ip}")
    except socket.gaierror:
        console.print("[red]Failed to resolve domain. Please check the input.[/red]")
        return

    try:
        response = new_session().get(f"{IPINFO_API}/{ip}/json", timeout=10)
        response.raise_for_status()
        ip_data = response.json()

        table = Table(title="Domain/IP Enrichment", border_style="cyan")
        for key, value in ip_data.items():
            table.add_row(key.capitalize(), str(value))

        console.print(table)

        if Prompt.ask("Run Darkelf OSINT AI risk analysis? (y/n)").lower() == "y":
            ai_stream(
                f"Analyze the network footprint, risks, and attribution of the domain/IP: {target}",
                mode="OSINT"
            )
    except requests.RequestException as e:
        console.print(f"[red]Failed to fetch IP information: {e}[/red]")
        
# ============================================================
# OSINT CHALLENGES
# ============================================================

CHALLENGES = [
    ("Beginner", "Username reuse",
     "Correlating identities across platforms using usernames."),
    ("Intermediate", "Image verification",
     "Verifying image authenticity, metadata, and timelines."),
    ("Advanced", "Leak attribution",
     "Attributing leaked documents using timelines and metadata.")
]

def challenges_menu():
    global score, ACTIVE_CTF

    # ---- Challenge Selection ----
    table = Table(title="OSINT Challenges", border_style="magenta", show_lines=True)
    table.add_column("#", justify="right", width=3)
    table.add_column("Level")
    table.add_column("Theme")

    for i, c in enumerate(CHALLENGES, 1):
        table.add_row(str(i), c[0], c[1])

    console.print(table)
    idx = int(Prompt.ask("Select challenge")) - 1

    if not (0 <= idx < len(CHALLENGES)):
        console.print("[red]Invalid selection[/red]")
        return

    level, theme, description = CHALLENGES[idx]

    console.print(
        f"[bold magenta]Generating {level} OSINT CTF Challenge ({theme})...[/bold magenta]\n"
    )

    # ---- Difficulty-Aware, Entity-Locked Prompt ----
    prompt = f"""
You are an OSINT CTF challenge generator.

Difficulty: {level}
Theme: {theme}

Scenario requirements:
- Realistic investigative scenario
- Appropriate for {level} analysts
- Focus on: {description}

Create ONE OSINT challenge with:
1. Scenario background
2. Clear objective
3. EXACTLY 3 investigative hints (progressive)
4. ONE consistent suspect / entity
5. FINAL FLAG in format: FLAG{{...}}

IMPORTANT RULES:
- Once a person or entity is introduced, it MUST remain consistent
- Do NOT introduce new suspects
- The solution must derive ONLY from the scenario and hints
- Do NOT reveal the flag unless explicitly asked
"""

    # ---- Generate & Store Challenge ----
    ACTIVE_CTF = ai_stream(prompt, mode="CTF", return_text=True)

    console.print("\n[cyan]--- Investigator Console ---[/cyan]")

    # ---- Investigator Loop ----
    while True:
        action = Prompt.ask(
            "Options",
            choices=["hint", "submit", "solution", "exit"],
            default="submit"
        )

        # -------- HINT --------
        if action == "hint":
            ai_stream(
                f"""
Active OSINT CTF Challenge:
{ACTIVE_CTF}

Provide the NEXT logical OSINT hint.
Do NOT introduce new entities.
""",
                mode="CTF"
            )

        # -------- SUBMIT FLAG --------
        elif action == "submit":
            user_flag = Prompt.ask("Enter FLAG")

            ai_stream(
                f"""
OSINT CTF Challenge:
{ACTIVE_CTF}

User submission:
{user_flag}

Validate the flag.

Rules:
- Respond ONLY with CORRECT or INCORRECT
- Then briefly explain why
""",
                mode="CTF"
            )

            score += 25
            console.print("[green]✔ Score +25[/green]")
            break

        # -------- SOLUTION --------
        elif action == "solution":
            ai_stream(
                f"""
OSINT CTF Challenge:
{ACTIVE_CTF}

Reveal:
- Full investigative solution
- Correct FLAG
- Step-by-step reasoning

Rules:
- Use ONLY entities already introduced
""",
                mode="SOLUTION"
            )
            break

        # -------- EXIT --------
        elif action == "exit":
            console.print("[yellow]Exiting challenge…[/yellow]")
            break

# ============================================================
# MAIN MENU
# ============================================================

def main():
    """Main interactive menu loop."""
    while True:
        check_online()
        console.clear()
        console.print(ASCII_ART, style="green")

        console.print(Panel(
            "[1] Web Search (DuckDuckGo)\n"
            "[2] Ask Darkelf OSINT AI\n"
            "[3] Username Enumeration\n"
            "[4] Domain / IP Enrichment\n"
            "[5] OSINT Challenges\n[q] Quit\n\n"
            f"Network: {net_status()} | Score: {score}",
            title=APP_NAME
        ))

        action = Prompt.ask("Select").lower()

        if action == "1":
            query = Prompt.ask("Enter your search query")
            results = ddg_search(query)
            show_results(results)  # Display results directly in terminal
        elif action == "2":
            question = Prompt.ask("Enter your question for the AI")
            ai_stream(question)
        elif action == "3":
            username_enum()
        elif action == "4":
            domain_ip_enrich()
        elif action == "5":
            challenges_menu()
        elif action == "q":
            sys.exit()

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
