from datetime import datetime
import logging
import re
import shutil
import subprocess
import sys


logger = logging.getLogger(__name__)


def check_arp_scan():
    """Check if arp-scan is installed."""
    arp_path = shutil.which("arp-scan")
    if arp_path:
        try:
            version = (
                subprocess.check_output(
                    ["arp-scan", "--version"], stderr=subprocess.STDOUT
                )
                .decode()
                .split("\n")[0]
            )
            logger.info("Found: %s", version)
            return True
        except Exception:
            logger.info("Found: arp-scan (version unknown)")
            return True

    logger.warning("arp-scan not found. MAC/vendor detection will be disabled.")
    logger.info("  macOS:  brew install arp-scan")
    logger.info("  Ubuntu: sudo apt install arp-scan")
    return False


def check_nmap():
    """Ensure nmap is installed and return its version string."""
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        logger.error("nmap not found. Please install nmap:")
        logger.error("  macOS:  brew install nmap")
        logger.error("  Ubuntu: sudo apt install nmap")
        sys.exit(1)

    try:
        version = subprocess.check_output(["nmap", "--version"]).decode().split("\n")[0]
        logger.info("Found: %s", version)
        return version
    except Exception as exc:
        logger.error("Could not get nmap version: %s", exc)
        sys.exit(1)


def check_vulners(vulners_script):
    """Verify the bundled vulners NSE script is present."""
    if not vulners_script.exists():
        logger.error(
            "Vulners NSE script not found at %s. Run: git clone https://github.com/vulnersCom/nmap-vulners.git %s",
            vulners_script,
            vulners_script.parent,
        )
        sys.exit(1)

    vulners_dir = vulners_script.parent
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--oneline"],
            cwd=vulners_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.info("Vulners script present (revision: %s)", result.stdout.strip())
        else:
            logger.info("Vulners script present at %s", vulners_script)
    except Exception:
        logger.info("Vulners script present at %s", vulners_script)

    return True


def create_scan_folder(customer_name, target, *, scans_dir, sanitize_customer_dir_name):
    """Create organized folder structure for a scan."""
    date_str = datetime.now().strftime("%Y-%m-%d")
    time_str = datetime.now().strftime("%H%M%S")
    safe_customer = sanitize_customer_dir_name(customer_name)
    safe_target = re.sub(r"[^\w\.]", "_", target)

    folder_name = f"scan_{time_str}_{safe_target}"
    scan_dir = scans_dir / safe_customer / date_str / folder_name
    scan_dir.mkdir(parents=True, exist_ok=True)
    return scan_dir


def run_quick_auto_scan(target, output_base):
    """Run a quick scan suitable for automated overnight scanning."""
    logger.info("Running auto scan on %s...", target)
    cmd = [
        "nmap",
        "-sS",
        "-T3",
        "--top-ports",
        "50",
        "-oA",
        str(output_base),
        target,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.error("Auto scan timed out after 120 seconds on %s", target)
        return False
