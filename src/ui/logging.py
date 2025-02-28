# logging.py

"""
This module provides logging functionalities with custom formatting and color-coded output for terminal display.
"""

import logging, sys
from src.utils import stop_event, interrupt_handled, executor

# Classe pour les couleurs dans le terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def display_program_info():
    """Displays information about the program at startup."""

    BANNER = Colors.CYAN + r"""
    #    _____        _____                                 
    #   |  __ \      / ____|                                
    #   | |__) |   _| (___   ___ __ _ _ __  _ __   ___ _ __ 
    #   |  ___/ | | |\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    #   | |   | |_| |____) | (_| (_| | | | | | | |  __/ |   
    #   |_|    \__, |_____/ \___\__,_|_| |_|_| |_|\___|_|   
    #           __/ |                                       
    #          |___/                Version : 1.0.0
    """ + Colors.ENDC

    print(BANNER)

    creator = Colors.BOLD + "1mR007" + Colors.ENDC
    github_link = Colors.BOLD + "github.com/1mR007" + Colors.ENDC

    # Displaying information
    print(f"Creator : {creator}")
    print(f"GitHub : {github_link}\n")



# Configure logging with a custom formatter
class CustomFormatter(logging.Formatter):
    """Custom formatter for log messages based on their level."""
    def format(self, record):
        prefix = ""
        suffix = ""
        
        if record.levelno == logging.ERROR:
            prefix = Colors.RED
            suffix = Colors.ENDC
        elif record.levelno == logging.INFO:
            prefix = Colors.GREEN
            suffix = Colors.ENDC
        elif record.levelno == logging.WARNING:
            prefix = Colors.YELLOW
            suffix = Colors.ENDC
            
        record.msg = f"{prefix}{record.msg}{suffix}"
        return super().format(record)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
formatter = CustomFormatter('%(asctime)s - %(levelname)s - %(message)s')
for handler in logger.handlers:
    handler.setFormatter(formatter)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def signal_handler(signum: int, frame) -> None:
    """Handle interrupt signals to perform a graceful shutdown."""
    global interrupt_handled, executor
    if not interrupt_handled:
        interrupt_handled = True
        stop_event.set()
        logger.info(f"{Colors.YELLOW}Gracefully shutting down PyScanner...{Colors.ENDC}")
        logger.info(f"{Colors.YELLOW}Stopping threads...{Colors.ENDC}")

        try:
            if executor:
                executor.shutdown(wait=False)
        except Exception as e:
            logger.error(f"{Colors.RED}Error during shutdown: {e}{Colors.ENDC}")
        finally:
            sys.exit(0)
    
def disable_colors():
    """Disable colored output by setting all color codes to empty strings."""
    for attr in dir(Colors):
        if not attr.startswith('_'):
            setattr(Colors, attr, '')