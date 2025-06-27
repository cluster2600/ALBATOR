import argparse
from typing import Optional

class ArgumentParser:
    """Handles command-line argument parsing for the macOS Security Compliance Project."""

    def __init__(self):
        """Initialize the parser with a detailed description."""
        self.parser = argparse.ArgumentParser(
            description=(
                "Generate a baseline.yaml file containing security rules based on a keyword tag. "
                "Use this tool to list available tags, verify NIST 800-53 control coverage, "
                "or create tailored baselines for macOS security compliance. "
                "Use --interactive for an interactive command prompt or --gui for a graphical interface."
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self._add_arguments()

    def _add_arguments(self) -> None:
        """Add command-line arguments with descriptive help messages."""
        self.parser.add_argument(
            "-c", "--controls",
            action="store_true",
            help="Display NIST 800-53 controls covered by the collected rules and exit."
        )
        self.parser.add_argument(
            "-k", "--keyword",
            type=str,
            help="Keyword tag to filter rules (e.g., 'stig', 'cis_lvl1'). Required unless -l, -c, -i, or --gui is used."
        )
        self.parser.add_argument(
            "-l", "--list_tags",
            action="store_true",
            help="List all available keyword tags that can be used with -k and exit."
        )
        self.parser.add_argument(
            "-t", "--tailor",
            action="store_true",
            help="Enable interactive customization of the baseline with organization-specific values."
        )
        self.parser.add_argument(
            "--root-dir",
            type=str,
            default=None,
            help="Specify the root directory for rules and output (defaults to current directory)."
        )
        self.parser.add_argument(
            "-i", "--interactive",
            action="store_true",
            help="Run in interactive mode with a command prompt."
        )
        self.parser.add_argument(
            "--gui",
            action="store_true",
            help="Run in graphical user interface mode."
        )

    def parse(self) -> argparse.Namespace:
        """Parse arguments and enforce required options."""
        args = self.parser.parse_args()
        
        if not args.list_tags and not args.controls and not args.interactive and not args.gui and args.keyword is None:
            self.parser.error("the following argument is required: -k/--keyword (unless using -l, -c, -i, or --gui)")
        
        return args

def create_args() -> argparse.Namespace:
    """
    Create and parse command-line arguments for the baseline generation tool.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = ArgumentParser()
    return parser.parse()

if __name__ == "__main__":
    # For testing
    args = create_args()
    print(f"Controls: {args.controls}")
    print(f"Keyword: {args.keyword}")
    print(f"List tags: {args.list_tags}")
    print(f"Tailor: {args.tailor}")
    print(f"Root dir: {args.root_dir}")
    print(f"Interactive: {args.interactive}")
    print(f"GUI: {args.gui}")
