import yara
from pathlib import Path
from typing import Dict, List, Optional

class YaraScanner:
    def __init__(self, rules_dir: Optional[Path] = None):
        """Initialize YARA scanner with rules.

        Args:
            rules_dir (Optional[Path]): Directory containing YARA rules
        """
        self.rules = None
        if rules_dir:
            self.load_rules(rules_dir)

    def load_rules(self, rules_dir: Path) -> None:
        """Load YARA rules from a directory.

        Args:
            rules_dir (Path): Directory containing YARA rules
        """
        filepaths = {}
        for rule_file in rules_dir.glob('*.yar*'):
            filepaths[rule_file.stem] = str(rule_file)
        
        if filepaths:
            try:
                self.rules = yara.compile(filepaths=filepaths)
            except Exception as e:
                print(f"Error compiling YARA rules: {str(e)}")
                self.rules = None

    def scan_file(self, file_path: Path) -> List[Dict[str, str]]:
        """Scan a file with loaded YARA rules.

        Args:
            file_path (Path): Path to the file to scan

        Returns:
            List[Dict[str, str]]: List of matched rules and their metadata
        """
        if not self.rules:
            return [{'error': 'No YARA rules loaded'}]

        try:
            matches = self.rules.match(str(file_path))
            results = []
            
            for match in matches:
                result = {
                    'rule_name': match.rule,
                    'tags': match.tags,
                    'meta': match.meta if hasattr(match, 'meta') else {}
                }
                results.append(result)
            
            return results

        except Exception as e:
            return [{'error': f'Scan failed: {str(e)}'}]