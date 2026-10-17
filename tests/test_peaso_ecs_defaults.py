"""Keep AWS-returned empty container defaults explicit to prevent replacements."""
from pathlib import Path
import re
import unittest


class EcsContainerDefaults(unittest.TestCase):
    def test_returned_empty_defaults_keep_tasks_stable(self):
        source = (Path(__file__).resolve().parents[1] / "infra/aws/workflow.tf").read_text()
        container = source.split("container_definitions = jsonencode([{", 1)[1].split("environment =", 1)[0]
        for field in ("portMappings", "volumesFrom", "systemControls"):
            with self.subTest(field=field):
                self.assertRegex(container, rf"\b{field}\s*=\s*\[\s*\]")
        capabilities = re.search(r"linuxParameters\s*=\s*\{\s*capabilities\s*=\s*\{([^}]+)\}", container)
        self.assertIsNotNone(capabilities)
        self.assertRegex(capabilities.group(1), r"\badd\s*=\s*\[\s*\]")
        self.assertRegex(capabilities.group(1), r'\bdrop\s*=\s*\["ALL"\]')
        self.assertRegex(container, r'readonlyRootFilesystem\s*=\s*true')
        self.assertRegex(container, r'user\s*=\s*"10001:10001"')


if __name__ == "__main__":
    unittest.main()
