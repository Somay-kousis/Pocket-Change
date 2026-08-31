"""The attack count is a claim in the README, so a test owns it.

Collects the corpus in a subprocess, without this file, and pins the number.
Adding or removing a case without changing ATTACK_CASES fails here, and so does
a case that only differs from another by a number in its name.
"""

import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent

# Raise this as cases land. The README quotes the run, not this constant.
ATTACK_CASES = 400


def _collected() -> list[str]:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         str(HERE), f"--ignore={HERE / Path(__file__).name}"],
        capture_output=True, text=True, cwd=HERE.parent.parent, check=False,
    ).stdout
    return [line for line in out.splitlines() if "::" in line]


def test_the_corpus_has_exactly_the_stated_number_of_attacks():
    assert len(_collected()) == ATTACK_CASES


def test_no_attack_is_a_copy_with_only_a_number_changed():
    names = [line.split("::", 1)[1] for line in _collected()]
    shapes = [re.sub(r"\d+", "#", name) for name in names]
    copies = {s for s in shapes if shapes.count(s) > 1}
    assert not copies, f"cases differing only by a number: {sorted(copies)}"
