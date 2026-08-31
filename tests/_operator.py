"""The test operator credential.

/mandates, /agents and /approvals now need X-Operator-Token. The suite plays the
operator, so every test client carries it; conftest sets the matching value in
the environment. Attack tests build their own clients without it.
"""

OPERATOR_TOKEN = "test-operator-credential"
OPERATOR_HEADERS = {"X-Operator-Token": OPERATOR_TOKEN}
