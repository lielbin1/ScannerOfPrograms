from dataclasses import dataclass


@dataclass
class Cve:
    identifier: int
    assigner: str
    description: str
    severity: str
    cpe_match: list

    def __init__(self, identifier, assigner, description, severity, cpe_match):
        self.identifier = identifier
        self.assigner = assigner
        self.description = description
        self.severity = severity
        self.cpe_match = cpe_match

    def cve_to_string(self) -> str:
        return """Identifier: {0}\n Assigner: {1}\n Description: {2}\n Severity: {3}""".format(self.identifier, self.assigner, self.description, self.severity)
