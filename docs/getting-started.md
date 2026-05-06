# Getting Started

This guide introduces `pentest-tools` as a configurable security automation
project.

## Install

```bash
pip install pttools
```

## First run

1. Review your authorized scope.
2. Confirm the environment variables and credentials you intend to use.
3. Run the CLI help to explore available commands.

```bash
pttools --help
```

## Typical workflow

- define a target and scope
- select a module or playbook
- collect evidence
- review findings
- export a report

## Notes

- Keep tests and assessments within approved scope.
- Prefer isolated environments when experimenting.
- Review the documentation for module-specific setup details.
