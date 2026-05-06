# Credentialed Scans

`pentest-tools` supports workflows where you have explicit authorization to use
provided credentials during assessment.

## Principles

- only test systems you are authorized to assess
- use least privilege wherever possible
- store secrets in approved secret managers
- keep evidence and access logs for review

## Example flow

1. Register or configure the credentials in your approved environment.
2. Start the relevant module or playbook.
3. Verify scope before proceeding.
4. Review generated evidence and reports.

## Operational guidance

- prefer disposable or staging environments
- rotate credentials after test runs when required
- document every exception or approval
