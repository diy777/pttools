<div align="center">

<h1>pentest-tools</h1>

**A modular security automation toolkit for authorized testing, reporting, and workflow orchestration.**

[![PyPI](https://img.shields.io/pypi/v/pttools?color=red&label=pypi&style=flat-square)](https://pypi.org/project/pttools/)
[![Python](https://img.shields.io/badge/python-3.10%2B-red?style=flat-square)](https://pypi.org/project/pttools/)
[![License](https://img.shields.io/github/license/pentest-tools/pentest-tools?color=red&style=flat-square)](LICENSE)

[**Install**](#install) · [**Getting Started**](docs/getting-started.md) · [**Documentation**](docs/) · [**License**](#license)

</div>

---

> ## Authorized use only
>
> `pentest-tools` is designed for testing systems you own or are explicitly
> authorized to assess. Always verify scope, approvals, and local laws before
> running any module.
>
> The toolkit includes prompts and safeguards to help you keep actions within
> your approved scope. You are responsible for how you deploy and use it.

---

## What it is

`pentest-tools` is a Python-based toolkit for security workflows. It brings
command-line automation, structured reports, modular agents, and extensible
playbooks into one project.

## What it focuses on

- repeatable security workflows
- clear evidence collection
- modular task execution
- local-first operation
- configurable integrations
- reporting and review

## Install

```bash
pip install pttools
```

## Basic usage

```bash
pttools --help
pttools start <target>
pttools menu
pttools serve
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [Credentialed Scans](docs/credentialed-scans.md)
- [Documentation Index](docs/index.md)
- [Project Specs](specs/README.md)

## Project structure

- `cli/` — command-line interface
- `engine/` — orchestration and core logic
- `agents/` — task-specific modules
- `api/` — HTTP interface and dashboard assets
- `mcp_server/` — MCP integration
- `tools/` — shared tools and registries
- `docs/` — user-facing documentation
- `specs/` — product and implementation notes
- `tests/` — automated test suite

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
