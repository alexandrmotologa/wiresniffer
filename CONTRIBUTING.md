# Contributing to WireSniffer

Thank you for your interest in contributing to WireSniffer! We welcome contributions of all kinds, whether you are fixing a bug, improving documentation, or proposing new features.

---

## Code of Conduct

Please treat everyone in the community with respect, kindness, and constructive feedback. Open source thrives when developers collaborate positively.

---

## How to Contribute

### 1. Reporting Bugs & Requesting Features
- **Search existing issues** first to avoid duplicates.
- **For bugs:** Open an issue describing the bug, including steps to reproduce, expected vs. actual behavior, and environment details (Python 3.12+ and environment details (OS, Python version)).
- **For feature requests:** Describe the problem you are trying to solve and propose a solution or interface specification.

### 2. Pull Request Workflow

1. **Fork the repository** and clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/wiresniffer.git
   cd wiresniffer
   ```

2. **Create a topic branch** from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   # or: git checkout -b fix/issue-description
   ```

3. **Follow commit conventions:** We follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: implement support for dynamic configuration streaming`
   - `fix: resolve race condition in background worker`
   - `docs: update quick start instructions in README`
   - `perf: optimize circular buffer throughput`

4. **Ensure code quality:**
   - Keep code clean, readable, and strictly typed.
   - Verify that all existing and new unit tests pass before submitting.
   - Run the local linter/formatter if available.

5. **Push and open a Pull Request:**
   - Push your branch to your fork:
     ```bash
     git push origin feat/your-feature-name
     ```
   - Open a Pull Request against the `main` branch.
   - Provide a clear PR title and description outlining the changes made and referencing any related issues (e.g., `Closes #12`).

---

## Development Setup

WireSniffer requires **Python 3.12+** and uses [`uv`](https://github.com/astral-sh/uv) (or standard `pip` / `venv`) for reproducible virtual environments.

1. **Clone the repository and set up a virtual environment:**
   ```bash
   git clone https://github.com/alexandrmotologa/wiresniffer.git
   cd wiresniffer
   uv venv
   # On Windows: .venv\Scripts\activate
   # On Linux/macOS: source .venv/bin/activate
   uv pip install -e ".[dev]"
   ```

2. **Run tests:**
   ```bash
   pytest -v
   ```

3. **Run code quality & linting checks:**
   ```bash
   ruff check .
   ruff format --check .
   ```

Refer to the **Quick Start** section in [README.md](README.md) for full configuration flags, architecture details, and usage examples.

---

## Questions & Discussions

If you have questions about architecture decisions or need guidance before submitting a large change, feel free to open a Discussion or an Issue with the `question` label.
