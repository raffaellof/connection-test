# Contributing to advanced-connection-test

Thank you for your interest in contributing to **advanced-connection-test**! Your help is welcome, whether you are reporting bugs, suggesting features, improving documentation, or submitting code.

## How to Contribute

### 1. Reporting Bugs
- Use the **Bug Report** issue template to provide a clear and detailed description of the problem, steps to reproduce, expected and actual behavior, and relevant environment details.

### 2. Requesting Features
- Use the **Feature Request** issue template to describe your idea, motivation, and possible alternatives.

### 3. Requesting Documentation Improvements
- Use the **Documentation Request** issue template to suggest improvements or additions to the documentation.

### 4. Submitting Code
- Fork the repository and create a new branch for your changes.
- Write clear, concise commit messages (e.g., "Add issue templates for bug reporting").
- Ensure your code follows the project's style and passes all tests.
- Submit a pull request with a description of your changes and reference any related issues.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/raffaellof/connection-test.git
   cd connection-test
   ```
2. Install dependencies (includes `pytest`, `pytest-asyncio`, and `pytest-mock`):
   ```bash
   pip install -e ".[dev]"
   ```
3. Run tests:
   ```bash
   pytest
   ```

> **Note:** The test suite uses `async def` tests. The `pip install -e ".[dev]"` command
> installs all required test dependencies automatically, including `pytest-asyncio`
> (needed to run async tests) and `pytest-mock`. If tests fail with
> *"async def functions are not natively supported"*, run `pip install -e ".[dev]"` again
> to make sure all dev dependencies are installed in the active virtual environment.

## Guidelines

- Be respectful and follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Use the provided issue templates for bug reports, feature requests, and documentation suggestions.
- Write clear, maintainable code and include tests where appropriate.
- Update documentation as needed.

## Need Help?
If you have questions or need guidance, feel free to open a discussion or contact a maintainer.

We appreciate your contributions to **advanced-connection-test**!

