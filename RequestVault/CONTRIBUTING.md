# Contributing to RequestVault

Thank you for your interest in contributing to **RequestVault**! We welcome contributions from penetration testers, security researchers, and developers.

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please treat all community members with respect.

---

## How Can I Contribute?

### 1. Reporting Bugs
Before filing an issue, check existing GitHub Issues to see if the bug has already been reported.

When reporting a bug, please include:
- A descriptive title.
- Burp Suite version (e.g., Burp Suite Pro 2024.1) and OS (Windows, Linux, macOS).
- Java runtime version (`java -version`).
- Exact steps to reproduce the issue.
- Expected vs actual behavior.
- Burp Suite Extensions output/error tab logs if applicable.

### 2. Suggesting Enhancements
Feature requests are always welcome!
- Open a GitHub Issue using the **Feature Request** template.
- Explain the real-world penetration testing or VAPT scenario where this feature would be useful.
- Provide examples of desired input, UI controls, and expected output formats.

### 3. Pull Requests
1. **Fork** the repository and clone your fork:
   ```bash
   git clone https://github.com/<your-username>/RequestVault.git
   cd RequestVault
   ```
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your code changes adhering to the existing coding style:
   - Use clean, well-commented Java code.
   - Maintain Dark/Light mode theme awareness (`isDarkMode()`).
   - Never alter captured raw evidence in memory.
4. Verify the build and run unit tests:
   ```bash
   # On Windows
   build.bat

   # Run test suite
   javac -cp "build/classes;lib/gson-2.10.1.jar;lib/montoya-api-2023.12.1.jar" -d build/classes src/test/java/requestvault/analysis/ResponseDiffTest.java
   java -cp "build/classes;lib/gson-2.10.1.jar;lib/montoya-api-2023.12.1.jar" requestvault.analysis.ResponseDiffTest
   ```
5. Commit your changes using conventional commit messages:
   ```bash
   git commit -m "feat(diff): add inline token highlighting for response bodies"
   ```
6. Push to your fork and submit a Pull Request to the `main` branch.

---

## Development Setup

### Prerequisites
- **Java Development Kit (JDK)**: JDK 17, 21, or 23.
- **Burp Suite**: Community or Professional (2023.12+).
- **Git**.

### Project Structure
- `src/main/java/requestvault/`:
  - `model/`: Data structures (`TrafficRecord`, `Engagement`).
  - `capture/`: Montoya proxy interception & history sync.
  - `storage/`: Memory storage and SHA-256 evidence manifest.
  - `analysis/`: Multi-filter search engine and side-by-side response diffing.
  - `security/`: SHA-256 hashing and credential redaction.
  - `export/`: Exporters (JSON, CSV, HTML, Markdown, RAW, HAR 1.2, Clipboard).
  - `ui/`: Swing UI panels and dialogs.
- `src/test/java/requestvault/`: Standalone unit tests.
- `lib/`: Local compile-time Montoya API and Gson dependencies.

---

## License

By contributing to RequestVault, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
