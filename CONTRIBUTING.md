# Contributing to RequestVault

Thank you for your interest in contributing to **RequestVault**. We welcome contributions from penetration testers, security researchers, and developers for both the **Burp Suite** and **Caido** editions.

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please treat all community members with respect and professionalism.

---

## How Can I Contribute?

### 1. Reporting Bugs
Before filing an issue, check existing GitHub Issues to see if the problem has already been reported.

When reporting a bug, please specify:
- Platform edition: **Burp Suite** or **Caido**.
- Tool version (e.g. Burp Suite Pro 2024.1+, Caido Desktop 0.45+).
- Operating system (Windows, Linux, macOS).
- Steps to reproduce the bug.
- Extension console or log output.

### 2. Suggesting Enhancements
Feature requests are welcome:
- Open a GitHub Issue using the **Feature Request** template.
- Explain the real-world penetration testing, bug bounty, or VAPT scenario where the feature is needed.
- Provide examples of desired input, UI controls, or export formats.

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

3. Make your changes:
   - For **Burp Suite Edition**: Code resides in `src/main/java/requestvault/`.
   - For **Caido Edition**: Code resides in `Caido/RequestVault-Caido/src/`.
   - Maintain dark and light theme awareness.
   - Never alter original in-memory captured raw traffic.

4. Run builds and automated test suites:

   **Burp Suite Edition:**
   ```powershell
   # Compile fat JAR
   cmd /c build.bat

   # Run automated test suites (Filter, Diff, Replay tests)
   javac -cp "lib/*;build/classes" -d build/classes/test src/test/java/requestvault/export/ReplayCodeGeneratorTest.java src/test/java/requestvault/analysis/TrafficFilterAndPresetTest.java src/test/java/requestvault/analysis/ResponseDiffTest.java
   java -cp "build/classes;build/classes/test;lib/*" requestvault.export.ReplayCodeGeneratorTest
   java -cp "build/classes;build/classes/test;lib/*" requestvault.analysis.TrafficFilterAndPresetTest
   java -cp "build/classes;build/classes/test;lib/*" requestvault.analysis.ResponseDiffTest
   ```

   **Caido Edition:**
   ```bash
   cd Caido/RequestVault-Caido
   npm install
   npm run typecheck
   node build.js
   node test/test.js
   ```

5. Commit using descriptive commit messages:
   ```bash
   git commit -m "feat(replay): add token parameter support to replay script generator"
   ```

6. Push to your fork and submit a Pull Request to the `main` branch.
