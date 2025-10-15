# funkyfuzz
small tool in python for checking sesitive file and xss and html injection vulnerability

<p align="center">
  <img src="https://img.shields.io/badge/funkyfuzz-lightgrey?style=for-the-badge&logo=zap&logoColor=white" alt="go4crt.sh" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=mit" alt="MIT" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge&logo=checkcircle" alt="Active" />
  <img src="https://img.shields.io/badge/For-Bug%20Bounty-red?style=for-the-badge&logo=bug" alt="For Bug Bounty Hunters" />
</p>

## funkyfuzz

`FunkyFuzz` is a medium-level web vulnerability scanner designed for security researchers, bug bounty hunters, and web penetration testers. It combines crawling, XSS/HTML injection detection, and sensitive file discovery into one easy-to-use tool.

---

## ✨ Features
- Web Crawling: Recursively explores target websites, respecting same-origin by default, with optional subdomain crawling.

- XSS & HTML Injection Detection: Injects payloads into query parameters and forms to detect reflected vulnerabilities.

- Sensitive File Discovery: Checks for exposed sensitive paths and files like .env, .git/, wp-config.php, robots.txt, and more.

- Reporting: Generates both machine-readable JSON and human-friendly HTML reports, including summaries and direct links to vulnerable URLs.

- Configurable: Supports async requests, concurrency, and page crawl limits for flexible scanning.

---

## 📦 Installation

```bash
git clone https://github.com/4ncurze/funkyfuzz
cd funkyfuzz
pip install -r requirements.txt --break-system-packages


```

## 🚀 Usage

```bash
python3 funkyfuzz -h 
```
`

