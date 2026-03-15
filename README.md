# Mini CTF Web Recon Scanner

A beginner-friendly Python tool made for **web CTF challenges** and **safe lab environments**.  
This scanner helps players quickly spot suspicious clues such as leaked headers, weak cookies, HTML comments, redirects, and common hidden endpoints.

## Features

- Checks for important security headers
- Detects suspicious response headers such as:
  - `Server`
  - `X-Powered-By`
  - debug/internal-style custom headers
- Inspects cookies for weak settings
- Searches for HTML comments in page source
- Hunts for interesting keywords such as:
  - `flag`
  - `admin`
  - `debug`
  - `secret`
  - `token`
- Tests common endpoints like:
  - `/robots.txt`
  - `/admin`
  - `/login`
  - `/debug`
  - `/.git`
  - `/phpinfo.php`
- Checks basic redirect behavior

## Why I Built This

I built this project as a small cybersecurity portfolio project during my semester break to improve my Python, web security, and GitHub skills.

The goal is not to create a full vulnerability scanner, but to build a lightweight **CTF web reconnaissance helper** that can support early-stage analysis in beginner-friendly web challenges.

## Technologies Used

- Python 3
- requests
- colorama
- beautifulsoup4

## Installation

Clone the repository:

```bash
git clone https://github.com/os3ng/Mini-WebSec-Scanner.git
cd Mini-WebSec-Scanner
