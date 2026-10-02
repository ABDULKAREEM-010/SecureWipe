# Secure E-Waste Data Wiping Platform

## Overview
A Python desktop application for secure data wiping with AI-powered sensitive file detection and configurable destruction methods. This application provides real file system access for actual secure data deletion operations.

## Recent Changes
- **2025-01-21**: Created core application structure with all main modules
- **2025-01-21**: Implemented AI-powered sensitive data detection using OpenAI GPT-5
- **2025-01-21**: Built secure wiping engine with configurable passes (1-35), patterns (zero/random/DoD), and methods
- **2025-01-21**: Created digital certificate generation system with PDF and JSON outputs
- **2025-01-21**: Added comprehensive audit logging for compliance tracking
- **2025-01-21**: Set up desktop GUI using tkinter with VNC support

## User Preferences
- **Real Operations**: User specifically requested NO simulations - all file operations must be real
- **Security Focus**: Emphasis on actual secure deletion with industry-standard methods
- **Compliance**: Digital certificates and audit trails for regulatory compliance
- **Cross-platform**: Designed to work on Windows/Linux with future Android support

## Project Architecture
- **main.py**: Desktop GUI application entry point with tkinter interface
- **src/file_manager.py**: Real file system operations and directory browsing
- **src/ai_detector.py**: OpenAI-powered sensitive data detection engine
- **src/wipe_engine.py**: Secure deletion algorithms with multiple overwrite patterns
- **src/certificate_generator.py**: Digital certificate creation with QR codes and signatures
- **src/audit_logger.py**: SQLite-based audit logging system

## Key Features
- Real file system access and browsing
- AI identification of sensitive files (SSN, credit cards, PII, etc.)
- Configurable secure deletion: 1-35 passes, zero/random/DoD patterns
- Digital certificates with tamper-proof signatures
- Comprehensive audit trails
- VNC-based desktop interface

## Dependencies
- Python 3.11 with OpenAI, cryptography, reportlab, qrcode, psutil, Pillow
- OpenAI API key configured for sensitive data detection
- SQLite for audit logging
- tkinter for desktop GUI (runs via VNC in Replit environment)

## Deployment
- Desktop application runs locally with VNC viewer in browser
- Future phases: cross-platform agents, bootable ISO, enterprise deployment