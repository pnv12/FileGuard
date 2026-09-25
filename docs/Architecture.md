# FileGuard Architecture

## Overview

FileGuard is a local-first file analysis application.

The system identifies a file, determines its format, selects the
appropriate analysis plan, runs relevant analyzers, collects evidence,
generates findings and presents the results through one interface.

## Core Pipeline

File
↓
File Detector
↓
Analysis Plan / Router
↓
Analyzer
↓
Evidence Engine
↓
Findings / Rules
↓
Correlation Engine
↓
Explanation
↓
Report / Next Action

## Main Layers

### Core

Central analysis orchestration and shared logic.

### Analyzers

Specialized file analysis engines.

V1:
- Generic
- Archive
- APK

### Utils

Reusable technical utilities.

V1:
- Hash calculation
- Byte processing
- Format detection
- Local storage

### UI

Interface-specific modules.

### Assets

Static application resources.

### Docs

Architecture, specification and roadmap documentation.

## Analysis Philosophy

FileGuard reports observable characteristics and explicit findings.

It does not claim that every file is malicious or safe.

Security findings must be based on evidence and defined rules.

AI may later explain or correlate findings, but it must not invent
the underlying security evidence.

## Privacy

The first version follows a local-first browser architecture.

Files should not be uploaded to external services unless a future
feature explicitly requires external processing and the user is
clearly informed.

## Future Extensions

The architecture should allow new analyzers without redesigning
the core application.

Possible future analyzers:

- PDF
- Office documents
- Images
- Executables
- Audio
- Video
- Additional Android analysis
