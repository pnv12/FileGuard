# FileGuard Architecture

## Overview

FileGuard is a local-first file analysis application.

The system is designed to identify a file, determine its format,
select the appropriate analysis plan, run relevant analyzers,
collect evidence, generate findings and present the results
through a single investigation interface.

## Core Pipeline

```text
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
