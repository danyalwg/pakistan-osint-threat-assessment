```
# Pakistan OSINT Threat Assessment Platform
```


---

## 1. Introduction

The **Pakistan OSINT Threat Assessment Platform** is a desktop-based Open-Source Intelligence (OSINT) system designed to **systematically collect, extract, filter, and shortlist news articles** that may pose **national security, geopolitical, strategic, or threat-related relevance to Pakistan**.

The platform ingests content from **local, regional, and international media outlets**, processes it through a **multi-stage intelligence pipeline**, and presents analysts with **structured, reviewable outputs** via a graphical interface.

Although the project name references AI, the current production version intentionally implements a **rule-based, explainable decision pipeline**, while remaining **fully AI-ready** for future extensions such as machine learning or large language models.

---

## 2. Key Objectives

- Continuous monitoring of global and regional media
- Identification of Pakistan-relevant narratives
- Early detection of potential threat indicators
- Reduction of analyst workload via intelligent shortlisting
- Reliable operation under blocking, censorship, and rate limits
- Analyst-friendly GUI operation (no CLI dependence)

---

## 3. High-Level System Architecture

```
User (GUI)
  ↓
Source Configuration (sources.json)
  ↓
Fetcher (RSS / Sitemap / HTML Listings)
  ↓
Tor-Routed Network Requests
  ↓
Article URL Discovery
  ↓
Content Extraction (Multi-Stage)
  ↓
Keyword Layer 1 (National Relevance)
  ↓
Keyword Layer 2 (Threat Indicators)
  ↓
Shortlisting
  ↓
Run-Based Storage
  ↓
Analyst Review / CSV Export
```

---

## 4. Technology Stack

### Core Language
- Python 3.10+

### Desktop Interface
- PyQt6

### Networking & Parsing
- requests
- feedparser
- BeautifulSoup4
- trafilatura

### Anonymity & Anti-Blocking
- Tor (SOCKS5 routing)

### Data Persistence
- JSON (human-readable, auditable)

---

## 5. Repository Structure (Complete)

```
pakistan-osint-threat-assessment/
│
├── main.py
├── requirements.txt
│
├── data/
│   ├── sources.json
│   ├── keywords_national.json
│   ├── keywords_threat.json
│   ├── keywords.json
│   ├── tor.exe
│   │
│   ├── news/
│   └── runs/
│       └── run_YYYY-MM-DD_HH-MM-SS/
│           ├── fetched/
│           └── shortlisted/
│
├── src/
│   ├── gui.py
│   ├── fetcher.py
│   ├── extractor.py
│   ├── keywords.py
│   ├── models.py
│   ├── sources_repo.py
│   ├── storage.py
│   ├── tor_client.py
│   ├── analysis_layers.py
│   └── __init__.py
│
└── tor_data/
    └── (Tor runtime state)
```

---

## 6. Entry Point

### main.py

- Application bootstrap file
- Validates required configuration files
- Initializes GUI
- Starts PyQt event loop

Run command:
- python main.py

---

## 7. GUI Layer

### src/gui.py

The GUI is the primary user interface for analysts.

Capabilities:
- Start new intelligence collection runs
- Edit and manage sources
- Edit national and threat keywords
- Browse fetched and shortlisted articles
- Export results to CSV
- View logs and status messages

Design advantages:
- No command-line usage required
- Suitable for non-technical analysts
- Clear separation between data ingestion and review

---

## 8. Source Management

### data/sources.json

Defines all monitored media outlets.

Each source includes:
- Country / Region
- Publisher name
- One or more endpoints
- Endpoint type

Supported endpoint types:
- RSS
- FEED_DIRECTORY
- HTML_LISTING
- SITEMAP_INDEX

### src/sources_repo.py

- Loads source definitions
- Validates structure
- Persists GUI edits back to JSON

Advantages:
- New sources added without code changes
- Supports heterogeneous publisher layouts

---

## 9. Fetching & URL Discovery

### src/fetcher.py

Responsible for discovering article URLs using multiple strategies:
- RSS feed parsing
- Sitemap traversal
- HTML listing scraping
- Feed auto-discovery from directories

Features:
- Deduplication
- Metadata normalization
- Resilience against missing RSS feeds

---

## 10. Tor Integration

### src/tor_client.py

All HTTP requests can be routed through Tor.

Behavior:
- Detects existing Tor services (9050 / 9150)
- Auto-launches bundled tor.exe if needed
- Routes traffic via SOCKS5 proxy
- Stores runtime state in tor_data/

Why Tor:
- Prevent IP bans
- Access region-blocked content
- Reduce attribution risk
- Enable sustained scraping

---

## 11. Article Content Extraction

### src/extractor.py

Multi-layer extraction pipeline:
1. Trafilatura (primary extractor)
2. JSON-LD metadata parsing
3. Next.js embedded content extraction
4. Semantic HTML (<article>, <main>)
5. Paragraph-level fallback

Extracted fields:
- Title
- Author
- Published date
- Clean article body text

Design advantage:
- High extraction success rate
- Works on modern JS-heavy sites
- Graceful degradation on failure

---

## 12. Data Model

### src/models.py

Defines the Article data structure.

Key fields:
- Source, country, URL
- Metadata (title, date, author)
- Full article text
- Keyword matches
- Flags:
  - national_relevant
  - threat_relevant
  - shortlisted

Reserved AI fields:
- truth_score
- threat_score
- threat_level
- threat_factors

---

## 13. Keyword Intelligence System

### Keyword Files
- data/keywords_national.json
- data/keywords_threat.json

### src/keywords.py

Implements a two-layer relevance funnel.

Layer 1: National Relevance
- Pakistan-related entities
- State institutions
- Strategic sectors
- Geography and borders

Layer 2: Threat Indicators
- Terrorism
- Insurgency
- Sanctions
- Military escalation
- Diplomatic pressure
- Cyber threats

Decision logic:
- Must pass Layer 1 → eligible for Layer 2
- Must pass both → shortlisted

Advantages:
- Strong noise reduction
- Explainable decisions
- Analyst-aligned triage logic

---

## 14. Analysis Layer (Future AI)

### src/analysis_layers.py

Currently a placeholder.

Intended future use:
- ML-based threat scoring
- Narrative clustering
- Credibility analysis
- Disinformation detection

The architecture allows AI insertion without refactoring core logic.

---

## 15. Storage & Runs

### src/storage.py

Each execution creates a new immutable run folder.

Structure:
- fetched/ → all collected articles
- shortlisted/ → filtered high-value articles

Benefits:
- Auditable history
- No data overwriting
- Supports longitudinal analysis

---

## 16. How to Run the Project

### Requirements
- Python 3.10+
- Windows (primary tested platform)
- Internet access


## Setup & Running the Application

This section explains how to clone the repository, install dependencies, and run the application.

---

### 1. Clone the Repository

Command:
```
git clone https://github.com/danyalwg/pakistan-osint-threat-assessment.git
```

Move into the project directory:
```
cd pakistan-osint-threat-assessment
```

---

### 2. Verify Python Installation

Check Python version (Python 3.10 or newer required):
```
python --version
```

If Python is not installed, download it from:
https://www.python.org/downloads/

Ensure Python is added to PATH during installation.

---

### 3. Install Dependencies

Install all required packages:
```
pip install -r requirements.txt
```

This installs:
- PyQt6 (GUI)
- requests, feedparser (network & RSS)
- trafilatura, BeautifulSoup4 (article extraction)
- Tor networking dependencies

---

### 4. Verify Required Configuration Files

Ensure the following files exist:
```
data/sources.json
```
```
data/keywords_national.json
```
```
data/keywords_threat.json
```

These files define:
- News sources
- National relevance keywords
- Threat indicator keywords

---

### 5. Tor Configuration (Optional but Recommended)

Tor behavior:
- Uses existing Tor service if running
- Otherwise launches bundled executable:
```
data/tor.exe
```

Tor runtime data is stored in:
```
tor_data/
```

If Tor is unavailable, the application will still run, but some sources may be blocked.

---

### 6. Run the Application

Start the application from the project root:
```
python main.py
```

This launches the desktop GUI titled:
- AI-based Threat Assessment of Pakistan

---

### 7. Running a Collection Cycle (GUI)

Inside the GUI:
1. Review or edit sources (optional)
2. Click Run / Start
3. The system will:
   - Fetch articles
   - Extract content
   - Apply keyword filtering
   - Save results into a new run directory

---

### 8. Output Location

Each run creates a timestamped folder:
```
data/runs/run_YYYY-MM-DD_HH-MM-SS/
```

With subfolders:
```
fetched/
```
```
shortlisted/
```

Results can be reviewed in the GUI or exported as CSV.



## 19. Current Limitations

- Rule-based keyword logic only
- No active ML models
- English-centric extraction
- No sentiment or stance detection

---

## 20. Roadmap (Optional)

- LLM-based threat scoring
- Multilingual (Urdu, Arabic) support
- Trend and spike detection
- Analyst annotation workflows
- Automated brief generation

---

## 21. Intended Use

This system is designed for:
- OSINT research
- Strategic monitoring
- Policy analysis
- Media threat assessment

It does **not** perform surveillance or interception.

---

## 22. License

To be defined per client requirements.

---

## Final Note

This project is engineered as a **professional intelligence ingestion and triage system**, prioritizing **reliability, explainability, and extensibility** over black-box automation.

```
