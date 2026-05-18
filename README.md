# Behavioral-Ransomware-Detection-Creating-an-Early-Warning-System-for-Endpoints

diplom-project

### Detailed Timeline & Deliverables

#### 🟢 Phase 1: Research, Abstraction & Stack Selection

- **Status:** **COMPLETED** ✅
- **Deliverables:**
  - Analyzed the SMB threat landscape and defined the "Protection Gap" between enterprise EDRs and signature-based AVs.
  - Formulated the mathematical foundation for local behavioral detection (sliding-window I/O Velocity + Shannon Entropy).

#### 🟡 Phase 2: Architecture, UI Prototyping & Core Engine

- **Status:** **IN PROGRESS (Advanced Stage)** ⏳
- **Deliverables:**
  - **[COMPLETED ✅]** Designed a detailed system architecture diagram separating User-Space logic from OS Kernel interactions.
  - **[COMPLETED ✅]** Developed a functional HTML/CSS prototype of the administrative dashboard, showcasing real-time UI/UX, entropy graphs, and process watchlist layouts.
  - **[IN PROGRESS]** Writing the asynchronous file system listener using the `watchdog` API to hook into low-level OS event streams (`ReadDirectoryChangesW` / `inotify`).
  - **[IN PROGRESS]** Implementing the math engine for real-time Shannon Entropy calculation (randomization threshold > 7.5).

#### 🔵 Phase 3: Isolated Sandbox Testing & Threshold Calibration

- **Status:** **PLANNED**
- **Deliverables:**
  - Provisioning a fully isolated VirtualBox testing network (sandbox) detached from the host and internet.
  - Developing safe "crypto-simulation" scripts to mimic ransomware behavior securely.
  - Fine-tuning thresholds to minimize false positives during heavy legitimate disk operations (compiling, archiving).

#### 🔵 Phase 4: Integration, Resource Profiling & Documentation

- **Status:** **PLANNED**
- **Deliverables:**
  - Integrating the Python core engine with the local SQLite3 database and connecting telemetry data to the HTML interface.
  - Conducting final resource profiling to guarantee the agent stays under strict limits (`<1% CPU`, `<50MB RAM`).
  - Compiling and formatting the final course project text for official defense.
