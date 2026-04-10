# Argus: Advanced Exam Supervision System
> "Because cheating shouldn't be easier than studying."

**Argus** is a high-performance, real-time network monitoring system engineered for high-stakes exam environments. Operating directly at the network packet level, it eliminates loopholes like VPNs, DNS-bypassing, and clock manipulation with surgical precision.

Developed for the **Software Project Lab 1** at the **Institute of Information Technology, University of Dhaka**.

---

### 🚀 Core Features
* **DPI & SNI Extraction:** Bypasses basic DNS filtering limitations by extracting Server Name Indication (SNI) from initial TLS handshakes before encryption fully takes over.
* **VPN Detection:** Analyzes payload randomness via **Shannon Entropy** to identify encrypted tunnels or VPNs without needing to decrypt data.
* **Hybrid Cryptography:** Secures the communication tunnel between student and supervisor using a robust mix of asymmetric (RSA) and symmetric (RC4/XOR) encryption.
* **Precision Anti-Tamper:** Employs **Cristian’s Algorithm** to sync clients with a trusted server time, defeating attempts to manipulate local OS system clocks.
* **Multiplexed Dashboard:** A single-threaded **I/O multiplexing (select())** architecture capable of asynchronously monitoring 100+ students via a sleek ImGui/OpenGL interface.

---

### 📦 Modern Deployment
Deployment has been modernized for professional cross-platform reliability:
* **CMake Integration:** Automated dependency discovery for libpcap, GLFW, and OpenGL.
* **Streamlined Makefiles:** Modular build system for clean installation of both the Student Agent and Supervisor Server.

---

### 🧠 The Algorithmic Engine
Argus is built on highly optimized data structures to ensure enforcement happens with zero network latency:
* **String Matching:** **Aho-Corasick Automaton** (Trie + BFS failure links) for O(n) simultaneous multi-pattern scanning of raw payloads.
* **Domain Resolution:** Trie-based recursive wildcard matching and **Polynomial Rolling Hashes** for $O(1)$ lookups.
* **Information Theory:** VPN detection via the Shannon Entropy formula:
  $$H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
* **Data Compression:** **Huffman Coding** shrinks violation logs to fit within the strict 512-byte binary protocol limit.

---

### ⚙️ System Components
* **Supervisor Server (`echo_supervisor.cpp`):** The command center. Processes handshakes, decrypts telemetry, and provides a real-time dark-themed dashboard.
* **Student Agent (`echo_student.cpp`):** A lightweight background sniffer with a **watchdog thread** that sends immediate tamper alerts if the process is terminated.

---

### 🛠️ Quick Start
**Prerequisites:** C++17, libpcap, GLFW, OpenGL 3.2+.

1. **Build:**
   ```bash
   mkdir build && cd build
   cmake ..
   make install
2. Supervisor: Launch ./bin/supervisor_app.
3. Student: Launch sudo ./bin/student_agent (requires root for packet sniffing).

Developed for excellence at IIT, University of Dhaka.
