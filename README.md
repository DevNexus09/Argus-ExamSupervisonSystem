Argus - Advanced Exam Supervision System

Argus is a real-time network monitoring system designed for strict exam supervision. Built entirely in C++, it operates directly at the network packet level to enforce domain whitelists, detect unauthorized internet usage, and prevent cheating mechanisms like VPNs or system clock tampering.

Developed for the Software Project Lab 1 at the Institute of Information Technology, University of Dhaka.

🚀 Core Features
1. Deep Packet Inspection (DPI) & SNI Extraction: Bypasses the limitations of basic DNS filtering. Argus extracts the Server Name Indication (SNI) from the initial TLS (HTTPS) handshake to guarantee the capture of the destination domain before the tunnel becomes fully encrypted.

2. Encrypted Traffic Analysis (VPN Detection): Analyzes the randomness of network payloads. If a connection maintains sustained high entropy, Argus flags it as a hidden encrypted tunnel or VPN, even without decrypting the data.

3. Hybrid Cryptographic Protocol: Secures the communication tunnel between the student client and the supervisor server using a mix of asymmetric and symmetric encryption mechanisms.

4. Anti-Tampering & Time Synchronization: Synchronizes the client with a trusted server time, compensating for network latency. Argus runs a parallel monotonic clock to instantly detect if a student attempts to manipulate their local OS system clock.

5. Custom Binary Protocol with Compression: Network payloads are strictly limited to 512 bytes. To prevent data loss and buffer overflows from large URLs, Argus compresses violation text before network transmission.

6. Multiplexed Live Dashboard: The Supervisor server utilizes I/O multiplexing, allowing a single thread to asynchronously monitor 100+ students without the heavy memory overhead of multithreading. The UI is powered by ImGui and OpenGL.

🧠 Algorithms & Data Structures
Argus is built on a foundation of highly optimized algorithms to ensure deep packet scanning, cryptographic security, and rule enforcement happen with zero noticeable network latency.

String Matching & Parsing
1. Aho-Corasick Algorithm: Used for Deep Packet Inspection (DPI). Builds an automaton using a Trie and Breadth-First Search (BFS) failure links to scan raw network payloads for blacklisted keywords simultaneously in O(n) time without backtracking.

2. Polynomial Rolling Hash: Used within a custom Hash Table implementation to provide instant O(1) lookups for specific, exact-match allowed websites (e.g., github.com). Handles collisions via chaining (Linked Lists).

3. Recursive Wildcard Matching (Trie): A Prefix Tree implementation that traverses nodes to match subdomain patterns, allowing wildcard entries like *.edu to instantly resolve and validate domains like mit.edu.

Cryptography & Security
1. RSA Algorithm (Modular Exponentiation): Asymmetric encryption used during the initial client-server handshake. The student encrypts a randomly generated session key using the supervisor's public key (N, E), heavily relying on efficient modular exponentiation math helpers.

2. RC4 / XOR Stream Cipher: Symmetric encryption used for the remainder of the session. Achieves high-speed, lightweight data obfuscation by XOR-ing the serialized packet bytes with the dynamically negotiated session key.

3. Shannon Entropy Formula: Used for VPN/Tunnel detection. Calculates the information density(Entropy)of packet payloads. An entropy approaching 8.0 bits/byte mathematically proves the data is encrypted or compressed noise.

Data Compression & Integrity
1. Huffman Coding: A lossless data compression algorithm used to shrink large URLs and violation payloads to fit within the strict 512-byte protocol limit. Utilizes a Min-Heap (Priority Queue) to build a static optimal prefix tree based on English and URL character frequencies, packing variable-length binary codes into 8-bit bytes.

2. Modulo 256 Checksum: An integrity verification algorithm that loops through the binary packet structure to detect network corruption or tampering before deserialization.

Distributed Systems & Concurrency
1. Cristian's Algorithm: Used for robust time synchronization. Compensates for network lag by measuring Round Trip Time (RTT), halving it to estimate one-way latency, and adding it to the server's time to establish a Trusted Time Reference.

2. I/O Multiplexing (select()): While not a traditional algorithm, this system-level polling mechanism is the core of the server architecture. It sequentially checks the states of multiple file descriptors (sockets) in a single loop, scaling to handle many concurrent examinees asynchronously.

3. Max-Heap (heapify_up, heapify_down): A Priority Queue implementation utilized by the Supervisor server to dynamically maintain and re-sort a real-time "Top Violators" leaderboard on the dashboard.

⚙️ System Components
1. Supervisor Server (echo_supervisor.cpp)
The centralized command center that manages incoming connections. It processes handshakes, decrypts incoming telemetry, records violations into an exported CSV/TXT report, and provides a sleek, dark-themed real-time dashboard.

2. Student Agent (echo_student.cpp)
A lightweight, background client running on the examinee's machine. It utilizes libpcap to intercept network traffic, enforces the Whitelist/Blacklist rules, and communicates securely with the Supervisor. It includes a built-in watchdog thread to send immediate tamper alerts if the process is forcefully killed.

🛠️ Prerequisites & Build Instructions
C++ Compiler: C++17 or higher
Libraries: libpcap (Packet capture)
GLFW & OpenGL 3.2+ (ImGui Dashboard)

Permissions: The Student Agent requires root/administrator privileges to bind to the network interface card for packet sniffing.


