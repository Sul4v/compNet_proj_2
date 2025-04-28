# Simple FTP Client/Server

This project implements a basic FTP client and server in C, following the specifications of a typical computer networks course assignment.

## Features

*   Implements a subset of FTP commands using **Active Mode** only.
*   **Server:** Handles multiple clients concurrently using `select()` for control connections and `fork()` for data transfer commands (`LIST`, `RETR`, `STOR`).
*   **Client:** Provides a command-line interface to interact with the FTP server.
*   **Authentication:** Uses a simple username/password scheme based on the `users.csv` file.

### Implemented Commands

**Server Commands:**
*   `USER <username>`
*   `PASS <password>`
*   `PORT <h1,h2,h3,h4,p1,p2>`
*   `LIST`
*   `RETR <filename>`
*   `STOR <filename>`
*   `CWD <directory>`
*   `PWD`
*   `QUIT`

**Client Local Commands:**
*   `!CWD <directory>` (Changes client's local directory)
*   `!PWD` (Displays client's local directory)

## Project Structure

```
.
├── client/
│   └── ftpcli.c      # Client source code
├── server/
│   └── ftpserv.c     # Server source code
├── Makefile          # Makefile for building the client and server
└── users.csv         # User authentication file (comma-separated: username,password)
```

## Building

Standard C build tools (`gcc`, `make`) are required.

1.  **Compile both client and server:**
    ```bash
    make
    ```
2.  **Compile only the client:**
    ```bash
    make client
    ```
3.  **Compile only the server:**
    ```bash
    make server
    ```
4.  **Clean build artifacts:**
    ```bash
    make clean
    ```

This will create two executables: `ftpcli` (in the root directory) and `ftpserv` (in the root directory).

## Running

1.  **Prepare `users.csv`:** Ensure the `users.csv` file exists in the root directory and contains username,password pairs, one per line (e.g., `bob,donuts`).

2.  **Start the Server:**
    Open a terminal in the project root directory and run:
    ```bash
    ./ftpserv 
    ```
    The server will start listening on port 21.

3.  **Start the Client:**
    Open *another* terminal in the project root directory and run:
    ```bash
    ./ftpcli <server_ip_address>
    ```
    Replace `<server_ip_address>` with the actual IP address of the machine running the server. If running on the same machine, use `127.0.0.1`:
    ```bash
    ./ftpcli 127.0.0.1
    ```
4.  **Interact:** The client will display usage instructions. You need to authenticate using `USER` and `PASS` with credentials from `users.csv` before using other commands like `LIST`, `RETR`, `STOR`, etc. 