#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <errno.h>
#include <ctype.h> // For isspace
#include <fcntl.h>    // For pipe, dup2
#include <signal.h>   // For kill()
#include <limits.h>   // For PATH_MAX
#include <sys/stat.h> // For stat()

#define LISTEN_PORT 21
#define BACKLOG 10
#define MAX_CLIENTS FD_SETSIZE // Maximum number of clients (usually 1024)
#define BUFFER_SIZE 1024
#define DATA_PORT 20 // Standard FTP data port
#define MAX_USERS 50 // Maximum number of users to load from file
#define MAX_USER_LEN 100
#define MAX_PASS_LEN 100
#define ROOT_PATH_MAX PATH_MAX

// Structure to hold client connection state
typedef struct {
    int fd; // Client socket file descriptor
    struct sockaddr_in addr; // Client address info
    // Authentication state:
    int authenticated;      // 0 = no, 1 = yes
    char username_provided[BUFFER_SIZE]; // Stores username after USER cmd
    // Data connection info (from PORT command):
    char data_ip[INET_ADDRSTRLEN]; // Client's IP for data connection
    int data_port;                 // Client's port for data connection
    int port_cmd_received;         // Flag: Has PORT been received recently?
    pid_t child_pid;               // PID of child process handling data transfer (-1 if none)
    char working_directory[PATH_MAX]; // Store the client's working directory
} client_state_t;

// Structure for storing user credentials
typedef struct {
    char username[MAX_USER_LEN];
    char password[MAX_PASS_LEN];
} user_auth_t;

// Global array for user credentials and count
user_auth_t loaded_users[MAX_USERS];
int num_loaded_users = 0;

char server_root[ROOT_PATH_MAX]; // Global variable to store server root

// TODO: Add function prototypes
// Function to send a reply to the client
void send_reply(int client_fd, const char *message);
// Function to handle commands from a client
void handle_client_command(client_state_t *client);
// New function prototype for handling child termination
void handle_child_termination(client_state_t clients[], int max_clients);
int load_users(const char* filename); // Prototype for user loading function

// Global array to store client states
client_state_t clients[MAX_CLIENTS];

int main(int argc, char *argv[]) {
    printf("FTP Server Starting...\n");

    // Store the server's root directory at startup
    if (getcwd(server_root, sizeof(server_root)) == NULL) {
        perror("getcwd failed for server root");
        exit(EXIT_FAILURE);
    }

    // Load users from file (now from root directory)
    if (load_users("users.csv") < 0) {
         fprintf(stderr, "FATAL: Failed to load users from users.csv\n");
         exit(EXIT_FAILURE);
    }
    printf("Loaded %d users from users.csv\n", num_loaded_users);
    if (num_loaded_users == 0) {
        fprintf(stderr, "WARNING: No users loaded. Authentication will fail.\n");
    }

    int listen_fd;
    struct sockaddr_in server_addr;
    int optval = 1;

    // Create listening socket
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse address
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt failed");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    // Initialize server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen on all interfaces
    server_addr.sin_port = htons(LISTEN_PORT);

    // Bind the socket to the address and port
    if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen failed");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", LISTEN_PORT);

    // Initialize client states
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        clients[i].fd = -1; // Mark as unused
        clients[i].authenticated = 0; // Initialize as not authenticated
        clients[i].username_provided[0] = '\0'; // Clear username
        clients[i].data_port = -1;       // Initialize data port
        clients[i].port_cmd_received = 0; // Reset PORT flag
        clients[i].child_pid = -1; // Initialize child PID
    }

    fd_set read_fds; // Set of file descriptors to monitor for reading
    int max_fd;      // Maximum file descriptor value for select()
    int activity;    // Result of select()

    while (1) { // Main server loop
        FD_ZERO(&read_fds);    // Clear the set
        FD_SET(listen_fd, &read_fds); // Add listening socket to the set
        max_fd = listen_fd;

        // Add active client sockets to the set
        for (int i = 0; i < MAX_CLIENTS; ++i) {
            if (clients[i].fd > 0) { // If the client slot is used
                FD_SET(clients[i].fd, &read_fds);
                if (clients[i].fd > max_fd) {
                    max_fd = clients[i].fd;
                }
            }
        }

        // Check for terminated child processes *before* select (non-blocking)
        handle_child_termination(clients, MAX_CLIENTS);

        // Set timeout for select (optional, but good practice)
        struct timeval timeout;
        timeout.tv_sec = 1; // Check for terminated children every second
        timeout.tv_usec = 0;

        // Wait for activity on any of the sockets
        activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if ((activity < 0) && (errno != EINTR)) {
            perror("select error");
            continue;
        }

        // If select timed out, loop again to check for terminated children etc.
        if (activity == 0) {
            continue;
        }

        // Check if there is an incoming connection on the listening socket
        if (FD_ISSET(listen_fd, &read_fds)) {
            int new_socket;
            struct sockaddr_in client_addr;
            socklen_t addrlen = sizeof(client_addr);

            if ((new_socket = accept(listen_fd, (struct sockaddr *)&client_addr, &addrlen)) < 0) {
                perror("accept failed");
                // Continue accepting other connections
            } else {
                printf("New connection from %s:%d on socket %d\n",
                       inet_ntoa(client_addr.sin_addr),
                       ntohs(client_addr.sin_port),
                       new_socket);

                // Add new socket to the array of clients
                int added = 0;
                for (int i = 0; i < MAX_CLIENTS; ++i) {
                    if (clients[i].fd == -1) { // Find an empty slot
                        clients[i].fd = new_socket;
                        clients[i].addr = client_addr;
                        clients[i].authenticated = 0; // Ensure new client is not authenticated
                        clients[i].username_provided[0] = '\0';
                        clients[i].data_port = -1;      // Reset data port info for new client
                        clients[i].port_cmd_received = 0;
                        clients[i].child_pid = -1; // Ensure new client has no child PID

                        // Send initial welcome message
                        send_reply(new_socket, "220 Service ready for new user.\r\n");
                        added = 1;
                        break;
                    }
                }
                if (!added) {
                    fprintf(stderr, "Too many clients connected.\n");
                    send_reply(new_socket, "421 Service not available, closing control connection.\r\n");
                    close(new_socket);
                }
            }
        }

        // Check active client sockets for incoming data (commands)
        for (int i = 0; i < MAX_CLIENTS; ++i) {
            if (clients[i].fd > 0 && FD_ISSET(clients[i].fd, &read_fds)) {
                client_state_t *current_client = &clients[i];
                // Check if client is busy with a data transfer
                if (current_client->child_pid != -1) {
                    // Optionally send a 4xx temporary error, or just ignore
                    // send_reply(current_client->fd, "425 Can't open data connection (transfer in progress?).\r\n");
                    // Read the command to clear the buffer, but ignore it for now
                    char temp_buf[100];
                    read(current_client->fd, temp_buf, sizeof(temp_buf));
                    printf("Client [%d] sent command while data transfer active. Ignored.\n", current_client->fd);
                } else {
                    handle_client_command(current_client);
                }
            }
        }
    }

    printf("FTP Server Shutting Down...\n");
    close(listen_fd); // Close the listening socket when done
    return 0;
}

// Function to send a reply to the client
void send_reply(int client_fd, const char *message) {
    if (send(client_fd, message, strlen(message), 0) < 0) {
        perror("send failed");
        // Handle error, maybe close connection?
    }
    printf("SENT to [%d]: %s", client_fd, message); // Log sent message
}

// Function to trim leading/trailing whitespace from a string (in-place)
char *trim_whitespace(char *str) {
    char *end;
    // Trim leading space
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) // All spaces?
        return str;
    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    // Write new null terminator
    *(end + 1) = 0;
    return str;
}

// Function to handle commands from a client
void handle_client_command(client_state_t *client) {
    char buffer[BUFFER_SIZE];
    char command[BUFFER_SIZE];
    char argument[BUFFER_SIZE];
    int valread = read(client->fd, buffer, BUFFER_SIZE - 1);

    if (valread > 0) {
        buffer[valread] = '\0'; // Null-terminate the received data
        printf("RECV from [%d]: %s", client->fd, buffer); // Log received message

        // Basic command parsing (split command and argument)
        char *raw_command = buffer;
        char *raw_argument = "";
        char *space = strchr(buffer, ' ');
        if (space != NULL) {
            *space = '\0'; // Null-terminate the command part
            raw_argument = space + 1;
        }

        // Copy and trim command and argument
        strncpy(command, raw_command, sizeof(command) - 1);
        command[sizeof(command) - 1] = '\0';
        strncpy(argument, raw_argument, sizeof(argument) - 1);
        argument[sizeof(argument) - 1] = '\0';

        char *trimmed_cmd = trim_whitespace(command);
        char *trimmed_arg = trim_whitespace(argument);

        // Reset port command flag before processing any command
        // This ensures PORT is only valid for the *next* data transfer command
        // client->port_cmd_received = 0; // Let's rethink this - maybe only reset *after* data transfer?

        // Handle commands
        if (strcasecmp(trimmed_cmd, "USER") == 0) {
            if (client->authenticated) {
                send_reply(client->fd, "530 Already logged in.\r\n");
            } else if (strlen(trimmed_arg) == 0) {
                send_reply(client->fd, "501 Syntax error in parameters or arguments (Missing username).\r\n");
            } else {
                // Check against loaded users
                int user_found = 0;
                for (int i = 0; i < num_loaded_users; ++i) {
                    if (strcmp(trimmed_arg, loaded_users[i].username) == 0) { // Case sensitive compare
                        user_found = 1;
                        strncpy(client->username_provided, trimmed_arg, sizeof(client->username_provided) - 1);
                        client->username_provided[sizeof(client->username_provided) - 1] = '\0';
                        send_reply(client->fd, "331 Username OK, need password.\r\n");
                        break; // Found the user
                    }
                }
                if (!user_found) {
                     client->username_provided[0] = '\0'; // Clear any previously provided username
                     send_reply(client->fd, "530 Not logged in (Unknown user).\r\n");
                }
            }
        } else if (strcasecmp(trimmed_cmd, "PASS") == 0) {
            if (client->authenticated) {
                send_reply(client->fd, "202 Command not implemented, superfluous at this site (already logged in).\r\n");
            } else if (client->username_provided[0] == '\0') {
                send_reply(client->fd, "503 Bad sequence of commands (USER first).\r\n");
            } else if (strlen(trimmed_arg) == 0) {
                 send_reply(client->fd, "501 Syntax error in parameters or arguments (Missing password).\r\n");
            } else {
                // Check password against loaded user
                int password_correct = 0;
                 for (int i = 0; i < num_loaded_users; ++i) {
                     // Find the matching username provided earlier
                     if (strcmp(client->username_provided, loaded_users[i].username) == 0) {
                         // Check the password
                         if (strcmp(trimmed_arg, loaded_users[i].password) == 0) {
                             password_correct = 1;
                         }
                         break; // Found the user entry, no need to check further
                     }
                 }

                if (password_correct) {
                    // First change back to the server root directory
                    if (chdir(server_root) == 0) {
                        // Then change to the server directory
                        if (chdir("server") == 0) {
                            // Finally try to change to the user's directory
                            if (chdir(client->username_provided) == 0) {
                                client->authenticated = 1;
                                // Store the working directory
                                if (getcwd(client->working_directory, sizeof(client->working_directory)) != NULL) {
                                    send_reply(client->fd, "230 User logged in, proceed.\r\n");
                                    printf("Client [%d] authenticated as user '%s' and changed to directory '%s'\n", 
                                           client->fd, client->username_provided, client->working_directory);
                                } else {
                                    perror("getcwd failed after chdir");
                                    client->authenticated = 0;
                                    client->username_provided[0] = '\0';
                                    send_reply(client->fd, "530 Failed to get current directory.\r\n");
                                }
                            } else {
                                perror("chdir to user directory failed");
                                client->authenticated = 0;
                                client->username_provided[0] = '\0';
                                send_reply(client->fd, "530 User directory not found.\r\n");
                            }
                        } else {
                            perror("chdir to server directory failed");
                            client->authenticated = 0;
                            client->username_provided[0] = '\0';
                            send_reply(client->fd, "530 Server directory not found.\r\n");
                        }
                    } else {
                        perror("chdir to server root failed");
                        client->authenticated = 0;
                        client->username_provided[0] = '\0';
                        send_reply(client->fd, "530 Server root directory not found.\r\n");
                    }
                } else {
                    // Wrong password or user disappeared between USER/PASS?
                    client->authenticated = 0;
                    client->username_provided[0] = '\0'; // Reset state, require USER again
                    send_reply(client->fd, "530 Not logged in (Password incorrect or User invalid).\r\n");
                }
            }
        } else if (strcasecmp(trimmed_cmd, "QUIT") == 0) {
            printf("Client [%d] requested QUIT.\n", client->fd);
            send_reply(client->fd, "221 Service closing control connection.\r\n");
            close(client->fd);
            client->fd = -1; // Mark slot as free
            return; // Important: client struct is invalid after QUIT processing
        }
        // --- Check authentication for all subsequent commands --- 
        else if (!client->authenticated) {
            send_reply(client->fd, "530 Not logged in.\r\n");
        }
        // --- Authenticated commands --- 
        else if (strcasecmp(trimmed_cmd, "PORT") == 0) {
            int h1, h2, h3, h4, p1, p2;
            // Expected format: h1,h2,h3,h4,p1,p2
            if (sscanf(trimmed_arg, "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2) == 6) {
                // Basic validation of numbers (0-255)
                if (h1 < 0 || h1 > 255 || h2 < 0 || h2 > 255 || h3 < 0 || h3 > 255 || h4 < 0 || h4 > 255 ||
                    p1 < 0 || p1 > 255 || p2 < 0 || p2 > 255) {
                    send_reply(client->fd, "501 Syntax error in parameters or arguments (Invalid host/port format).\r\n");
                } else {
                    // Format the IP address string
                    snprintf(client->data_ip, sizeof(client->data_ip), "%d.%d.%d.%d", h1, h2, h3, h4);
                    // Calculate the port number
                    client->data_port = (p1 * 256) + p2;
                    client->port_cmd_received = 1; // Set the flag

                    printf("Client [%d] Set PORT to %s:%d\n", client->fd, client->data_ip, client->data_port);
                    send_reply(client->fd, "200 PORT command successful.\r\n");
                }
            } else {
                // Parsing failed
                send_reply(client->fd, "501 Syntax error in parameters or arguments (Cannot parse PORT arguments).\r\n");
            }
        }
        else if (strcasecmp(trimmed_cmd, "LIST") == 0) {
            if (!client->port_cmd_received) {
                send_reply(client->fd, "503 Bad sequence of commands (PORT required before LIST).\r\n");
            } else {
                // PORT command was received
                send_reply(client->fd, "150 File status okay; about to open data connection.\r\n");
                
                pid_t pid = fork();
                if (pid < 0) {
                    perror("fork failed");
                    send_reply(client->fd, "451 Requested action aborted: local error in processing (fork failed).\r\n");
                    client->port_cmd_received = 0; // Reset port flag on error
                } else if (pid == 0) {
                    // --- Child Process --- 
                    int data_sock = -1;
                    struct sockaddr_in data_conn_addr, client_data_addr;

                    // Close listening socket (child doesn't need it)
                    // close(listen_fd); // Need listen_fd passed or global
                    // Close other client sockets? Recommended but omitted for simplicity

                    // Create data socket
                    if ((data_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                        perror("child socket failed");
                        exit(EXIT_FAILURE); // Child exits on error
                    }

                    // Bind data socket to port 20
                    memset(&data_conn_addr, 0, sizeof(data_conn_addr));
                    data_conn_addr.sin_family = AF_INET;
                    data_conn_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Or get specific server IP
                    data_conn_addr.sin_port = htons(DATA_PORT);
                    
                    // Allow reuse of port 20 quickly
                    int optval = 1;
                    setsockopt(data_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
                    
                    if (bind(data_sock, (struct sockaddr *)&data_conn_addr, sizeof(data_conn_addr)) < 0) {
                        perror("child bind failed (Port 20)");
                        close(data_sock);
                        exit(EXIT_FAILURE);
                    }
                    
                    // Prepare client address for connect
                    memset(&client_data_addr, 0, sizeof(client_data_addr));
                    client_data_addr.sin_family = AF_INET;
                    client_data_addr.sin_port = htons(client->data_port);
                    if (inet_pton(AF_INET, client->data_ip, &client_data_addr.sin_addr) <= 0) {
                        perror("child inet_pton failed");
                        close(data_sock);
                        exit(EXIT_FAILURE);
                    }
                    
                    // Connect to the client's data port
                    printf("CHILD: Connecting to %s:%d from port %d\n", client->data_ip, client->data_port, DATA_PORT);
                    if (connect(data_sock, (struct sockaddr *)&client_data_addr, sizeof(client_data_addr)) < 0) {
                        perror("child connect failed");
                        close(data_sock);
                        exit(EXIT_FAILURE); // Child exits if connect fails
                    }
                    
                    printf("CHILD: Data connection established. Running ls -l.\n");

                    // Redirect stdout to the data socket
                    dup2(data_sock, STDOUT_FILENO);
                    dup2(data_sock, STDERR_FILENO); // Redirect stderr too
                    close(data_sock); // Close original descriptor after dup2

                    // Execute ls -l command
                    // First change to the correct directory
                    if (chdir(client->working_directory) == 0) {
                        execlp("ls", "ls", "-l", (char *)NULL);
                    } else {
                        perror("chdir failed in LIST");
                        exit(EXIT_FAILURE);
                    }
                    
                    // If execlp returns, it's an error
                    perror("execlp ls failed");
                    exit(EXIT_FAILURE); // Exit child on error

                } else {
                    // --- Parent Process --- 
                    printf("PARENT: Forked child %d for LIST request from client [%d]\n", pid, client->fd);
                    client->child_pid = pid; // Store child PID in client state
                    client->port_cmd_received = 0; // Consume the PORT command flag
                    // Parent continues in select loop, waiting for child termination
                }
            }
        }
        else if (strcasecmp(trimmed_cmd, "PWD") == 0) {
            char reply[BUFFER_SIZE];
            // Get the path relative to the user's directory
            char *user_dir = strstr(client->working_directory, client->username_provided);
            if (user_dir != NULL) {
                // Add trailing slash
                char dir_with_slash[PATH_MAX];
                snprintf(dir_with_slash, sizeof(dir_with_slash), "%s/", user_dir);
                snprintf(reply, sizeof(reply), "257 \"%s\" is current directory.\r\n", dir_with_slash);
            } else {
                // Fallback to just the username if we can't find the path
                snprintf(reply, sizeof(reply), "257 \"%s/\" is current directory.\r\n", client->username_provided);
            }
            send_reply(client->fd, reply);
        }
        else if (strcasecmp(trimmed_cmd, "CWD") == 0) {
             if (strlen(trimmed_arg) == 0) {
                 send_reply(client->fd, "501 Syntax error in parameters or arguments (Missing directory).\r\n");
             } else {
                 if (chdir(trimmed_arg) == 0) {
                     // Update the working directory
                     if (getcwd(client->working_directory, sizeof(client->working_directory)) != NULL) {
                         printf("Client [%d] changed directory to: %s\n", client->fd, client->working_directory);
                         send_reply(client->fd, "200 Directory changed successfully.\r\n");
                     } else {
                         perror("getcwd failed after chdir");
                         send_reply(client->fd, "550 Failed to get current directory.\r\n");
                     }
                 } else {
                     perror("chdir failed");
                     char error_reply[BUFFER_SIZE];
                     snprintf(error_reply, sizeof(error_reply), "550 %s: %s.\r\n", trimmed_arg, strerror(errno));
                     send_reply(client->fd, error_reply);
                 }
             }
        }
        // --- Add RETR Handler --- 
        else if (strcasecmp(trimmed_cmd, "RETR") == 0) {
            if (!client->port_cmd_received) {
                send_reply(client->fd, "503 Bad sequence of commands (PORT required before RETR).\r\n");
            } else if (strlen(trimmed_arg) == 0) {
                send_reply(client->fd, "501 Syntax error in parameters or arguments (Missing filename).\r\n");
            } else {
                // Argument is the filename
                char *filename = trimmed_arg;

                // Check if the file exists and is a regular file
                struct stat file_stat;
                if (stat(filename, &file_stat) < 0) {
                    perror("stat failed for RETR");
                    send_reply(client->fd, "550 File not found or access denied.\r\n");
                    client->port_cmd_received = 0; // Reset flag as PORT wasn't used
                } else if (!S_ISREG(file_stat.st_mode)) {
                    send_reply(client->fd, "550 Requested action not taken (Not a regular file).\r\n");
                    client->port_cmd_received = 0; // Reset flag as PORT wasn't used
                } else {
                    // Try opening the file for reading
                    int file_fd = open(filename, O_RDONLY);
                    if (file_fd < 0) {
                        perror("open failed for RETR");
                        send_reply(client->fd, "550 File not found or access denied.\r\n");
                        client->port_cmd_received = 0; // Reset flag as PORT wasn't used
                    } else {
                        // File opened successfully, proceed with transfer
                        char reply[BUFFER_SIZE];
                        snprintf(reply, sizeof(reply),
                                 "150 Opening BINARY mode data connection for %s (%lld bytes).\r\n",
                                 filename, (long long)file_stat.st_size); // Send file size
                        send_reply(client->fd, reply);

                        pid_t pid = fork();
                        if (pid < 0) {
                            perror("fork failed for RETR");
                            send_reply(client->fd, "451 Requested action aborted: local error in processing (fork failed).\r\n");
                            close(file_fd); // Close file in parent on fork error
                            client->port_cmd_received = 0;
                        } else if (pid == 0) {
                            // --- Child Process --- 
                            int data_sock = -1;
                            struct sockaddr_in data_conn_addr, client_data_addr;
                            ssize_t bytes_read;
                            char data_buffer[BUFFER_SIZE];

                            // Create data socket, bind to port 20, connect to client
                            // (Error handling simplified, exits child on failure)
                            if ((data_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { perror("child socket"); close(file_fd); exit(1); }
                            memset(&data_conn_addr, 0, sizeof(data_conn_addr));
                            data_conn_addr.sin_family = AF_INET;
                            data_conn_addr.sin_addr.s_addr = htonl(INADDR_ANY);
                            data_conn_addr.sin_port = htons(DATA_PORT);
                            int optval = 1;
                            setsockopt(data_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
                            if (bind(data_sock, (struct sockaddr *)&data_conn_addr, sizeof(data_conn_addr)) < 0) { perror("child bind"); close(file_fd); close(data_sock); exit(1); }
                            memset(&client_data_addr, 0, sizeof(client_data_addr));
                            client_data_addr.sin_family = AF_INET;
                            client_data_addr.sin_port = htons(client->data_port);
                            if (inet_pton(AF_INET, client->data_ip, &client_data_addr.sin_addr) <= 0) { perror("child inet_pton"); close(file_fd); close(data_sock); exit(1); }
                            printf("CHILD: Connecting to %s:%d from port %d for RETR\n", client->data_ip, client->data_port, DATA_PORT);
                            if (connect(data_sock, (struct sockaddr *)&client_data_addr, sizeof(client_data_addr)) < 0) { perror("child connect"); close(file_fd); close(data_sock); exit(1); }

                            printf("CHILD: Data connection established. Sending file: %s\n", filename);

                            // Read from file and write to data socket
                            while ((bytes_read = read(file_fd, data_buffer, sizeof(data_buffer))) > 0) {
                                if (send(data_sock, data_buffer, bytes_read, 0) < 0) {
                                    perror("child send failed");
                                    close(file_fd);
                                    close(data_sock);
                                    exit(EXIT_FAILURE); // Exit child with error status
                                }
                            }

                            if (bytes_read < 0) {
                                perror("child read file failed");
                                close(file_fd);
                                close(data_sock);
                                exit(EXIT_FAILURE); // Exit child with error status
                            }

                            // Finished sending file
                            printf("CHILD: Finished sending file. Closing data connection.\n");
                            close(file_fd);   // Close file
                            close(data_sock); // Close data socket (signals EOF to client)
                            exit(EXIT_SUCCESS); // Exit child successfully

                        } else {
                            // --- Parent Process --- 
                             printf("PARENT: Forked child %d for RETR request from client [%d]\n", pid, client->fd);
                            close(file_fd); // Close file descriptor in parent
                            client->child_pid = pid; // Store child PID
                            client->port_cmd_received = 0; // Consume the PORT command flag
                            // Parent continues in select loop...
                        }
                    }
                }
            }
        }
        // --- Add STOR Handler --- 
        else if (strcasecmp(trimmed_cmd, "STOR") == 0) {
             if (!client->port_cmd_received) {
                send_reply(client->fd, "503 Bad sequence of commands (PORT required before STOR).\r\n");
            } else if (strlen(trimmed_arg) == 0) {
                send_reply(client->fd, "501 Syntax error in parameters or arguments (Missing filename).\r\n");
            } else {
                char *target_filename = trimmed_arg;
                char temp_filename[PATH_MAX];
                // Create a temporary filename (simple .tmp suffix)
                snprintf(temp_filename, sizeof(temp_filename), "%s.tmp", target_filename);

                // Try opening the temporary file for writing
                // O_EXCL ensures we don't overwrite an existing .tmp file accidentally
                int temp_fd = open(temp_filename, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, 0644);
                if (temp_fd < 0) {
                    perror("open failed for STOR temporary file");
                    if (errno == EEXIST) {
                         send_reply(client->fd, "451 Requested action aborted: Temporary file exists (transfer already in progress?).\r\n");
                    } else {
                         send_reply(client->fd, "553 Requested action not taken (Cannot create temporary file).\r\n");
                    }
                     client->port_cmd_received = 0; // Reset flag
                } else {
                     // Temp file opened successfully, proceed
                     send_reply(client->fd, "150 Ok to send data.\r\n");

                     pid_t pid = fork();
                     if (pid < 0) {
                        perror("fork failed for STOR");
                        send_reply(client->fd, "451 Requested action aborted: local error in processing (fork failed).\r\n");
                        close(temp_fd); // Close temp file in parent
                        remove(temp_filename); // Clean up temp file
                        client->port_cmd_received = 0;
                    } else if (pid == 0) {
                        // --- Child Process --- 
                        int data_sock = -1;
                        struct sockaddr_in data_conn_addr, client_data_addr;
                        ssize_t bytes_read;
                        char data_buffer[BUFFER_SIZE];
                        int success = 1; // Assume success initially

                        // Create data socket, bind, connect (similar to RETR/LIST)
                        if ((data_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { perror("child socket"); close(temp_fd); remove(temp_filename); exit(1); }
                        memset(&data_conn_addr, 0, sizeof(data_conn_addr));
                        data_conn_addr.sin_family = AF_INET;
                        data_conn_addr.sin_addr.s_addr = htonl(INADDR_ANY);
                        data_conn_addr.sin_port = htons(DATA_PORT);
                        int optval = 1;
                        setsockopt(data_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
                        if (bind(data_sock, (struct sockaddr *)&data_conn_addr, sizeof(data_conn_addr)) < 0) { perror("child bind"); close(temp_fd); remove(temp_filename); close(data_sock); exit(1); }
                        memset(&client_data_addr, 0, sizeof(client_data_addr));
                        client_data_addr.sin_family = AF_INET;
                        client_data_addr.sin_port = htons(client->data_port);
                        if (inet_pton(AF_INET, client->data_ip, &client_data_addr.sin_addr) <= 0) { perror("child inet_pton"); close(temp_fd); remove(temp_filename); close(data_sock); exit(1); }
                        printf("CHILD: Connecting to %s:%d from port %d for STOR\n", client->data_ip, client->data_port, DATA_PORT);
                        if (connect(data_sock, (struct sockaddr *)&client_data_addr, sizeof(client_data_addr)) < 0) { perror("child connect"); close(temp_fd); remove(temp_filename); close(data_sock); exit(1); }

                        printf("CHILD: Data connection established. Receiving file to %s\n", temp_filename);

                        // Read from data socket and write to temp file
                        while ((bytes_read = read(data_sock, data_buffer, sizeof(data_buffer))) > 0) {
                            if (write(temp_fd, data_buffer, bytes_read) < 0) {
                                perror("child write temp file failed");
                                success = 0;
                                break;
                            }
                        }

                        if (bytes_read < 0) {
                             perror("child read data socket failed");
                             success = 0;
                        }

                        // Finished receiving data
                        printf("CHILD: Finished receiving data. Closing data connection.\n");
                        close(temp_fd);   // Close temp file
                        close(data_sock); // Close data socket

                        if (success) {
                            // Rename temp file to target filename
                            printf("CHILD: Renaming %s to %s\n", temp_filename, target_filename);
                            if (rename(temp_filename, target_filename) < 0) {
                                perror("child rename failed");
                                remove(temp_filename); // Clean up if rename failed
                                exit(EXIT_FAILURE); // Exit with failure status
                            } else {
                                 exit(EXIT_SUCCESS); // Exit successfully after rename
                            }
                        } else {
                            // Transfer failed, clean up temp file and exit with error
                            printf("CHILD: Transfer failed. Removing temporary file %s\n", temp_filename);
                            remove(temp_filename);
                            exit(EXIT_FAILURE);
                        }

                    } else {
                        // --- Parent Process --- 
                        printf("PARENT: Forked child %d for STOR request to %s (temp: %s) from client [%d]\n", 
                               pid, target_filename, temp_filename, client->fd);
                        close(temp_fd); // Close temp file descriptor in parent
                        client->child_pid = pid; // Store child PID
                        client->port_cmd_received = 0; // Consume the PORT command flag
                         // Parent continues in select loop...
                    }
                }
            }
        }
        // --- Add other authenticated command handlers --- 
        else if (strcasecmp(trimmed_cmd, "!CWD") == 0) {
            if (chdir(trimmed_arg) == 0) {
                printf("Changed local directory to %s\n", trimmed_arg);
            } else {
                perror("Local CWD failed");
            }
        }
        else if (strcasecmp(trimmed_cmd, "!pwd") == 0) {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != NULL) {
                printf("Local current directory: %s\n", cwd);
            } else {
                perror("getcwd failed");
            }
        }
        else {
            send_reply(client->fd, "502 Command not implemented.\r\n");
        }

    } else if (valread == 0) {
        // Client disconnected gracefully
        printf("Client [%d] disconnected.\n", client->fd);
        if (client->child_pid != -1) {
             printf("Client [%d] disconnected during data transfer. Killing child %d.\n", client->fd, client->child_pid);
             kill(client->child_pid, SIGKILL); // Force kill child
             waitpid(client->child_pid, NULL, 0); // Reap the killed child
        }
        close(client->fd);
        client->fd = -1; // Mark slot as free
    } else {
        // Error reading from socket
        perror("read failed");
        fprintf(stderr, "Error reading from client [%d]. Closing connection.\n", client->fd);
        if (client->child_pid != -1) {
             printf("Error reading from client [%d] during data transfer. Killing child %d.\n", client->fd, client->child_pid);
             kill(client->child_pid, SIGKILL);
             waitpid(client->child_pid, NULL, 0);
         }
        close(client->fd);
        client->fd = -1; // Mark slot as free
    }
}

// Function to check for and handle terminated child processes
void handle_child_termination(client_state_t clients[], int max_clients) {
    int status;
    pid_t pid;

    // Check for any terminated child without blocking
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        printf("PARENT: Child process %d terminated.\n", pid);
        // Find which client this child belonged to
        int client_index = -1;
        for (int i = 0; i < max_clients; ++i) {
            if (clients[i].child_pid == pid) {
                client_index = i;
                break;
            }
        }

        if (client_index != -1) {
            client_state_t *client = &clients[client_index];
            printf("PARENT: Child %d belonged to client [%d].\n", pid, client->fd);
            client->child_pid = -1; // Reset child PID for this client

            // Check child exit status (optional, but good for debugging)
            if (WIFEXITED(status)) {
                 printf("PARENT: Child %d exited normally with status %d.\n", pid, WEXITSTATUS(status));
                 // If exited normally (status 0 usually means success), send 226
                 if (WEXITSTATUS(status) == 0) {
                    send_reply(client->fd, "226 Transfer complete.\r\n");
                 } else {
                     send_reply(client->fd, "451 Requested action aborted: local error in processing (Transfer failed).\r\n");
                 }
            } else if (WIFSIGNALED(status)) {
                printf("PARENT: Child %d killed by signal %d.\n", pid, WTERMSIG(status));
                send_reply(client->fd, "451 Requested action aborted: local error in processing (Transfer interrupted).\r\n");
            } else {
                printf("PARENT: Child %d terminated abnormally.\n", pid);
                send_reply(client->fd, "451 Requested action aborted: local error in processing (Unknown transfer error).\r\n");
            }
            // Reset port command received flag *after* transfer attempt is fully complete
            // client->port_cmd_received = 0; // We reset this in the parent after fork now
        } else {
            printf("PARENT: Reaped child %d, but couldn't find corresponding client state.\n", pid);
        }
    }
    
    // Handle error from waitpid, except for ECHILD (no children)
    if (pid < 0 && errno != ECHILD) {
        perror("waitpid error in handle_child_termination");
    }
}

// Function to load users from a file
int load_users(const char* filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening user file");
        return -1;
    }

    char line[MAX_USER_LEN + MAX_PASS_LEN + 2]; 
    num_loaded_users = 0;

    while (fgets(line, sizeof(line), file) != NULL && num_loaded_users < MAX_USERS) {
        // Remove trailing newline/carriage return
        line[strcspn(line, "\r\n")] = 0;

        // Find the first comma to separate username and password
        char *comma = strchr(line, ',');
        if (comma == NULL || comma == line || *(comma + 1) == '\0') {
            // Skip lines without a comma, empty username, or empty password
            fprintf(stderr, "Skipping malformed line in user file (no comma or empty field): %s\n", line);
            continue;
        }

        // Null-terminate the username part
        *comma = '\0';
        char *username = line;
        char *password = comma + 1;

        // Trim leading/trailing whitespace from username and password (optional but robust)
        // NOTE: Need trim_whitespace function if we want this.
        // For now, assume no leading/trailing whitespace around comma.

        // Copy to our structure (check lengths)
        if (strlen(username) >= MAX_USER_LEN || strlen(password) >= MAX_PASS_LEN) {
            fprintf(stderr, "Skipping line due to length exceeded: %s,...\n", username);
            continue;
        }
        strncpy(loaded_users[num_loaded_users].username, username, MAX_USER_LEN - 1);
        loaded_users[num_loaded_users].username[MAX_USER_LEN - 1] = '\0';
        strncpy(loaded_users[num_loaded_users].password, password, MAX_PASS_LEN - 1);
        loaded_users[num_loaded_users].password[MAX_PASS_LEN - 1] = '\0';

        num_loaded_users++;
    }

    fclose(file);

    if (num_loaded_users >= MAX_USERS) {
        fprintf(stderr, "Warning: Maximum number of users (%d) reached. Some users may not have been loaded.\n", MAX_USERS);
    }

    return num_loaded_users;
} 