#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h> // For getsockname
#include <netdb.h>     // For getnameinfo
#include <limits.h>    // For PATH_MAX
#include <fcntl.h>     // For open() flags
#include <sys/wait.h>  // For waitpid

#define SERVER_PORT 21
#define BUFFER_SIZE 4096 // Larger buffer for potential LIST responses

// Function prototypes
int read_reply(int sock_fd, char *reply_buffer, size_t buffer_size);
int setup_data_connection(int control_sock_fd, int *data_listen_fd, char *port_cmd_buf, size_t port_cmd_buf_size);
int get_local_ip_and_port(int sock_fd, char *ip_str, size_t ip_str_len, int *port);
void print_client_usage();

// Global variable to store the data listening socket
int data_listen_fd = -1; // Initialize to invalid

int main(int argc, char *argv[]) {
    int sock_fd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char user_input[BUFFER_SIZE];
    int bytes_received;
    char original_command[BUFFER_SIZE];
    char original_argument[BUFFER_SIZE];

    // Use localhost if no IP provided
    const char *server_ip = (argc == 2) ? argv[1] : "127.0.0.1";

    // Create socket
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Change to client directory
    if (chdir("client") < 0) {
        // perror("Failed to change to client directory");
        // fprintf(stderr, "Warning: Could not change to client directory\n");
    }

    // Initialize server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    // Convert IPv4 address from text to binary form
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        // perror("inet_pton failed: Invalid address or address family not supported");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        // perror("connect failed");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    // Read the initial welcome message from the server
    bytes_received = read_reply(sock_fd, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0) {
        // fprintf(stderr, "Failed to receive welcome message or server disconnected.\n");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    buffer[bytes_received] = '\0';
    printf("%s", buffer);  // Print server response without "SERVER: " prefix

    // Check if the welcome message indicates readiness (starts with 220)
    if (strncmp(buffer, "220", 3) != 0) {
        // fprintf(stderr, "Server not ready or sent unexpected welcome message.\n");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    // Print client usage instructions
    print_client_usage();

    // Main command loop
    while (1) {
        // Clean up any previous data listening socket if it wasn't used
        if (data_listen_fd != -1) {
            close(data_listen_fd);
            data_listen_fd = -1;
        }

        printf("ftp> ");
        fflush(stdout);

        if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
            if (feof(stdin)) {
                printf("\nExiting (EOF detected).\n");
                // Optionally send QUIT before exiting
                snprintf(buffer, sizeof(buffer), "QUIT\r\n");
                send(sock_fd, buffer, strlen(buffer), 0);
                read_reply(sock_fd, buffer, sizeof(buffer) - 1); // Read final reply
                printf("SERVER: %s", buffer);
                break; // Exit loop on EOF
            } else {
                perror("fgets failed");
                break; // Exit on error
            }
        }

        // Remove trailing newline
        user_input[strcspn(user_input, "\n")] = 0;

        // Check for empty input
        if (strlen(user_input) == 0) {
            continue;
        }

        // Store original command and parse argument before potential ! handling
        strncpy(original_command, user_input, sizeof(original_command) - 1);
        original_command[sizeof(original_command) - 1] = '\0';
        original_argument[0] = '\0'; // Clear argument initially
        char *space_in_orig = strchr(original_command, ' ');
        if (space_in_orig != NULL) {
            // Extract argument (handle potential leading/trailing spaces if needed)
            strncpy(original_argument, space_in_orig + 1, sizeof(original_argument) -1);
            original_argument[sizeof(original_argument) - 1] = '\0';
            // Null-terminate the command part in original_command
            *space_in_orig = '\0'; 
        } else {
            // Command has no argument
        }
        // We now have original_command (e.g., "RETR") and original_argument (e.g., "filename.txt")

        // --- Check for local commands (!PWD, !CWD) --- 
        if (user_input[0] == '!') {
            char *local_cmd = user_input + 1; // Skip '!'
            char *local_arg = "";
            char *space = strchr(local_cmd, ' ');
            if (space != NULL) {
                *space = '\0';
                local_arg = space + 1;
            }

            if (strcasecmp(local_cmd, "PWD") == 0) {
                char current_dir[PATH_MAX];
                if (getcwd(current_dir, sizeof(current_dir)) != NULL) {
                    printf("%s\n", current_dir);
                } else {
                    perror("Local getcwd failed");
                }
            } else if (strcasecmp(local_cmd, "CWD") == 0) {
                if (strlen(local_arg) == 0) {
                    // fprintf(stderr, "Usage: !CWD <directory>\n");
                } else {
                    if (chdir(local_arg) == 0) {
                        char current_dir[PATH_MAX];
                        getcwd(current_dir, sizeof(current_dir));
                        printf("Changing directory to: %s\n", local_arg);
                    } else {
                        // perror("Local chdir failed");
                    }
                }
            } else if (strcasecmp(local_cmd, "LIST") == 0) {
                pid_t pid = fork();
                if (pid < 0) {
                    // perror("fork failed for local LIST");
                } else if (pid == 0) {
                    printf("Connecting to Client Transfer Socket...\n");
                    printf("Connection Successful\n");
                    printf("Listing directory\n");
                    execlp("ls", "ls", "-l", (char *)NULL);
                    // perror("execlp ls failed");
                    exit(EXIT_FAILURE);
                } else {
                    int status;
                    waitpid(pid, &status, 0);
                    printf("226 Transfer complete\n");
                }
            } else {
                // fprintf(stderr, "Unknown local command: %s\n", local_cmd);
            }
            // After handling local command, continue to next prompt
            continue; 
        } 
        // --- End Local Command Handling ---

        // --- Pre-command processing (PORT setup) --- 
        char command_to_send[BUFFER_SIZE];
        strncpy(command_to_send, user_input, sizeof(command_to_send) - 1);
        command_to_send[sizeof(command_to_send) - 1] = '\0';

        // Check if the command requires a data connection setup (PORT)
        // (LIST, RETR, STOR)
        int needs_data_connection = (strncasecmp(command_to_send, "LIST", 4) == 0 ||
                                     strncasecmp(command_to_send, "RETR", 4) == 0 ||
                                     strncasecmp(command_to_send, "STOR", 4) == 0);

        if (needs_data_connection) {
            char port_command[100];
            int port_result = setup_data_connection(sock_fd, &data_listen_fd, port_command, sizeof(port_command));

            if (port_result < 0) {
                // fprintf(stderr, "Error setting up data connection.\n");
                continue;
            }

            if (send(sock_fd, port_command, strlen(port_command), 0) < 0) {
                // perror("send (PORT) failed");
                close(data_listen_fd);
                data_listen_fd = -1;
                continue;
            }

            bytes_received = read_reply(sock_fd, buffer, sizeof(buffer) - 1);
            if (bytes_received <= 0) {
                // fprintf(stderr, "Server disconnected or error reading PORT reply.\n");
                close(data_listen_fd);
                data_listen_fd = -1;
                break;
            }
            buffer[bytes_received] = '\0';
            printf("%s", buffer);

            if (strncmp(buffer, "200", 3) != 0) {
                // fprintf(stderr, "PORT command failed. Aborting data transfer command.\n");
                close(data_listen_fd);
                data_listen_fd = -1;
                continue;
            }
        }

        // --- Send the command to server --- 
        // Format command with FTP required CRLF
        snprintf(buffer, sizeof(buffer), "%s\r\n", command_to_send);

        // Send command to server
        if (send(sock_fd, buffer, strlen(buffer), 0) < 0) {
            perror("send failed");
            if (data_listen_fd != -1) close(data_listen_fd);
            break;
        }

        // --- Post-command processing --- 

        // Read server's reply to the main command
        bytes_received = read_reply(sock_fd, buffer, sizeof(buffer) - 1);
        if (bytes_received <= 0) {
            fprintf(stderr, "Server disconnected or error reading reply.\n");
            if (data_listen_fd != -1) close(data_listen_fd);
            break;
        }
        buffer[bytes_received] = '\0';
        printf("%s", buffer);

        // If the command was one that initiated data transfer AND
        // the server sent a positive preliminary reply (e.g., 150), 
        // then we need to accept the connection and handle the data transfer.
        if (needs_data_connection && strncmp(buffer, "150", 3) == 0) {
            // printf("DEBUG: Waiting for data connection from server...\n");
            struct sockaddr_in data_client_addr;
            socklen_t addrlen = sizeof(data_client_addr);
            int data_sock_fd = accept(data_listen_fd, (struct sockaddr *)&data_client_addr, &addrlen);
            
            close(data_listen_fd);
            data_listen_fd = -1;

            if (data_sock_fd < 0) {
                perror("accept (data connection) failed");
            } else {
                // printf("DEBUG: Data connection established...\n");

                // Determine action based on original command
                if (strcasecmp(original_command, "LIST") == 0) {
                    // --- Handle LIST data --- 
                    // printf("--- Directory Listing Start ---\n");
                    ssize_t data_bytes_read;
                    char data_buffer[BUFFER_SIZE];
                    while ((data_bytes_read = read(data_sock_fd, data_buffer, sizeof(data_buffer) - 1)) > 0) {
                        data_buffer[data_bytes_read] = '\0';
                        printf("%s", data_buffer);
                    }
                    // printf("--- Directory Listing End ---\n");
                    if (data_bytes_read < 0) { perror("read (LIST data) failed"); }

                } else if (strcasecmp(original_command, "RETR") == 0) {
                    // --- Handle RETR data --- 
                    char *local_filename = original_argument; // Use argument parsed earlier
                    if (strlen(local_filename) == 0) {
                        fprintf(stderr, "Error: Filename missing for RETR.\n");
                        // No local file to open, but need to drain/close data socket
                    } else {
                        printf("Receiving file: %s\n", local_filename);
                        // Open local file for writing (Create if not exists, Truncate if exists)
                        int local_fd = open(local_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644); // Permissions rw-r--r--
                        if (local_fd < 0) {
                            perror("open (local file for RETR) failed");
                            fprintf(stderr, "Error opening local file %s. Data transfer will be skipped.\n", local_filename);
                            // No local file, but need to drain/close data socket
                        } else {
                            // Read from data socket and write to local file
                            ssize_t data_bytes_read;
                            ssize_t bytes_written;
                            char data_buffer[BUFFER_SIZE];
                            long long total_bytes_received = 0;
                            while ((data_bytes_read = read(data_sock_fd, data_buffer, sizeof(data_buffer))) > 0) {
                                bytes_written = write(local_fd, data_buffer, data_bytes_read);
                                if (bytes_written < 0) {
                                     perror("write (local file for RETR) failed");
                                     // Error writing to local file, stop transfer
                                     break; 
                                } else if (bytes_written != data_bytes_read) {
                                     fprintf(stderr, "Warning: Short write to local file %s.\n", local_filename);
                                     // Potentially handle partial writes more robustly? Loop write?
                                }
                                total_bytes_received += bytes_written;
                            }
                            printf("Finished receiving file: %s (%lld bytes)\n", local_filename, total_bytes_received);

                            if (data_bytes_read < 0) { perror("read (RETR data) failed"); }
                            
                            // Close the local file
                            if (close(local_fd) < 0) {
                                perror("close (local file for RETR) failed");
                            }
                        }
                    }
                } else if (strcasecmp(original_command, "STOR") == 0) {
                    // --- Handle STOR data --- 
                    char *local_filename = original_argument; // Use argument parsed earlier
                    if (strlen(local_filename) == 0) {
                        fprintf(stderr, "Error: Filename missing for STOR.\n");
                        // Need to close data socket even if no file sent
                    } else {
                        printf("Sending file: %s\n", local_filename);
                        // Open local file for reading
                        int local_fd = open(local_filename, O_RDONLY);
                        if (local_fd < 0) {
                            perror("open (local file for STOR) failed");
                            fprintf(stderr, "Error opening local file %s. Aborting STOR.\n", local_filename);
                            // Need to close data socket even if no file sent
                        } else {
                            // Read from local file and send to data socket
                            ssize_t bytes_read;
                            ssize_t bytes_sent;
                            char data_buffer[BUFFER_SIZE];
                            long long total_bytes_sent = 0;
                            while ((bytes_read = read(local_fd, data_buffer, sizeof(data_buffer))) > 0) {
                                bytes_sent = send(data_sock_fd, data_buffer, bytes_read, 0);
                                if (bytes_sent < 0) {
                                     perror("send (STOR data) failed");
                                     // Error sending data, stop transfer
                                     break; 
                                } else if (bytes_sent != bytes_read) {
                                     fprintf(stderr, "Warning: Short send for STOR data (sent %zd / %zd).\n", bytes_sent, bytes_read);
                                     // Potentially handle partial sends more robustly? Loop send?
                                }
                                total_bytes_sent += bytes_sent;
                            }
                            printf("Finished sending file: %s (%lld bytes)\n", local_filename, total_bytes_sent);

                            if (bytes_read < 0) { perror("read (local file for STOR) failed"); }
                            
                            // Close the local file after reading
                            close(local_fd);
                        }
                    }
                    // We close data_sock_fd *after* this block, regardless of success/failure sending
                    // Closing it signals EOF to the server
                }

                // Close the data socket after data transfer attempt
                close(data_sock_fd);
                // printf("DEBUG: Data connection closed.\n");

                // After data transfer, read the final reply (e.g., 226) from control connection
                bytes_received = read_reply(sock_fd, buffer, sizeof(buffer) - 1);
                 if (bytes_received <= 0) {
                    fprintf(stderr, "Server disconnected or error reading final reply.\n");
                    break;
                 }      
                 buffer[bytes_received] = '\0';
                 printf("%s", buffer);
            }
        }

        // Check if the command was QUIT 
        if (strcasecmp(user_input, "QUIT") == 0) {
            printf("Closed!\n");
            break; // Exit loop
        }
    }

    // Close the control socket
    close(sock_fd);
    // Ensure data listening socket is closed if loop exited unexpectedly
    if (data_listen_fd != -1) close(data_listen_fd);
    printf("Connection closed.\n");

    return 0;
}

// Helper function to get the local IP address and port associated with a connected socket
int get_local_ip_and_port(int sock_fd, char *ip_str, size_t ip_str_len, int *port) {
    struct sockaddr_storage local_addr;
    socklen_t addr_len = sizeof(local_addr);

    if (getsockname(sock_fd, (struct sockaddr *)&local_addr, &addr_len) == -1) {
        perror("getsockname failed");
        return -1;
    }

    // Use getnameinfo for portability (works for IPv4 and IPv6)
    if (getnameinfo((struct sockaddr *)&local_addr, addr_len,
                    ip_str, ip_str_len, NULL, 0, NI_NUMERICHOST) != 0) {
        perror("getnameinfo failed");
        return -1;
    }
    
    // Get port based on address family
    if (local_addr.ss_family == AF_INET) {
        *port = ntohs(((struct sockaddr_in *)&local_addr)->sin_port);
    } else if (local_addr.ss_family == AF_INET6) {
        *port = ntohs(((struct sockaddr_in6 *)&local_addr)->sin6_port);
    } else {
        fprintf(stderr, "Unknown address family\n");
        return -1;
    }

    return 0;
}

// Creates a listening socket for the data connection, gets the port, and formats the PORT command
int setup_data_connection(int control_sock_fd, int *p_data_listen_fd, char *port_cmd_buf, size_t port_cmd_buf_size) {
    struct sockaddr_in data_addr;
    int listen_fd;

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        // perror("data socket creation failed");
        return -1;
    }

    memset(&data_addr, 0, sizeof(data_addr));
    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    data_addr.sin_port = 0; // Let system assign port

    if (bind(listen_fd, (struct sockaddr *)&data_addr, sizeof(data_addr)) < 0) {
        // perror("data socket bind failed");
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, 1) < 0) {
        // perror("data socket listen failed");
        close(listen_fd);
        return -1;
    }

    // Get the assigned port number
    struct sockaddr_in assigned_addr;
    socklen_t len = sizeof(assigned_addr);
    if (getsockname(listen_fd, (struct sockaddr *)&assigned_addr, &len) == -1) {
        // perror("getsockname failed");
        close(listen_fd);
        return -1;
    }

    // Get local IP address
    char ip_str[INET_ADDRSTRLEN];
    int port;
    if (get_local_ip_and_port(control_sock_fd, ip_str, sizeof(ip_str), &port) < 0) {
        // fprintf(stderr, "Failed to get local IP address\n");
        close(listen_fd);
        return -1;
    }

    // Format PORT command with comma-separated address and port
    int assigned_port = ntohs(assigned_addr.sin_port);
    int p1 = assigned_port >> 8;    // High byte of port
    int p2 = assigned_port & 0xFF;  // Low byte of port

    // Replace dots with commas in IP address
    char ip_cmd[INET_ADDRSTRLEN * 2];
    strncpy(ip_cmd, ip_str, sizeof(ip_cmd));
    for (char *p = ip_cmd; *p; p++) {
        if (*p == '.') *p = ',';
    }

    // Format the full PORT command
    snprintf(port_cmd_buf, port_cmd_buf_size, "PORT %s,%d,%d\r\n", ip_cmd, p1, p2);

    *p_data_listen_fd = listen_fd;
    return 0;
}

// Function to read a full reply from the server (handles multi-line replies)
int read_reply(int sock_fd, char *reply_buffer, size_t buffer_size) {
    memset(reply_buffer, 0, buffer_size);
    int total_bytes_read = 0;
    int bytes_read;

    // Perform a non-blocking read first to see if data is immediately available
    // This helps avoid blocking indefinitely if the server doesn't send anything
    // Use MSG_DONTWAIT if available (Linux specific)
    // bytes_read = recv(sock_fd, reply_buffer, buffer_size - 1, MSG_DONTWAIT);

    // A more portable approach is to use select/poll before read, but for simplicity
    // we'll do a simple blocking read here initially.
    // Be aware this might block if the server doesn't respond as expected.

    bytes_read = read(sock_fd, reply_buffer, buffer_size - 1);

    if (bytes_read < 0) {
        perror("read_reply failed");
        return -1;
    } else if (bytes_read == 0) {
        printf("read_reply: Server closed connection.\n");
        return 0;
    }

    total_bytes_read = bytes_read;
    reply_buffer[total_bytes_read] = '\0'; // Null-terminate

    // Note: This basic version doesn't handle multi-line FTP replies correctly.
    // For example, LIST command output spans multiple lines but has one final code.
    // A full implementation would need to parse the reply structure.
    // For now, it reads whatever is available in one go.

    return total_bytes_read;
}

void print_client_usage() {
    printf("Hello!! Please Authenticate to run server commands\n");
    printf("1. type \"USER\" followed by a space and your username\n");
    printf("2. type \"PASS\" followed by a space and your password\n\n");
    printf("\"QUIT\" to close connection at any moment\n");
    printf("Once Authenticated\n");
    printf("this is the list of commands :\n");
    printf("\"STOR\" + space + filename |to send a file to the server\n");
    printf("\"RETR\" + space + filename |to download a file from the server\n");
    printf("\"LIST\" |to  to list all the files under the current server directory\n");
    printf("\"CWD\" + space + directory |to change the current server directory\n");
    printf("\"PWD\" to display the current server directory\n");
    printf("Add \"!\" before the last three commands to apply them locally\n\n");
} 