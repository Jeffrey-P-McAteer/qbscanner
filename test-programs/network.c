#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    printf("Created socket: %d\n", sock);

    // We can simulate a server by moving to any unused directory and running
    //   python -m http.server
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8000);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    printf("Attempting to connect to 127.0.0.1:8000\n");
    
    // This will likely fail, but we'll see the socket operations
    int result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (result < 0) {
        printf("Connection failed (expected)\n");
    } else {
        printf("Connection successful\n");
        
        const char *msg = "GET / HTTP/1.0\r\n\r\n";
        send(sock, msg, strlen(msg), 0);
        
        char buf[1024];
        int bytes = recv(sock, buf, sizeof(buf)-1, 0);
        if (bytes > 0) {
            buf[bytes] = '\0';
            printf("Received: %s\n", buf);
        }
    }
    
    close(sock);
    printf("Socket closed\n");
    return 0;
}
