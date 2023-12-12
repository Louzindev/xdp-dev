#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/signal.h>
#include <wait.h>
#include <errno.h>
#include <string.h>

#define PORT "8080"
void sighandler(int s)
{
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
    errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(void)
{
    int sockfd, newfd;
    struct addrinfo hints, *serverinfo, *p;
    struct sockaddr_storage their_addr;

    struct sigaction sa;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int res = getaddrinfo(NULL, PORT, &hints, &serverinfo);
    if (res != 0)
    {
        printf("getaddrinfo error: %s", gai_strerror(res));
        exit(1);
    }

    for (p = serverinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }
        int yes = 1;

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("Reuse addr");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("bind");
            continue;
        }
        break;
    }
    freeaddrinfo(serverinfo);

    if (p == NULL)
    {
        perror("failure.");
        exit(1);
    }

    if (listen(sockfd, 10) == -1)
    {
        perror("listen error");
        exit(1);
    }

    sa.sa_handler = sighandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("Sigaction");
        exit(1);
    }

    while (1)
    {
        socklen_t sin_size = sizeof their_addr;
        newfd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (newfd == -1)
        {
            continue;
        }

        if (!fork())
        {
            char s[INET6_ADDRSTRLEN];
            inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
            printf("New connection from %s\n", s);
            close(sockfd);
            if (send(newfd, "CLI:", 15, 0) == -1)
            {
                perror("Send");
                close(newfd);
                exit(1);
            }
            char buffer[1024];
            while (1)
            {
                int bytes_received = recv(newfd, buffer, sizeof buffer, 0);
                if (bytes_received < 0)
                {
                    perror("Receive");
                    close(newfd);
                    exit(1);
                }
                buffer[bytes_received] = '\0';
                printf("%s: %s\n", s, buffer);
                const char *msg = "buffer received\nCLI:";
                if (send(newfd, msg, strlen(msg), 0) == -1)
                {
                    perror("Send");
                    close(newfd);
                    exit(1);
                }
            }
        }
        close(newfd);
    }
    return 1;
}