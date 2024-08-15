#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>


#define MEM_SIZE 1024
#define MAX_SIZE 64
#define LENGTH 2048

volatile sig_atomic_t flag = 0;
int sockfd = 0;

char driverMessage[MEM_SIZE];
char username[MAX_SIZE];
char password[MAX_SIZE];
int fd;

int comparePass(const char ina[MAX_SIZE], const char inb[MAX_SIZE])
{
    if (strcmp(ina, inb) == 0)
        return 0;
    return 1;
}

//Hàm này đọc dữ liệu từ file data.txt để tìm kiếm một tài khoản dựa trên tên người dùng và mật khẩu đã mã hóa
int findInFile(const char uname[MAX_SIZE], const char hashPass[MEM_SIZE])
{
    char tmpUsername[MAX_SIZE], tmpPassHashed[MAX_SIZE], tempLine[MAX_SIZE];
    FILE *fPtr;
    int flag = 1; // Initialize to 1 (not found)
    char line[MEM_SIZE];
    fPtr = fopen("/home/minhquang/code/Nhom12/Socket/chatSocket-AES/data.txt", "r");
    if (fPtr == NULL)
    {
        printf("\nUnable to open file.\n");
        exit(0);
    }

    while (fgets(line, sizeof(line), fPtr))
    {
        sscanf(line, "%s %s", tmpUsername, tmpPassHashed);
        if (strcmp(tmpUsername, uname) == 0)
        {
            flag = comparePass(hashPass, tmpPassHashed);
            break;
        }
    }

    fclose(fPtr);
    return flag;
}

void writeInfo(const char username[MAX_SIZE], const char password[MEM_SIZE])
{
    char temp[MEM_SIZE];
    sprintf(temp, "%s %s\n", username, password);
    FILE *fPtr;

    fPtr = fopen("/home/minhquang/code/Nhom12/Socket/chatSocket-AES/data.txt", "a");
    if (fPtr == NULL)
    {
        printf("\nUnable to open file.\n");
        exit(0);
    }

    fputs(temp, fPtr);
    fclose(fPtr);
}

//gửi và nhận thông điệp từ character driver thông qua giao tiếp file. Nó gửi yêu cầu (mode) và giá trị (value) tới character driver và nhận phản hồi từ nó.

void handlerDriver(int fd, int mode, char *value)
{
    char buffer[MEM_SIZE];
    memset(driverMessage, 0, sizeof(driverMessage));
    sprintf(buffer, "opt:%d\nvalue:%s\n", mode, crypto_cipher_encrypt_onevalue);
    write(fd, buffer, strlen(buffer));
    memset(buffer, 0, sizeof(buffer));
    read(fd, buffer, sizeof(buffer));
    strcpy(driverMessage, buffer);
}

void str_overwrite_stdout()
{
    printf("%s", "----------> ");
    fflush(stdout);
}

void str_trim_lf(char *arr, int length)
{
    int i;
    for (i = 0; i < length; i++)
    {
        if (arr[i] == '\n')
        {
            arr[i] = '\0';
            break;
        }
    }
}

//gọi khi người dùng nhấn Ctrl+C. Nó đặt cờ flag thành 1 để thoát khỏi vòng lặp chính.
void catch_ctrl_c_and_exit(int sig)
{
    flag = 1;
}

//Hàm này là một luồng (thread) xử lý việc gửi tin nhắn từ người dùng tới máy chủ qua socket. Nó đọc tin nhắn từ người dùng và gửi nó tới máy chủ.
void *send_msg_handler(void *arg)
{
    char message[LENGTH] = {};
    char buffer[LENGTH + 32] = {};

    while (1)
    {
        str_overwrite_stdout();
        fgets(message, LENGTH, stdin);
        str_trim_lf(message, LENGTH);
        handlerDriver(fd, 2, message);

        if (strcmp(message, "exit") == 0)
        {
            break;
        }
        else
        {
            sprintf(buffer, "Sender:%s\nMessage:%s\n", username, driverMessage);
            send(sockfd, buffer, strlen(buffer), 0);
        }

        memset(message, 0, sizeof(message));
        memset(driverMessage, 0, sizeof(driverMessage));
        memset(buffer, 0, sizeof(buffer));
    }
    catch_ctrl_c_and_exit(2);
    return NULL;
}

// Hàm này là một luồng (thread) xử lý việc nhận tin nhắn từ máy chủ qua socket và hiển thị chúng cho người dùng.
void *recv_msg_handler(void *arg)
{
    char cipherText[LENGTH] = {};
    char message[MAX_SIZE];
    char sender[MAX_SIZE];
    while (1)
    {
        int receive = recv(sockfd, cipherText, LENGTH, 0);
        if (receive > 0)
        {
            sscanf(cipherText, "Sender:%s\nMessage:%s\n", sender, message);
            handlerDriver(fd, 3, message);
            printf("%s: ", sender);
            printf("%s\n", driverMessage);
            str_overwrite_stdout();
        }
        else if (receive == 0)
        {
            break;
        }

        memset(sender, 0, sizeof(sender));
        memset(cipherText, 0, sizeof(cipherText));
        memset(message, 0, sizeof(message));
        memset(driverMessage, 0, sizeof(driverMessage));
    }
    return NULL;
}

void handleSocket(const char *username)
{
    char *ip = "127.0.0.1";
    int port = 5000;
    struct sockaddr_in server_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_port = htons(port);
    int err = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (err == -1)
    {
        printf("ERROR: Can't Connect\n");
        exit(EXIT_FAILURE);
    }
    send(sockfd, username, strlen(username), 0);
    printf("--------------- WELCOME --------------\n");
    pthread_t send_msg_thread;
    if (pthread_create(&send_msg_thread, NULL, send_msg_handler, NULL) != 0)
    {
        printf("ERROR: PTHREAD\n");
        exit(EXIT_FAILURE);
    }
    pthread_t recv_msg_thread;
    if (pthread_create(&recv_msg_thread, NULL, recv_msg_handler, NULL) != 0)
    {
        printf("ERROR: PTHREAD\n");
        exit(EXIT_FAILURE);
    }
    while (1)
    {
        if (flag)
        {
            printf("\nBye\n");
            break;
        }
    }
    close(sockfd);
}

int main()
{
    int auth; // lưu trạng thái xác thực sau khi  đăng nhập.
    char hashMode[MAX_SIZE];  // Mảng để lưu chế độ mã hóa (MD5, SHA1, SHA2).
    char cipherMode[MAX_SIZE]; //(AES, DES).
    char value[MEM_SIZE]; // Increase size to avoid overflow
    char option;

    printf("############### Character driver - Chat with Encryption ##############\n");
    fd = open("/dev/simple_driver", O_RDWR);
    if (fd < 0)
    {
        printf("Cannot open device file...\n");
        return 0;
    }

    while (1)
    {
    	printf("\n");
        printf("--------------------------- Nhap lua chon ----------------------------\n");
        printf("                  1. Them tai khoan                    \n");
        printf("                  2. Chat                           \n");
        printf("                  3. Exit                           \n");
        printf("----------------------------------------------------------------------\n");

        scanf(" %c", &option);
        getchar();
        printf("Lua chon cua ban: %c\n", option);

        switch (option)
        {
            case '1':
                //config ma hoa
                strcpy(hashMode, "MD5");
                strcpy(cipherMode, "AES");
                sprintf(value, "%s%s", hashMode, cipherMode);
                handlerDriver(fd, 0, value);         
                printf("%s \n", driverMessage);

                //xu ly them tai khoan
                printf("--- THEM TAI KHOAN  ---\n");
                printf(" > Nhap ten tai khoan: ");
                fgets(username, MAX_SIZE, stdin);
                username[strcspn(username, "\n")] = '\0';
                printf(" > Nhap mat khau: ");
                fgets(password, MAX_SIZE, stdin);
                password[strcspn(password, "\n")] = '\0';
                sprintf(value, "%s %s", username, password);
                handlerDriver(fd, 1, value);
                writeInfo(username, driverMessage);
                printf("---> THEM TAI KHOAN THANH CONG ");
                printf("\n");
                break;
            case '2':
                printf("--- DANG NHAP ---\n");
                printf(" > Ten tai khoan: ");
                fgets(username, MAX_SIZE, stdin);
                username[strcspn(username, "\n")] = '\0';
                printf(" >  Mat khau: ");
                fgets(password, MAX_SIZE, stdin);
                password[strcspn(password, "\n")] = '\0';
                sprintf(value, "%s %s", username, password);
                handlerDriver(fd, 1, value);
                auth = findInFile(username, driverMessage);   
                
                if (auth == 0)
                {
                    printf("---> DANG NHAP THANH CONG! ");
                    printf("\n");
                    handleSocket(username);
                }
                break;
            case '3':
                close(fd);
                exit(1);
                break;
            default:
                printf("Lua chon khong hop le! \n");
                break;
        }
    }
    return 0;
}

