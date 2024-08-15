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

#define MAX_CLIENTS 100
#define BUFFER_SZ 2048
char driverMessage[BUFFER_SZ];
static _Atomic unsigned int cli_count = 0;
static int uid = 10;
int fd;
typedef struct
{
	struct sockaddr_in address;
	int sockfd;
	int uid;
	char name[32];
} client_t;

client_t *clients[MAX_CLIENTS];

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;


// gửi yêu cầu và nhận phản hồi từ character driver. Nó ghi dữ liệu yêu cầu (chế độ và giá trị) vào file descriptor (fd) và sau đó đọc phản hồi từ character driver vào biến driverMessage.
void handlerDriver(int fd, int mode, char *value)
{
	char buffer[BUFFER_SZ];
	memset(driverMessage, 0, strlen(driverMessage));
	sprintf(buffer, "opt:%d\nvalue:%s\n", mode, value);
	write(fd, buffer, strlen(buffer));
	memset(buffer, 0, sizeof(buffer));
	read(fd, buffer, sizeof(buffer));
	strcpy(driverMessage, buffer);
}
//sử dụng để ghi đè lên dòng dữ liệu được nhập từ người dùng
void str_overwrite_stdout()
{
	printf("\r%s", "> ");
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
// in địa chỉ IP của client từ cấu trúc sockaddr_in được truyền vào.
void print_client_addr(struct sockaddr_in addr)
{
	printf("%d.%d.%d.%d",
		  addr.sin_addr.s_addr & 0xff,
		  (addr.sin_addr.s_addr & 0xff00) >> 8,
		  (addr.sin_addr.s_addr & 0xff0000) >> 16,
		  (addr.sin_addr.s_addr & 0xff000000) >> 24);
}
// Dảm bảo rằng chỉ có một luồng có thể truy cập và sửa đổi dữ liệu của hàng đợi tại một thời điểm, ngăn chặn các xung đột hoặc sự không nhất quán trong dữ liệu.
void queue_add(client_t *cl)
{
	pthread_mutex_lock(&clients_mutex); // sử dụng để khóa mutex (clients_mutex) trước khi truy cập vào biến hoặc tài nguyên chia sẻ bởi nhiều luồng.

	for (int i = 0; i < MAX_CLIENTS; ++i)
	{
		if (!clients[i])
		{
			clients[i] = cl;
			break;
		}
	}

	pthread_mutex_unlock(&clients_mutex);
}

void queue_remove(int uid)
{
	pthread_mutex_lock(&clients_mutex);

	for (int i = 0; i < MAX_CLIENTS; ++i)
	{
		if (clients[i])
		{
			if (clients[i]->uid == uid)
			{
				clients[i] = NULL;
				break;
			}
		}
	}

	pthread_mutex_unlock(&clients_mutex);
}

void send_message(char *s, int uid)
{
	pthread_mutex_lock(&clients_mutex);

	for (int i = 0; i < MAX_CLIENTS; ++i)
	{
		if (clients[i])
		{
			if (clients[i]->uid != uid)
			{
				if (write(clients[i]->sockfd, s, strlen(s)) < 0)
				{
					perror("ERROR: write to descriptor failed");
					break;
				}
			}
		}
	}

	pthread_mutex_unlock(&clients_mutex);
}
//Hàm này nhận dữ liệu từ client, gửi tin nhắn cho các client khác và thực hiện các thao tác khi client rời khỏi cuộc trò chuyện.
// hàm lấy tên của client từ client socket (cli->sockfd). Nếu không nhận được tên , hàm đặt cờ leave_flag thành 1 để thoát khỏi hàm.

void *handle_client(void *arg)
{
	char buff_out[BUFFER_SZ];
	char name[32];
	char message[BUFFER_SZ + 64];
	int leave_flag = 0;
	cli_count++;
	client_t *cli = (client_t *)arg;
	bzero(buff_out, BUFFER_SZ);
	recv(cli->sockfd, name, 32, 0);
	strcpy(cli->name, name);
	sprintf(buff_out, "%s has joined\n", cli->name);
	
	printf("LOG: %s", buff_out);

	while (1)
{
	if (leave_flag)
	{
	break;
	}
	int receive = recv(cli->sockfd, buff_out, BUFFER_SZ, 0);
	if (receive > 0)
	{
	if (strlen(buff_out) > 0)
	{
	send_message(buff_out, cli->uid);
	sscanf(buff_out, "Sender:%s\nMessage:%s\n", name, message);
	printf("# Message: %s => %s\n", name, message);
	}
	}
	else if (receive == 0 || strcmp(buff_out, "exit") == 0)
	{
	sprintf(buff_out, "%s has left\n", cli->name);
	
	printf("LOG: %s", buff_out);

	leave_flag = 1;
	}
	else
	{
	printf("ERROR: -1\n");
	leave_flag = 1;
	}
	bzero(buff_out, BUFFER_SZ);
	}
	close(cli->sockfd);
	queue_remove(cli->uid);
	free(cli);
	cli_count--;
	pthread_detach(pthread_self());
	return NULL;
}

// kiểm tra số lượng tham số dòng lệnh được truyền vào. Nếu số lượng không đúng (khác 2), nghĩa là không có cổng được chỉ định
int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("Usage: %s <port>\n", argv[0]);
		return EXIT_FAILURE;
	}

	char *ip = "127.0.0.1";
	int port = atoi(argv[1]);
	int option = 1;
	int listenfd = 0, connfd = 0;  //là các file descriptor để lắng nghe kết nối và kết nối của client.
	struct sockaddr_in serv_addr;
	struct sockaddr_in cli_addr;
	pthread_t tid;
	fd = open("/dev/simple_driver", O_RDWR);
	listenfd = socket(AF_INET, SOCK_STREAM, 0);//socket được tạo
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(ip);
	serv_addr.sin_port = htons(port);

	signal(SIGPIPE, SIG_IGN);
	//setsockop  de cấu hình socket  tùy chọn SO_REUSEPORT và SO_REUSEADDR để tái sử dụng cổng và địa chỉ của socket sau khi nó được giải phóng.

	if (setsockopt(listenfd, SOL_SOCKET, (SO_REUSEPORT | SO_REUSEADDR), (char *)&option, sizeof(option)) < 0)
	{
		perror("ERROR: setsockopt failed");
		return EXIT_FAILURE;
	}

	if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) //Socket được ràng buộc (bind) với địa chỉ và cổng được chỉ định
	{
		perror("ERROR: Socket binding failed");
		return EXIT_FAILURE;
	}

	if (listen(listenfd, 10) < 0)
	{
		perror("ERROR: Socket listening failed");
		return EXIT_FAILURE;
	}
	
	printf("\n");
	printf("============= WELCOME TO THE CHATROOM =============\n");

	while (1)
	{
		socklen_t clilen = sizeof(cli_addr);
		connfd = accept(listenfd, (struct sockaddr *)&cli_addr, &clilen);

		if ((cli_count + 1) == MAX_CLIENTS)
		{
			printf("Max clients reached. Rejected: ");
			print_client_addr(cli_addr);
			printf(":%d\n", cli_addr.sin_port);
			close(connfd);
			continue;
		}

		client_t *cli = (client_t *)malloc(sizeof(client_t));
		cli->address = cli_addr;
		cli->sockfd = connfd;
		cli->uid = uid++;

		queue_add(cli);
		pthread_create(&tid, NULL, &handle_client, (void *)cli);
		sleep(1); //server chờ một thời gian ngắn bằng cách gọi hàm sleep(1) trước khi quay lại vòng lặp để chấp nhận kết nối từ client tiếp theo.
	}

	return EXIT_SUCCESS;
}
