#include <curses.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>
#include <getopt.h>
#include <string>
using std::string;
#include <deque>
using std::deque;
#include <pthread.h>
#include <utility>
using std::pair;
#include "dh.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/kdf.h>
#include <cstdlib>
#include <ctime>

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void *recvMsg(void *);      /* for trecv */
static pthread_t tcurses;   /* setup curses and draw messages from queue */
void *cursesthread(void *); /* for tcurses */
/* tcurses will get a queue full of these and redraw the appropriate windows */
struct redraw_data
{
    bool resize;
    string msg;
    string sender;
    WINDOW *win;
};
static deque<redraw_data> mq; /* messages and resizes yet to be drawn */
/* manage access to message queue: */
static pthread_mutex_t qmx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qcv = PTHREAD_COND_INITIALIZER;

/* XXX different colors for different senders */

/* record chat history as deque of strings: */
static deque<string> transcript;

#define max(a, b) \
    ({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

int listensock, sockfd;

[[noreturn]] static void fail_exit(const char *msg);

[[noreturn]] static void error(const char *msg)
{
    perror(msg);
    fail_exit("");
}

unsigned char server_sharedSec_key_global[1232];
unsigned char client_sharedSec_key_global[1232];

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// Function to compare and verify shared keys
void compareSharedKeys()
{
    // Read the shared keys from the shared memory
    unsigned char server_shared_key[pLen];
    unsigned char client_shared_key[pLen];
    memcpy(server_shared_key, server_sharedSec_key_global, pLen);
    memcpy(client_shared_key, client_sharedSec_key_global, pLen);

    // Compare the shared keys
    if (memcmp(server_shared_key, client_shared_key, pLen) == 0)
    {
        printf("Server and client have the same shared key.\n\n");
    }
    else
    {
        printf("Server and client do not have the same shared key.\n\n");
    }

    printf("Server's key:\n");
    for (size_t i = 0; i < pLen; i++)
    {
        printf("%02x ", server_shared_key[i]);
    }
    printf("\n\nClient's key:\n");
    for (size_t i = 0; i < pLen; i++)
    {
        printf("%02x ", client_shared_key[i]);
    }
}

int initServerNet(int port)
{
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    /* NOTE: might not need the above if you make sure the client closes first */
    if (listensock < 0)
        error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    fprintf(stderr, "listening on port %i...\n", port);
    listen(listensock, 1);
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr *)&cli_addr, &clilen);
    if (sockfd < 0)
        error("error on accept");
    close(listensock);
    fprintf(stderr, "connection made, starting session...\n");
    /* at this point, should be able to send/recv on sockfd */

    // Handshake Protocol

    // Server receives SYN
    size_t SYN, ACK;
    if (recv(sockfd, &SYN, sizeof(SYN), 0) == -1)
    {
        error("Server failed to receive SYN from Client.");
    }
    else
    {
        printf("Server received SYN successfully!\n\n");
    }
    // sleep(1);

    // Server sends SYNC+ACK to Client
    ACK = SYN + 1;
    srand(time(nullptr));
    SYN = rand() % 1000000 + 100000;
    if (send(sockfd, &SYN, sizeof(SYN), 0) == -1)
    {
        error("Client failed to send SYN to Server.");
    }
    else
    {
        printf("Server sent SYN successfully!\n");
    }
    if (send(sockfd, &ACK, sizeof(ACK), 0) == -1)
    {
        error("Server failed to send ACK to Client.");
    }
    else
    {
        printf("Server sent ACK successfully!\n");
    }
    printf("Server sent SYN+ACK successfully!\n\n");
    // sleep(1);

    // Server receives ACK from Client
    if (recv(sockfd, &ACK, sizeof(ACK), 0) == -1)
    {
        error("Server failed to receive ACK from Client.");
    }
    else
    {
        printf("Server received ACK successfully!\n\n");
    }
    // sleep(1);

    printf("================================================\n\n");
    /////////////////////////////////////////////////////////
    // DH
    if (init("params") == 0)
    {
        gmp_printf("Successfully read DH params:\nq = %Zd\np = %Zd\ng = %Zd\n", q, p, g);
    }
    // Generate Server's Private and Public keys
    NEWZ(server_secKey);
    NEWZ(server_pubKey);
    if (dhGen(server_secKey, server_pubKey) < 0)
    {
        error("ERROR Server's secret key and public key failed to generate.");
    }
    else
    {
        printf("Server's Secret key and Public key generated.\n\n");
    }

    // send Server's Public key to Client
    unsigned char server_pk_buf[pLen];
    size_t server_pk_len = sizeof(server_pk_buf);
    Z2BYTES(server_pk_buf, server_pk_len, server_pubKey);
    if (send(sockfd, server_pk_buf, server_pk_len, 0) == -1)
    {
        error("ERROR sending Server's DH public key to Client");
    }
    else
    {
        printf("Server's Public key sent successfully!\n\n");
    }

    // receive Client's Public key
    unsigned char client_pk_buf[pLen];
    size_t client_pk_len = sizeof(client_pk_buf);
    NEWZ(client_pubKey);
    if (recv(sockfd, client_pk_buf, client_pk_len, 0) == -1)
    {
        error("ERROR receiving DH client's public key");
    }
    else
    {
        printf("Client's Public key received successfully!\n\n");
    }
    BYTES2Z(client_pubKey, client_pk_buf, client_pk_len);

    // Compute shared secret key
    unsigned char server_sharedSec_key_buf[pLen];
    size_t sharedSec_key_len = sizeof(server_sharedSec_key_buf);
    if (dhFinal(server_secKey, server_pubKey, client_pubKey, server_sharedSec_key_buf, sharedSec_key_len) < 0)
    {
        error("ERROR shared key");
    }
    else
    {
        printf("SUCCESS shared key!\n\n");
    }

    // Copy server's shared key to global server shared key buf to VERIFY
    memcpy(server_sharedSec_key_global, server_sharedSec_key_buf, sharedSec_key_len);
    // compareSharedKeys();

    // Verify shared secret key are the same
    // if (memcmp(server_sharedSec_key_buf,client_sharedSec_key_global,512) == 0) {
    // 	printf("The Server and the Client have the same key :D\n");
    // } else {
    // 	printf("The Server and the Client doesn't have the same key :c\n");
    // }

    // printf("Server's key:\n");
    // for (size_t i = 0; i < pLen; i++) {
    // 	printf("%02x ",server_sharedSec_key_buf[i]);
    // }
    // printf("\n\nClient's key:\n");
    // for (size_t i = 0; i < pLen; i++) {
    // 	printf("%02x ",client_sharedSec_key_global[i]);
    // }

    printf("\n\n================================================\n\n");

    return 0;
}

static int initClientNet(char *hostname, int port)
{
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 0)
        error("ERROR opening socket");
    server = gethostbyname(hostname);
    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    /* at this point, should be able to send/recv on sockfd */

    // Handshake Protocol

    srand(time(nullptr));
    size_t SYN = rand() % 1000000 + 10000;

    // Client sends SYN to Server
    if (send(sockfd, &SYN, sizeof(SYN), 0) == -1)
    {
        error("Client failed to send SYN to Server.");
    }
    else
    {
        printf("Client sent SYN successfully!\n\n");
    }
    // sleep(1);

    // Client received SYNC+ACK from Server
    size_t ACK;
    if (recv(sockfd, &SYN, sizeof(SYN), 0) == -1)
    {
        error("Client failed to receive SYN to Server.");
    }
    else
    {
        printf("Client received SYN successfully!\n");
    }
    if (recv(sockfd, &ACK, sizeof(ACK), 0) == -1)
    {
        error("Client failed to receive ACK to Server.");
    }
    else
    {
        printf("Client received ACK successfully!\n");
    }
    printf("Client received SYN+ACK successfully!\n\n");
    // sleep(1);

    // Client sends ACK to Server
    ACK = SYN + 1;
    if (send(sockfd, &ACK, sizeof(ACK), 0) == -1)
    {
        error("Client failed to send ACK to Server.");
    }
    else
    {
        printf("Client sent ACK successfully!\n\n");
    }
    // sleep(1);

    printf("================================================\n\n");

    /////////////////////////////////////////////////////////
    // DH
    if (init("params") == 0)
    {
        gmp_printf("Successfully read DH params:\nq = %Zd\np = %Zd\ng = %Zd\n", q, p, g);
    }
    // gen client's sk and pk, and also server's pk
    NEWZ(client_secKey);
    NEWZ(client_pubKey);
    if (dhGen(client_secKey, client_pubKey) < 0)
    {
        error("ERROR Server's secret key and public key failed to generate.");
    }
    else
    {
        printf("Client's Secret key and Public key generated.\n\n");
    }

    // send Client Public key to Server
    unsigned char client_pk_buf[pLen];
    size_t client_pk_len = sizeof(client_pk_buf);
    Z2BYTES(client_pk_buf, client_pk_len, client_pubKey);
    if (send(sockfd, client_pk_buf, client_pk_len, 0) == -1)
    {
        error("ERROR sending Client's DH public key to Server");
    }
    else
    {
        printf("Client's Public key sent successfully!\n\n");
    }

    // receive Server's Public key
    unsigned char server_pk_buf[pLen];
    size_t server_pk_len = sizeof(server_pk_buf);
    NEWZ(server_pubKey);
    if (recv(sockfd, server_pk_buf, server_pk_len, 0) == -1)
    {
        error("ERROR receiving DH server's public key");
    }
    else
    {
        printf("Server's Public key received successfully!\n\n");
    }
    BYTES2Z(server_pubKey, server_pk_buf, server_pk_len);

    // compute Shared Secret key
    unsigned char client_sharedSec_key_buf[pLen];
    size_t sharedSec_key_len = sizeof(client_sharedSec_key_buf);
    if (dhFinal(client_secKey, client_pubKey, server_pubKey, client_sharedSec_key_buf, sharedSec_key_len) < 0)
    {
        error("ERROR shared key");
    }
    else
    {
        printf("SUCCESS shared key!\n\n");
    }

    // Copy client's shared key to global client shared key buf to VERIFY
    memcpy(client_sharedSec_key_global, client_sharedSec_key_buf, sharedSec_key_len);
    // compareSharedKeys();

    // printf("\n\nClient's key:\n");
    // for (size_t i = 0; i < pLen; i++) {
    // 	printf("%02x ",client_sharedSec_key_buf[i]);
    // }

    printf("\n\n================================================\n\n");

    return 0;
}

static int shutdownNetwork()
{
    shutdown(sockfd, 2);
    unsigned char dummy[64];
    ssize_t r;
    do
    {
        r = recv(sockfd, dummy, 64, 0);
    } while (r != 0 && r != -1);
    close(sockfd);
    return 0;
}

/* end network stuff. */

[[noreturn]] static void fail_exit(const char *msg)
{
    // Make sure endwin() is only called in visual mode. As a note, calling it
    // twice does not seem to be supported and messed with the cursor position.
    if (!isendwin())
        endwin();
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

// Checks errors for (most) ncurses functions. CHECK(fn, x, y, z) is a checked
// version of fn(x, y, z).
#define CHECK(fn, ...)                                  \
    do                                                  \
        if (fn(__VA_ARGS__) == ERR)                     \
            fail_exit(#fn "(" #__VA_ARGS__ ") failed"); \
    while (false)

static bool should_exit = false;

// Message window
static WINDOW *msg_win;
// Separator line above the command (readline) window
static WINDOW *sep_win;
// Command (readline) window
static WINDOW *cmd_win;

// Input character for readline
static unsigned char input;

static int readline_getc(FILE *dummy)
{
    return input;
}

/* if batch is set, don't draw immediately to real screen (use wnoutrefresh
 * instead of wrefresh) */
static void msg_win_redisplay(bool batch, const string &newmsg = "", const string &sender = "")
{
    if (batch)
        wnoutrefresh(msg_win);
    else
    {
        wattron(msg_win, COLOR_PAIR(2));
        wprintw(msg_win, "%s:", sender.c_str());
        wattroff(msg_win, COLOR_PAIR(2));
        wprintw(msg_win, " %s\n", newmsg.c_str());
        wrefresh(msg_win);
    }
}

static void msg_typed(char *line)
{

    /////////////////////
    // gen client's sk and pk, and also server's pk

    /////////////////////
    int bytes_sent;
    ////////////////////

    unsigned char hash[32]; /* change 32 to 64 if you use sha512 */
    SHA256((unsigned char *)line, strlen(line), hash);
    if ((bytes_sent = send(sockfd, hash, sizeof(hash), 0)) == -1)
        error("send failed");
    /////////////////////////
    // printf("here\n");
    unsigned char *plaintext = (unsigned char *)line;
    // printf("%s\n",plaintext);
    const EVP_CIPHER *cipher = EVP_aes_256_cbc(); // Use AES-256 CBC algorithm
    unsigned char ciphertext[1024];               // Output buffer
    unsigned char decryptedtext[1024];
    const EVP_MD *md = EVP_sha256(); // Hash function to use
    unsigned char key[32];           // Output buffer for derived key
    size_t key_len = sizeof(key);    // Key length in bytes
    // Derive key using HKDF
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, md);
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0); // No salt
    EVP_PKEY_CTX_set1_hkdf_key(pctx, server_sharedSec_key_global, 1232);
    EVP_PKEY_derive(pctx, key, &key_len);
    EVP_PKEY_CTX_free(pctx);

    const int iv_len = EVP_CIPHER_iv_length(cipher); // iv_len will be 16 (128 bits)
    unsigned char iv[iv_len];                        // Allocate space for the IV
    memcpy(iv, key, iv_len);

    int decryptedtext_len, ciphertext_len;
    ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);
    // printf("key:");
    // BIO_dump_fp(stdout, (const char *)key, 32);
    // printf("iv:");
    // BIO_dump_fp(stdout, (const char *)iv, 16);
    // printf("Ciphertext:");
    // BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

    if ((bytes_sent = send(sockfd, key, sizeof(key), 0)) == -1)
        error("send failed");
    if ((bytes_sent = send(sockfd, iv, sizeof(iv), 0)) == -1)
        error("send failed");
    if ((bytes_sent = send(sockfd, &ciphertext_len, sizeof(ciphertext_len), 0)) == -1)
        error("send failed");
    string mymsg;
    if (!line)
    {
        // Ctrl-D pressed on empty line
        should_exit = true;
        /* XXX send a "goodbye" message so other end doesn't
         * have to wait for timeout on recv()? */
    }
    else
    {
        if (*line)
        {
            add_history(line);
            mymsg = string(line);
            transcript.push_back("me: " + mymsg);
            ssize_t nbytes;
            if ((nbytes = send(sockfd, ciphertext, ciphertext_len, 0)) == -1)
                error("send failed");
            // printf("success!\n");
        }
        pthread_mutex_lock(&qmx);
        mq.push_back({false, mymsg, "me", msg_win});
        pthread_cond_signal(&qcv);
        pthread_mutex_unlock(&qmx);
    }
}

/* if batch is set, don't draw immediately to real screen (use wnoutrefresh
 * instead of wrefresh) */
static void cmd_win_redisplay(bool batch)
{
    int prompt_width = strnlen(rl_display_prompt, 128);
    int cursor_col = prompt_width + strnlen(rl_line_buffer, rl_point);

    werase(cmd_win);
    mvwprintw(cmd_win, 0, 0, "%s%s", rl_display_prompt, rl_line_buffer);
    /* XXX deal with a longer message than the terminal window can show */
    if (cursor_col >= COLS)
    {
        // Hide the cursor if it lies outside the window. Otherwise it'll
        // appear on the very right.
        curs_set(0);
    }
    else
    {
        wmove(cmd_win, 0, cursor_col);
        curs_set(1);
    }
    if (batch)
        wnoutrefresh(cmd_win);
    else
        wrefresh(cmd_win);
}

static void readline_redisplay(void)
{
    pthread_mutex_lock(&qmx);
    mq.push_back({false, "", "", cmd_win});
    pthread_cond_signal(&qcv);
    pthread_mutex_unlock(&qmx);
}

static void resize(void)
{
    if (LINES >= 3)
    {
        wresize(msg_win, LINES - 2, COLS);
        wresize(sep_win, 1, COLS);
        wresize(cmd_win, 1, COLS);
        /* now move bottom two to last lines: */
        mvwin(sep_win, LINES - 2, 0);
        mvwin(cmd_win, LINES - 1, 0);
    }

    /* Batch refreshes and commit them with doupdate() */
    msg_win_redisplay(true);
    wnoutrefresh(sep_win);
    cmd_win_redisplay(true);
    doupdate();
}

static void init_ncurses(void)
{
    if (!initscr())
        fail_exit("Failed to initialize ncurses");

    if (has_colors())
    {
        CHECK(start_color);
        CHECK(use_default_colors);
    }
    CHECK(cbreak);
    CHECK(noecho);
    CHECK(nonl);
    CHECK(intrflush, NULL, FALSE);

    curs_set(1);

    if (LINES >= 3)
    {
        msg_win = newwin(LINES - 2, COLS, 0, 0);
        sep_win = newwin(1, COLS, LINES - 2, 0);
        cmd_win = newwin(1, COLS, LINES - 1, 0);
    }
    else
    {
        // Degenerate case. Give the windows the minimum workable size to
        // prevent errors from e.g. wmove().
        msg_win = newwin(1, COLS, 0, 0);
        sep_win = newwin(1, COLS, 0, 0);
        cmd_win = newwin(1, COLS, 0, 0);
    }
    if (!msg_win || !sep_win || !cmd_win)
        fail_exit("Failed to allocate windows");

    scrollok(msg_win, true);

    if (has_colors())
    {
        // Use white-on-blue cells for the separator window...
        CHECK(init_pair, 1, COLOR_WHITE, COLOR_BLUE);
        CHECK(wbkgd, sep_win, COLOR_PAIR(1));
        /* NOTE: -1 is the default background color, which for me does
         * not appear to be any of the normal colors curses defines. */
        CHECK(init_pair, 2, COLOR_MAGENTA, -1);
    }
    else
    {
        wbkgd(sep_win, A_STANDOUT); /* c.f. man curs_attr */
    }
    wrefresh(sep_win);
}

static void deinit_ncurses(void)
{
    delwin(msg_win);
    delwin(sep_win);
    delwin(cmd_win);
    endwin();
}

static void init_readline(void)
{
    // Let ncurses do all terminal and signal handling
    rl_catch_signals = 0;
    rl_catch_sigwinch = 0;
    rl_deprep_term_function = NULL;
    rl_prep_term_function = NULL;

    // Prevent readline from setting the LINES and COLUMNS environment
    // variables, which override dynamic size adjustments in ncurses. When
    // using the alternate readline interface (as we do here), LINES and
    // COLUMNS are not updated if the terminal is resized between two calls to
    // rl_callback_read_char() (which is almost always the case).
    rl_change_environment = 0;

    // Handle input by manually feeding characters to readline
    rl_getc_function = readline_getc;
    rl_redisplay_function = readline_redisplay;

    rl_callback_handler_install("> ", msg_typed);
}

static void deinit_readline(void)
{
    rl_callback_handler_remove();
}

static const char *usage =
    "Usage: %s [OPTIONS]...\n"
    "Secure chat for CSc380.\n\n"
    "   -c, --connect HOST  Attempt a connection to HOST.\n"
    "   -l, --listen        Listen for new connections.\n"
    "   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
    "   -h, --help          show this message and exit.\n";

int main(int argc, char *argv[])
{
    // define long options
    static struct option long_opts[] = {
        {"connect", required_argument, 0, 'c'},
        {"listen", no_argument, 0, 'l'},
        {"port", required_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};
    // process options:
    char c;
    int opt_index = 0;
    int port = 1337;
    char hostname[HOST_NAME_MAX + 1] = "localhost";
    hostname[HOST_NAME_MAX] = 0;
    bool isclient = true;

    while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1)
    {
        switch (c)
        {
        case 'c':
            if (strnlen(optarg, HOST_NAME_MAX))
                strncpy(hostname, optarg, HOST_NAME_MAX);
            break;
        case 'l':
            isclient = false;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'h':
            printf(usage, argv[0]);
            return 0;
        case '?':
            printf(usage, argv[0]);
            return 1;
        }
    }
    if (isclient)
    {
        initClientNet(hostname, port);
    }
    else
    {
        initServerNet(port);
    }

    /* NOTE: these don't work if called from cursesthread */
    init_ncurses();
    init_readline();
    /* start curses thread */
    if (pthread_create(&tcurses, 0, cursesthread, 0))
    {
        fprintf(stderr, "Failed to create curses thread.\n");
    }
    /* start receiver thread: */
    if (pthread_create(&trecv, 0, recvMsg, 0))
    {
        fprintf(stderr, "Failed to create update thread.\n");
    }

    /* put this in the queue to signal need for resize: */
    redraw_data rd = {false, "", "", NULL};
    do
    {
        int c = wgetch(cmd_win);
        switch (c)
        {
        case KEY_RESIZE:
            pthread_mutex_lock(&qmx);
            mq.push_back(rd);
            pthread_cond_signal(&qcv);
            pthread_mutex_unlock(&qmx);
            break;
            // Ctrl-L -- redraw screen
        // case '\f':
        // 	// Makes the next refresh repaint the screen from scratch
        // 	/* XXX this needs to be done in the curses thread as well. */
        // 	clearok(curscr,true);
        // 	resize();
        // 	break;
        default:
            input = c;
            rl_callback_read_char();
        }
    } while (!should_exit);

    shutdownNetwork();
    deinit_ncurses();
    deinit_readline();
    return 0;
}

/* Let's have one thread responsible for all things curses.  It should
 * 1. Initialize the library
 * 2. Wait for messages (we'll need a mutex-protected queue)
 * 3. Restore terminal / end curses mode? */

/* We'll need yet another thread to listen for incoming messages and
 * post them to the queue. */

void *cursesthread(void *pData)
{
    /* NOTE: these calls only worked from the main thread... */
    // init_ncurses();
    // init_readline();
    while (true)
    {
        pthread_mutex_lock(&qmx);
        while (mq.empty())
        {
            pthread_cond_wait(&qcv, &qmx);
            /* NOTE: pthread_cond_wait will release the mutex and block, then
             * reaquire it before returning.  Given that only one thread (this
             * one) consumes elements of the queue, we probably don't have to
             * check in a loop like this, but in general this is the recommended
             * way to do it.  See the man page for details. */
        }
        /* at this point, we have control of the queue, which is not empty,
         * so write all the messages and then let go of the mutex. */
        while (!mq.empty())
        {
            redraw_data m = mq.front();
            mq.pop_front();
            if (m.win == cmd_win)
            {
                cmd_win_redisplay(m.resize);
            }
            else if (m.resize)
            {
                resize();
            }
            else
            {
                msg_win_redisplay(false, m.msg, m.sender);
                /* Redraw input window to "focus" it (otherwise the cursor
                 * will appear in the transcript which is confusing). */
                cmd_win_redisplay(false);
            }
        }
        pthread_mutex_unlock(&qmx);
    }
    return 0;
}

void *recvMsg(void *)
{

    unsigned char hash[32];   /* change 32 to 64 if you use sha512 */
    unsigned char r_hash[32]; // recieved hash to auth mess

    const EVP_CIPHER *cipher = EVP_aes_256_cbc(); // Use AES-256 CBC algorithm
    unsigned char ciphertext[1024];               // Output buffer
    unsigned char decryptedtext[1024];
    unsigned char key[32];          // Output buffer for derived key
    memset(key, 0x00, sizeof(key)); // Zero out key buffer
    size_t key_len = sizeof(key);   // Key length in bytes

    const int iv_len = EVP_CIPHER_iv_length(cipher); // iv_len will be 16 (128 bits)
    unsigned char iv[iv_len];                        // Allocate space for the IV
    memcpy(iv, key, iv_len);
    int decryptedtext_len, ciphertext_len;

    size_t maxlen = 256;

    char msg[maxlen + 1];
    ssize_t nbytes;
    while (1)
    {

        if ((nbytes = recv(sockfd, r_hash, 32, 0)) == -1)
            error("send failed");
        if ((nbytes = recv(sockfd, key, sizeof(key), 0)) == -1)
            error("recv failed");
        if ((nbytes = recv(sockfd, iv, sizeof(iv), 0)) == -1)
            error("recv failed");
        // printf("key:");
        // BIO_dump_fp(stdout, (const char *)key, 32);
        // printf("iv:");
        // BIO_dump_fp(stdout, (const char *)iv, 16);
        if ((nbytes = recv(sockfd, &ciphertext_len, sizeof(ciphertext_len), 0)) == -1)
            error("recv failed");
        // printf("cipherlen:%d\n", ciphertext_len);
        if ((nbytes = recv(sockfd, ciphertext, ciphertext_len, 0)) == -1)
            error("recv failed");
        // printf("Ciphertext is:\n");
        // print ciphertext
        // BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
        /* Decrypt the ciphertext */
        decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
        // printf("%s\n",ciphertext);
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';
        // printf("%s\n", decryptedtext);

        SHA256((unsigned char *)msg, strlen(msg), hash);
        if (memcmp(r_hash, hash, 32) == 0)
            // printf("hi\n");

            if (nbytes == 0)
            {
                /* signal to the main loop that we should quit: */
                should_exit = true;
                return 0;
            }
        pthread_mutex_lock(&qmx);
        mq.push_back({false, (char *)decryptedtext, "Mr Thread", msg_win});
        pthread_cond_signal(&qcv);
        pthread_mutex_unlock(&qmx);
    }
    return 0;
}
