#define _GNU_SOURCE
/*
 * WebSocket lib for plain "ws://" connections.
 * Copyright 2010 Joel Martin
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h> // daemonizing
#include <fcntl.h>  // daemonizing
#include <stdint.h>
#include <strings.h>
#include "websocket.h"

/*
 * Global state
 *
 *   Warning: not thread safe
 */
int pipe_error = 0;
settings_t settings;


void traffic(const char * token) {
    if ((settings.verbose) && (! settings.daemon)) {
        fprintf(stdout, "%s", token);
        fflush(stdout);
    }
}

void error(char *msg)
{
    perror(msg);
}

void fatal(char *msg)
{
    perror(msg);
    exit(1);
}

/* resolve host with also IP address parsing */
int resolve_host(struct in_addr *sin_addr, const char *hostname)
{
    if (!inet_aton(hostname, sin_addr)) {
        struct addrinfo *ai, *cur;
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        if (getaddrinfo(hostname, NULL, &hints, &ai))
            return -1;
        for (cur = ai; cur; cur = cur->ai_next) {
            if (cur->ai_family == AF_INET) {
                *sin_addr = ((struct sockaddr_in *)cur->ai_addr)->sin_addr;
                freeaddrinfo(ai);
                return 0;
            }
        }
        freeaddrinfo(ai);
        return -1;
    }
    return 0;
}


/*
 * SSL Wrapper Code
 */

ssize_t ws_recv(ws_ctx_t *ctx, void *buf, size_t len) {
    return recv(ctx->sockfd, buf, len, 0);
}

ssize_t ws_send(ws_ctx_t *ctx, const void *buf, size_t len) {
    return send(ctx->sockfd, buf, len, 0);
}

ws_ctx_t *alloc_ws_ctx() {
    ws_ctx_t *ctx;
    if (! (ctx = malloc(sizeof(ws_ctx_t))) )
        { fatal("malloc()"); }

    if (! (ctx->cin_buf = malloc(BUFSIZE)) )
        { fatal("malloc of cin_buf"); }
    if (! (ctx->cout_buf = malloc(BUFSIZE)) )
        { fatal("malloc of cout_buf"); }
    if (! (ctx->tin_buf = malloc(BUFSIZE)) )
        { fatal("malloc of tin_buf"); }
    if (! (ctx->tout_buf = malloc(BUFSIZE)) )
        { fatal("malloc of tout_buf"); }

    ctx->headers = malloc(sizeof(headers_t));
    return ctx;
}

void free_ws_ctx(ws_ctx_t *ctx) {
    free(ctx->cin_buf);
    free(ctx->cout_buf);
    free(ctx->tin_buf);
    free(ctx->tout_buf);
    free(ctx);
}

ws_ctx_t *ws_socket(ws_ctx_t *ctx, int socket) {
    ctx->sockfd = socket;
    return ctx;
}

void ws_socket_free(ws_ctx_t *ctx) {
    if (ctx->sockfd) {
        shutdown(ctx->sockfd, SHUT_RDWR);
        close(ctx->sockfd);
        ctx->sockfd = 0;
    }
}

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int ws_b64_ntop(const unsigned char const *src, size_t srclen,
                char *dst, size_t dstlen) {
    size_t i, out = 0;

    for (i = 0; i < srclen; i += 3) {
        unsigned int v = src[i] << 16;
        int remain = srclen - i;

        if (remain > 1)
            v |= src[i + 1] << 8;
        if (remain > 2)
            v |= src[i + 2];

        if (out + 4 >= dstlen)
            return -1;

        dst[out++] = b64_table[(v >> 18) & 0x3f];
        dst[out++] = b64_table[(v >> 12) & 0x3f];
        dst[out++] = remain > 1 ? b64_table[(v >> 6) & 0x3f] : '=';
        dst[out++] = remain > 2 ? b64_table[v & 0x3f] : '=';
    }

    if (out >= dstlen)
        return -1;
    dst[out] = '\0';
    return out;
}

static int b64_value(char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    if (c == '=')
        return -2;
    return -1;
}

int ws_b64_pton(const char const *src, unsigned char *dst, size_t dstlen) {
    int vals[4];
    size_t out = 0;

    while (*src) {
        int i;
        unsigned int v;

        for (i = 0; i < 4; i++) {
            vals[i] = b64_value(*src++);
            if (vals[i] == -1)
                return -1;
        }

        v = ((vals[0] & 0x3f) << 18) | ((vals[1] & 0x3f) << 12);
        if (vals[2] >= 0)
            v |= (vals[2] & 0x3f) << 6;
        if (vals[3] >= 0)
            v |= vals[3] & 0x3f;

        if (out >= dstlen)
            return -1;
        dst[out++] = (v >> 16) & 0xff;
        if (vals[2] >= 0) {
            if (out >= dstlen)
                return -1;
            dst[out++] = (v >> 8) & 0xff;
        }
        if (vals[3] >= 0) {
            if (out >= dstlen)
                return -1;
            dst[out++] = v & 0xff;
        }
    }

    return out;
}

/* ------------------------------------------------------- */


int encode_hixie(u_char const *src, size_t srclength,
                 char *target, size_t targsize) {
    int sz = 0, len = 0;
    target[sz++] = '\x00';
    len = ws_b64_ntop(src, srclength, target+sz, targsize-sz);
    if (len < 0) {
        return len;
    }
    sz += len;
    target[sz++] = '\xff';
    return sz;
}

int decode_hixie(char *src, size_t srclength,
                 u_char *target, size_t targsize,
                 unsigned int *opcode, unsigned int *left) {
    char *start, *end, cntstr[4];
    int i, len, framecount = 0, retlen = 0;
    unsigned char chr;
    if ((src[0] != '\x00') || (src[srclength-1] != '\xff')) {
        handler_emsg("WebSocket framing error\n");
        return -1;
    }
    *left = srclength;

    if (srclength == 2 &&
        (src[0] == '\xff') &&
        (src[1] == '\x00')) {
        // client sent orderly close frame
        *opcode = 0x8; // Close frame
        return 0;
    }
    *opcode = 0x1; // Text frame

    start = src+1; // Skip '\x00' start
    do {
        /* We may have more than one frame */
        end = (char *)memchr(start, '\xff', srclength);
        *end = '\x00';
        len = ws_b64_pton(start, target+retlen, targsize-retlen);
        if (len < 0) {
            return len;
        }
        retlen += len;
        start = end + 2; // Skip '\xff' end and '\x00' start
        framecount++;
    } while (end < (src+srclength-1));
    if (framecount > 1) {
        snprintf(cntstr, 3, "%d", framecount);
        traffic(cntstr);
    }
    *left = 0;
    return retlen;
}

int encode_hybi(u_char const *src, size_t srclength,
                char *target, size_t targsize, unsigned int opcode)
{
    unsigned long long payload_offset = 2;
    int len = 0;

    if (opcode != OPCODE_TEXT && opcode != OPCODE_BINARY) {
        handler_emsg("Invalid opcode. Opcode must be 0x01 for text mode, or 0x02 for binary mode.\n");
        return -1;
    }

    target[0] = (char)((opcode & 0x0F) | 0x80);

    if ((int)srclength <= 0) {
        return 0;
    }

    if (opcode & OPCODE_TEXT) {
        len = ((srclength - 1) / 3) * 4 + 4;
    } else {
        len = srclength;
    }

    if (len <= 125) {
        target[1] = (char) len;
        payload_offset = 2;
    } else if ((len > 125) && (len < 65536)) {
        target[1] = (char) 126;
        *(u_short*)&(target[2]) = htons(len);
        payload_offset = 4;
    } else {
        handler_emsg("Sending frames larger than 65535 bytes not supported\n");
        return -1;
        //target[1] = (char) 127;
        //*(u_long*)&(target[2]) = htonl(b64_sz);
        //payload_offset = 10;
    }

    if (opcode & OPCODE_TEXT) {
        len = ws_b64_ntop(src, srclength, target+payload_offset, targsize-payload_offset);
    } else {
        memcpy(target+payload_offset, src, srclength);
        len = srclength;
    }

    if (len < 0) {
        return len;
    }

    return len + payload_offset;
}

int decode_hybi(unsigned char *src, size_t srclength,
                u_char *target, size_t targsize,
                unsigned int *opcode, unsigned int *left)
{
    unsigned char *frame, *mask, *payload, save_char;
    char cntstr[4];
    int masked = 0;
    int i = 0, len, framecount = 0;
    size_t remaining;
    unsigned int target_offset = 0, hdr_length = 0, payload_length = 0;

    *left = srclength;
    frame = src;

    //printf("Deocde new frame\n");
    while (1) {
        // Need at least two bytes of the header
        // Find beginning of next frame. First time hdr_length, masked and
        // payload_length are zero
        frame += hdr_length + 4*masked + payload_length;
        //printf("frame[0..3]: 0x%x 0x%x 0x%x 0x%x (tot: %d)\n",
        //       (unsigned char) frame[0],
        //       (unsigned char) frame[1],
        //       (unsigned char) frame[2],
        //       (unsigned char) frame[3], srclength);

        if (frame > src + srclength) {
            //printf("Truncated frame from client, need %d more bytes\n", frame - (src + srclength) );
            break;
        }
        remaining = (src + srclength) - frame;
        if (remaining < 2) {
            //printf("Truncated frame header from client\n");
            break;
        }
        framecount ++;

        *opcode = frame[0] & 0x0f;
        masked = (frame[1] & 0x80) >> 7;

        if (*opcode == 0x8) {
            // client sent orderly close frame
            break;
        }

        payload_length = frame[1] & 0x7f;
        if (payload_length < 126) {
            hdr_length = 2;
            //frame += 2 * sizeof(char);
        } else if (payload_length == 126) {
            payload_length = (frame[2] << 8) + frame[3];
            hdr_length = 4;
        } else {
            handler_emsg("Receiving frames larger than 65535 bytes not supported\n");
            return -1;
        }
        if ((hdr_length + 4*masked + payload_length) > remaining) {
            continue;
        }
        //printf("    payload_length: %u, raw remaining: %u\n", payload_length, remaining);
        payload = frame + hdr_length + 4*masked;

        if (*opcode != OPCODE_TEXT && *opcode != OPCODE_BINARY) {
            handler_msg("Ignoring non-data frame, opcode 0x%x\n", *opcode);
            continue;
        }

        if (payload_length == 0) {
            handler_msg("Ignoring empty frame\n");
            continue;
        }

        if ((payload_length > 0) && (!masked)) {
            handler_emsg("Received unmasked payload from client\n");
            return -1;
        }

        // Terminate with a null for base64 decode
        save_char = payload[payload_length];
        payload[payload_length] = '\0';

        // unmask the data
        mask = payload - 4;
        for (i = 0; i < payload_length; i++) {
            payload[i] ^= mask[i%4];
        }

        if (*opcode & OPCODE_TEXT) {
            // base64 decode the data
            len = ws_b64_pton((const char*)payload, target+target_offset, targsize);
        } else {
            memcpy(target+target_offset, payload, payload_length);
            len = payload_length;
        }

        // Restore the first character of the next frame
        payload[payload_length] = save_char;
        if (len < 0) {
            handler_emsg("Base64 decode error code %d", len);
            return len;
        }
        target_offset += len;

        //printf("    len %d, raw %s\n", len, frame);
    }

    if (framecount > 1) {
        snprintf(cntstr, 3, "%d", framecount);
        traffic(cntstr);
    }

    *left = remaining;
    return target_offset;
}



int parse_handshake(ws_ctx_t *ws_ctx, char *handshake) {
    char *start, *end;
    headers_t *headers = ws_ctx->headers;

    headers->key1[0] = '\0';

    if ((strlen(handshake) < 92) || (bcmp(handshake, "GET ", 4) != 0)) {
        return 0;
    }
    start = handshake+4;
    end = strstr(start, " HTTP/1.1");
    if (!end) { return 0; }
    strncpy(headers->path, start, end-start);
    headers->path[end-start] = '\0';

    start = strcasestr(handshake, "\r\nHost: ");
    if (!start) { return 0; }
    start += 8;
    end = strstr(start, "\r\n");
    strncpy(headers->host, start, end-start);
    headers->host[end-start] = '\0';

    headers->origin[0] = '\0';
    start = strcasestr(handshake, "\r\nOrigin: ");
    if (start) {
        start += 10;
        end = strstr(start, "\r\n");
        strncpy(headers->origin, start, end-start);
        headers->origin[end-start] = '\0';
    }

    start = strcasestr(handshake, "\r\nSec-WebSocket-Version: ");
    if (!start) {
        return 0;
    }
    start += 25;
    end = strstr(start, "\r\n");
    strncpy(headers->version, start, end-start);
    headers->version[end-start] = '\0';
    ws_ctx->hybi = strtol(headers->version, NULL, 10);

    start = strcasestr(handshake, "\r\nSec-WebSocket-Key: ");
    if (!start) { return 0; }
    start += 21;
    end = strstr(start, "\r\n");
    strncpy(headers->key1, start, end-start);
    headers->key1[end-start] = '\0';

    start = strcasestr(handshake, "\r\nConnection: ");
    if (!start) { return 0; }
    start += 14;
    end = strstr(start, "\r\n");
    strncpy(headers->connection, start, end-start);
    headers->connection[end-start] = '\0';

    start = strcasestr(handshake, "\r\nSec-WebSocket-Protocol: ");
    if (start) {
        start += 26;
        end = strstr(start, "\r\n");
        strncpy(headers->protocols, start, end-start);
        headers->protocols[end-start] = '\0';
    } else {
        headers->protocols[0] = '\0';
    }

    return 1;
}

static uint32_t rol32(uint32_t v, unsigned int n) {
    return (v << n) | (v >> (32 - n));
}

static void sha1_transform(uint32_t state[5], const unsigned char block[64]) {
    uint32_t w[80], a, b, c, d, e, f, k, temp;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               block[i * 4 + 3];
    }
    for (i = 16; i < 80; i++)
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        temp = rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

static void sha1_digest(const unsigned char *data, size_t len,
                        unsigned char out[20]) {
    uint32_t state[5] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    };
    unsigned char block[64];
    uint64_t bit_len = (uint64_t)len * 8;
    size_t off = 0, rem;
    int i;

    while (len - off >= 64) {
        sha1_transform(state, data + off);
        off += 64;
    }

    rem = len - off;
    memset(block, 0, sizeof(block));
    memcpy(block, data + off, rem);
    block[rem] = 0x80;

    if (rem >= 56) {
        sha1_transform(state, block);
        memset(block, 0, sizeof(block));
    }

    for (i = 0; i < 8; i++)
        block[56 + i] = (bit_len >> (56 - i * 8)) & 0xff;
    sha1_transform(state, block);

    for (i = 0; i < 5; i++) {
        out[i * 4] = (state[i] >> 24) & 0xff;
        out[i * 4 + 1] = (state[i] >> 16) & 0xff;
        out[i * 4 + 2] = (state[i] >> 8) & 0xff;
        out[i * 4 + 3] = state[i] & 0xff;
    }
}

static void gen_sha1(headers_t *headers, char *target) {
    unsigned char input[1024 + sizeof(HYBI_GUID)];
    unsigned char hash[20];
    size_t key_len = strlen(headers->key1);

    memcpy(input, headers->key1, key_len);
    memcpy(input + key_len, HYBI_GUID, sizeof(HYBI_GUID) - 1);
    sha1_digest(input, key_len + sizeof(HYBI_GUID) - 1, hash);
    ws_b64_ntop(hash, sizeof(hash), target, HYBI10_ACCEPTHDRLEN);
}


ws_ctx_t *do_handshake(int sock) {
    char handshake[4096], response[4096], sha1[29];
    headers_t *headers;
    int len, i, offset;
    ws_ctx_t * ws_ctx;
    char *response_protocol;
    const char *response_protocol_header = "Sec-WebSocket-Protocol: ";
    const char *response_protocol_crlf = "\r\n";

    // Peek, but don't read the data
    len = recv(sock, handshake, 1024, MSG_PEEK);
    handshake[len] = 0;
    if (len == 0) {
        handler_msg("ignoring empty handshake\n");
        return NULL;
    } else if ((bcmp(handshake, "\x16", 1) == 0) ||
               (bcmp(handshake, "\x80", 1) == 0)) {
        handler_msg("TLS/wss connections are not supported\n");
        return NULL;
    } else {
        ws_ctx = alloc_ws_ctx();
        ws_socket(ws_ctx, sock);
        if (! ws_ctx) { return NULL; }
        handler_msg("using plain ws socket\n");
    }
    offset = 0;
    for (i = 0; i < 10; i++) {
        /* (offset + 1): reserve one byte for the trailing '\0' */
        if (0 > (len = ws_recv(ws_ctx, handshake + offset, sizeof(handshake) - (offset + 1)))) {
            handler_emsg("Read error during handshake: %m\n");
            free_ws_ctx(ws_ctx);
            return NULL;
        } else if (0 == len) {
            handler_emsg("Client closed during handshake\n");
            free_ws_ctx(ws_ctx);
            return NULL;
        }
        offset += len;
        handshake[offset] = 0;
        if (strstr(handshake, "\r\n\r\n")) {
            break;
        } else if (sizeof(handshake) <= (size_t)(offset + 1)) {
            handler_emsg("Oversized handshake\n");
            free_ws_ctx(ws_ctx);
            return NULL;
        } else if (9 == i) {
            handler_emsg("Incomplete handshake\n");
            free_ws_ctx(ws_ctx);
            return NULL;
        }
        usleep(10);
    }

    //handler_msg("handshake: %s\n", handshake);
    if (!parse_handshake(ws_ctx, handshake)) {
        handler_emsg("Invalid WS request\n");
        free_ws_ctx(ws_ctx);
        return NULL;
    }

    headers = ws_ctx->headers;

    if (headers->protocols == NULL || headers->protocols[0] == 0) {
        ws_ctx->opcode = OPCODE_BINARY;
        response_protocol_header = "";
        response_protocol = "";
        response_protocol_crlf = "";
    } else {
        response_protocol = strtok(headers->protocols, ",");
        if (!response_protocol || !strlen(response_protocol)) {
            ws_ctx->opcode = OPCODE_BINARY;
            response_protocol = "null";
        } else if (!strcmp(response_protocol, "base64")) {
            ws_ctx->opcode = OPCODE_TEXT;
        } else {
            ws_ctx->opcode = OPCODE_BINARY;
        }
    }

    handler_msg("using protocol HyBi/IETF 6455 %d\n", ws_ctx->hybi);
    gen_sha1(headers, sha1);
    snprintf(response, sizeof(response), SERVER_HANDSHAKE_HYBI,
             sha1, response_protocol_header, response_protocol,
             response_protocol_crlf);

    //handler_msg("response: %s\n", response);
    ws_send(ws_ctx, response, strlen(response));

    return ws_ctx;
}

void signal_handler(int sig) {
    switch (sig) {
        case SIGHUP: break; // ignore for now
        case SIGPIPE: pipe_error = 1; break; // handle inline
        case SIGTERM: exit(0); break;
    }
}

void daemonize(int keepfd) {
    int pid, i;

    umask(0);
    chdir("/");
    setgid(getgid());
    setuid(getuid());

    /* Double fork to daemonize */
    pid = fork();
    if (pid<0) { fatal("fork error"); }
    if (pid>0) { exit(0); }  // parent exits
    setsid();                // Obtain new process group
    pid = fork();
    if (pid<0) { fatal("fork error"); }
    if (pid>0) { exit(0); }  // parent exits

    /* Signal handling */
    signal(SIGHUP, signal_handler);   // catch HUP
    signal(SIGTERM, signal_handler);  // catch kill

    /* Close open files */
    for (i=getdtablesize(); i>=0; --i) {
        if (i != keepfd) {
            close(i);
        } else if (settings.verbose) {
            printf("keeping fd %d\n", keepfd);
        }
    }
    i=open("/dev/null", O_RDWR);  // Redirect stdin
    dup(i);                       // Redirect stdout
    dup(i);                       // Redirect stderr
}


void start_server() {
    int lsock, csock, pid, sopt = 1, i;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;
    ws_ctx_t *ws_ctx;


    /* Initialize buffers */
    lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (lsock < 0) { error("ERROR creating listener socket"); }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(settings.listen_port);

    /* Resolve listen address */
    if (settings.listen_host && (settings.listen_host[0] != '\0')) {
        if (resolve_host(&serv_addr.sin_addr, settings.listen_host) < -1) {
            fatal("Could not resolve listen address");
        }
    } else {
        serv_addr.sin_addr.s_addr = INADDR_ANY;
    }

    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char *)&sopt, sizeof(sopt));
    if (bind(lsock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        fatal("ERROR on binding listener socket");
    }
    listen(lsock,100);

    signal(SIGPIPE, signal_handler);  // catch pipe

    if (settings.daemon) {
        daemonize(lsock);
    }


    // Reep zombies
    signal(SIGCHLD, SIG_IGN);

    printf("Waiting for connections on %s:%d\n",
            settings.listen_host, settings.listen_port);

    while (1) {
        clilen = sizeof(cli_addr);
        pipe_error = 0;
        pid = 0;
        csock = accept(lsock,
                       (struct sockaddr *) &cli_addr,
                       &clilen);
        if (csock < 0) {
            error("ERROR on accept");
            continue;
        }
        handler_msg("got client connection from %s\n",
                    inet_ntoa(cli_addr.sin_addr));

        if (!settings.run_once) {
            handler_msg("forking handler process\n");
            pid = fork();
        }

        if (pid == 0) {  // handler process
            ws_ctx = do_handshake(csock);
            if (settings.run_once) {
                if (ws_ctx == NULL) {
                    // Not a real WebSocket connection
                    continue;
                } else {
                    // Successful connection, stop listening for new
                    // connections
                    close(lsock);
                }
            }
            if (ws_ctx == NULL) {
                handler_msg("No connection after handshake\n");
                break;   // Child process exits
            }

            settings.handler(ws_ctx);
            if (pipe_error) {
                handler_emsg("Closing due to SIGPIPE\n");
            }
            break;   // Child process exits
        } else {         // parent process
            settings.handler_id += 1;
            close(csock);
        }
    }
    if (pid == 0) {
        if (ws_ctx) {
            ws_socket_free(ws_ctx);
            free_ws_ctx(ws_ctx);
        } else {
            shutdown(csock, SHUT_RDWR);
            close(csock);
        }
        handler_msg("handler exit\n");
    } else {
        handler_msg("websockify exit\n");
    }

}
