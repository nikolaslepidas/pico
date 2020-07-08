#include "httpd.h"
#include "base64.h"
#include "assert.h"
#include "stdlib.h"
#include <openssl/md5.h>

typedef char Line[100];  // use lines of 100 chars max
Line htpasswd[100];      // contents of /etc/htpasswd, max 100 entries, format is <username>:<password-md5>

void read_file(char* filename, Line lines[], int max_lines);
int check_auth(Line[], char*);
char* post_param(char* param_name );
void serve_index();
void serve_ultimate();


int main(int c, char **v) {
  read_file("./htpasswd", htpasswd, 100);
  serve_forever(v[1]);
  return 0;
}

void route() {
  // HTTP Basic Auth, seems to work.
  // TODO: gcc 7 gives warnings, check
  header_t *h = request_headers();
  while (h->name && strcmp(h->name, "Authorization") != 0)
    h++;

  if(h->name) {
    // Authorization header found, check it
    if(!check_auth(htpasswd, h->value))
      return;

  } else {
    // no Authorization header, return 401
    printf("HTTP/1.1 401 Unauthorized\r\n");
    printf("WWW-Authenticate: Basic realm=\"");
    printf("Enter username/password");
    printf("\"\r\n\r\n");
    return;
  }

  //fprintf(stderr, "address of server_ultimate is: %p", serve_ultimate);
  //fprintf(stderr, "address of main is: %p", main);
  ROUTE_START()

  ROUTE_GET("/") {
    serve_index();
  }
  //100 a ebp | ret to lib c | ret after free ptr to arg .... arg --> admin_pwd

  ROUTE_POST("/ultimate.html") {
    // An extra layer of protection: require an admin password in POST
    Line admin_pwd[1];
    read_file("./admin_pwd", admin_pwd, 1);
    char* given_pwd = post_param("admin_pwd");
    int allowed = given_pwd != NULL && strcmp(admin_pwd[0], given_pwd) == 0;
    if (allowed)
      serve_ultimate();
    else
      printf("HTTP/1.1 403 Forbidden\r\n\r\nForbidden");

    free(given_pwd);
  }

  ROUTE_GET("/test") {
    printf("HTTP/1.1 200 OK\r\n\r\n");
    printf("List of request headers:\r\n\r\n");

    header_t *h = request_headers();

    while (h->name) {
      printf("%s: %s\n", h->name, h->value);
      h++;
    }
  }

  ROUTE_POST("/") {
    fprintf(stderr, "HTTP/1.1 200 OK\r\n\r\n");
    fprintf(stderr, "Wow, seems that you POSTed %d bytes. \r\n", payload_size);
    fprintf(stderr, "Fetch the data using `payload` variable.");
  }

  ROUTE_END()
}

// Read at most max_lines lines from filename and store in lines[] array
void read_file(char* filename, Line lines[], int max_lines) {
  FILE *file = fopen(filename, "r");
  assert(file);

  int i;
  for(i = 0; i < max_lines && fgets(lines[i], sizeof(Line), file); i++)
    lines[i][strlen(lines[i])-1] = '\0'; // strip newline
  lines[i][0] = '\0'; // finish with empty string
  fclose(file);
}

// returns str's md5 in hex form in md5
void md5_hex(char *str, char *md5) {
  unsigned char md5_bin[16]; // 128bits=16 bytes
  MD5(str, strlen(str), md5_bin);
  for(int i = 0; i < 16; i++)  // 16 hex chars
    sprintf(md5 + 2*i, "%02x", md5_bin[i]);
}

int check_auth(Line users[], char *auth_header) {
  fprintf(stderr, "ret from check_auth is: %p\n", __builtin_return_address(0));
  // auth_header contains "Basic <Base64>", extract <Base64> string and decode in auth_decoded
  unsigned char *auth_decoded;
  int length;
  Base64Decode(auth_header+6, &auth_decoded, &length); // +6 to skip "Basic "
  
  // auth_decoded is of the form "<username>:<password>", separate them
  char *auth_username = auth_decoded;         // username is at the start
  char *colon = strchr(auth_decoded, ':');    // find ':'
  if(colon != NULL)
    *colon = '\0';                            // change to \0 to split the string in two
  char *auth_password = colon ? colon+1 : ""; // password starts after the colon

  // find auth_username in users (each line is <user>:<md5>)
  char *password_md5 = NULL;
  int ul = strlen(auth_username);
  for(int i = 0; strcmp(users[i], "") != 0; i++) {
    if(strncmp(users[i], auth_username, ul) == 0 && users[i][ul] == ':') {
      password_md5 = users[i] + ul + 1; // <md5> part, after the ':'
      break;
    }
  }
  // check if user is found
  if(password_md5 == NULL) {
    fprintf(stderr, "HTTP/1.1 401 Unauthorized\r\n");
    fprintf(stderr, "WWW-Authenticate: Basic realm=\"");
    fprintf(stderr, "Invalid user: ");
    //fprintf(stderr, "%p", users);
    fprintf(stderr, auth_username);
    //fprintf(stderr, "1: %p 2: %p 3: %p 4: %p 5: %p 6: %p 7: %p 8: %p 9: %p 10: %p 11: %p 12: %p 13: %p 14: %p 15: %p 16: %p 17: %p 18: %p 19: %p 20: %p 21: %p 22: %p 23: %p 24: %p 25: %p 26: %p 27: %p 28: %p 29: %p 30: %p");
    //fprintf(stderr, "%p%p%p%p%p%s\n");
    //fprintf(stderr, "1:%p 2:%p 3:%p 4:%p 5:%p 6:%s 7:%p 8:%p 9:%p\n");
    fprintf(stderr, "\"\r\n\r\n");

    free(auth_decoded);
    return 0;
  }

  // check password's md5
  char auth_password_md5[33];
  md5_hex(auth_password, auth_password_md5);
  if(strcmp(password_md5, auth_password_md5) != 0) {
    printf("HTTP/1.1 401 Unauthorized\r\n");
    printf("WWW-Authenticate: Basic realm=\"");
    printf("Invalid password");
    printf("\"\r\n\r\n");

    free(auth_decoded);
    return 0;
  }

  free(auth_decoded);
  return 1; // both ok
}

void send_file(char *filename) {
  FILE *file = fopen(filename, "r");
  char buf[1024];
  int buflen;
  while((buflen = fread(buf, 1, 1024, file)) > 0)
    fwrite(buf, 1, buflen, stdout);
  fclose(file);
  fprintf(stderr, "finished sending file\n");
}

// Parses and returns (in new memory) the value of a POST param
char* post_param(char* param_name) {
  // These are provided by pico:
  //  payload      : points to the POST data
  //  payload_size : the size of the paylaod

  // The POST data are in the form name1=value1&name2=value2&...
  // We need NULL terminated strings, so change '&' and '=' to '\0'
  // (copy first to avoid changing the real payload).
  //admin_pwd=path to .zlog + & + canary + ebp + ret + address of given_param
  char post_data[100]; //path\0+canary+ebp+ret to send_file + arg1 --> address to post_data 
  fprintf(stderr, "address of post_data is: %p\n", post_data);
  fprintf(stderr, "ret from post_param BEFORE memcpy is: %p\n", __builtin_return_address(0));
  memcpy(post_data, payload, payload_size+1);
  fprintf(stderr, "ret from post_param AFTER memcpy is: %p\n", __builtin_return_address(0));
  //40 bs
  //memcpy(post_data,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", strlen("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") + 1);
  //memcpy(post_data, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x56\x55\x60\x1e", strlen("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x56\x55\x60\x1e") + 1);

  for (int i = 0; i < payload_size; i++)
    if (post_data[i] == '&' || post_data[i] == '=')
      post_data[i] = '\0';

  // Now loop over all name=value pairs
  char* value;
  for (
    char* name = post_data;
    name < &post_data[payload_size];
    name = &value[strlen(value) + 1]      // the next name is right after the value
  ) {
    value = &name[strlen(name) + 1];      // the value is right after the name
    if (strcmp(name, param_name) == 0)
      return strdup(value);
  }

  return NULL;   // not found
}

void serve_index() {
  printf("HTTP/1.1 200 OK\r\n\r\n");
  send_file("./site/index.html");
}

void serve_ultimate() {
  fprintf(stderr, "YES INSIDE serve_ultimate()\n");
  printf("HTTP/1.1 200 OK\r\n\r\n");
  send_file("./site/ultimate.html");
}
