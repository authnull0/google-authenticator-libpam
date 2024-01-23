// PAM module for two-factor authentication.
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>

#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h> /* struct hostent, gethostbyname */
#ifdef HAVE_SYS_FSUID_H
// We much rather prefer to use setfsuid(), but this function is unfortunately
// not available on all systems.
#include <sys/fsuid.h>
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/_pam_macros.h>


#include "base32.h"
#include "hmac.h"
#include "sha1.h"
#include "util.h"



// Module name shortened to work with rsyslog.
// See https://github.com/google/google-authenticator-libpam/issues/172
#define MODULE_NAME   "pam_google_auth"

#define SECRET        "~/.google_authenticator"
#define CODE_PROMPT   "Verification code: "
#define PWCODE_PROMPT "Password & verification code: "
#define LINE_BUFSIZE 128
typedef struct Params {
  const char *secret_filename_spec;
  const char *authtok_prompt;
  enum { NULLERR=0, NULLOK, SECRETNOTFOUND } nullok;
  int        noskewadj;
  int        echocode;
  int        fixed_uid;
  int        no_increment_hotp;
  uid_t      uid;
  enum { PROMPT = 0, TRY_FIRST_PASS, USE_FIRST_PASS } pass_mode;
  int        forward_pass;
  int        debug;
  int        no_strict_owner;
  int        allowed_perm;
  time_t     grace_period;
  int        allow_readonly;
} Params;

static char oom;

static const char* nobody = "nobody";

#if defined(DEMO) || defined(TESTING)
static char* error_msg = NULL;

const char *get_error_msg(void) __attribute__((visibility("default")));
const char *get_error_msg(void) {
  if (!error_msg) {
    return "";
  }
  return error_msg;
}
#endif


#define ENV_ITEM(n) { (n), #n }
static struct {
  int item;
  const char *name;
} env_items[] = {
  ENV_ITEM(PAM_SERVICE),
  ENV_ITEM(PAM_USER),
  ENV_ITEM(PAM_TTY),
  ENV_ITEM(PAM_RHOST),
  ENV_ITEM(PAM_RUSER),
};

/* move_fd_to_non_stdio copies the given file descriptor to something other
 * than stdin, stdout, or stderr.  Assumes that the caller will close all
 * unwanted fds after calling. */
static int
move_fd_to_non_stdio (pam_handle_t *pamh, int fd)
{
  while (fd < 3)
    {
      fd = dup(fd);
      if (fd == -1)
	{
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "dup failed: %m");
	  _exit (err);
	}
    }
  return fd;
}


static void log_message(int priority, pam_handle_t *pamh,

                        const char *format, ...) {
  char *service = NULL;
  if (pamh)
    pam_get_item(pamh, PAM_SERVICE, (void *)&service);
  if (!service)
    service = "";

  char logname[80];
  snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

  va_list args;
  va_start(args, format);
#if !defined(DEMO) && !defined(TESTING)
  openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  vsyslog(priority, format, args);
  closelog();
#else
  if (!error_msg) {
    error_msg = strdup("");
  }
  {
    char buf[1000];
    vsnprintf(buf, sizeof buf, format, args);
    const int newlen = strlen(error_msg) + 1 + strlen(buf) + 1;
    char* n = malloc(newlen);
    if (n) {
      snprintf(n, newlen, "%s%s%s", error_msg, strlen(error_msg)?"\n":"",buf);
      free(error_msg);
      error_msg = n;
    } else {
      fprintf(stderr, "Failed to malloc %d bytes for log data.\n", newlen);
    }
  }
#endif

  va_end(args);

  if (priority == LOG_EMERG) {
    // Something really bad happened. There is no way we can proceed safely.
    _exit(1);
  }
}


#ifndef UNUSED_ATTR
# if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
#  define UNUSED_ATTR __attribute__((__unused__))
# else
#  define UNUSED_ATTR
# endif
#endif

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED_ATTR,
                                   int argc, const char **argv) {
return google_authenticator(pamh, argc, argv);
//return call_exec ("auth", pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED_ATTR,
                int flags UNUSED_ATTR,
                int argc UNUSED_ATTR,
                const char **argv UNUSED_ATTR) {
  return PAM_SUCCESS;
}

#ifdef PAM_STATC
struct pam_module _pam_listfile_modstruct = {
  MODULE_NAME,
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};
#endif
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
//function definition
int myStrStr(char* str, char* sub)
{
    int flag = 0;

    int i = 0, len1 = 0, len2 = 0;

    len1 = strlen(str);
    len2 = strlen(sub);

    while (str[i] != '\0') {
        if (str[i] == sub[0]) {
            if ((i + len2) > len1)
                break;

            if (strncmp(str + i, sub, len2) == 0) {
                flag = 1;
                break;
            }
        }
        i++;
    }

    return flag;
}



// return the user name in heap-allocated buffer.
// Caller frees.
static const char *getUserName(uid_t uid) {
  struct passwd pwbuf, *pw;
  char *buf;
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len = 4096;
  #endif
  buf = malloc(len);
  char *user;
  if (getpwuid_r(uid, &pwbuf, buf, len, &pw) || !pw) {
    user = malloc(32);
    snprintf(user, 32, "%d", uid);
  } else {
    user = strdup(pw->pw_name);
    if (!user) {
      perror("malloc()");
      _exit(1);
    }
  }
  free(buf);
  return user;
}

int google_authenticator(pam_handle_t *pamh,
 		int argc, const char **argv) {
  log_message(LOG_INFO,pamh,"Customized pam to invoke DID ");
  //const char* const username = get_user_name(pamh, &params);
  int pam_err;
    register struct passwd *pw;
    //register uid_t uid;
  char *user = NULL;
  char *host = NULL;
  char *service = NULL;
  const uid_t uid = getuid();
  int retval;
  //const char *user = getUserName(uid);
  /* identify user */
  bool userExistLocallyFlag = false;
  retval = pam_get_user(pamh, &user, NULL);
  if (retval != PAM_SUCCESS) {
    log_message(LOG_INFO,pamh,"retval",retval);
  }

  struct passwd *pwd = getpwnam(user);
  if (pwd != NULL) {
    userExistLocallyFlag = true;
    printf("User %s does not exist.\n", user);
  }
  log_message(LOG_INFO,pamh,"retvalusere %s",user);


  char cwd[PATH_MAX];
  if (getcwd(cwd, sizeof(cwd)) != NULL) {
    log_message(LOG_INFO,pamh,"Current working dir: %s\n", cwd);
  }


//CURL *curl;
 // CURLcode res;
  //char url[]= "https://api.did.kloudlearn.com/authnull0/api/v1/authn/do-authentication";
  //char postData[] = "username=newuser&password=newpasswd&msg=test&msisdn=9999999999&tagname=Demo&shortcode=8888&telcoId=5&dnRequired=false";
  //char* jsonObj = "{ \"username\" : \'user\' , \"responseType\" : \"ssh\" }";
  
//log_message(LOG_INFO,pamh,"curl req to be sent",jsonObj);
  //struct curl_slist *headers = NULL;
    //curl_slist_append(headers, "Accept: application/json");
    //curl_slist_append(headers, "Content-Type: application/json");
    //curl_slist_append(headers, "charset: utf-8");

  //curl = curl_easy_init();
  //if(curl) {
   // curl_easy_setopt(curl, CURLOPT_URL, url);
    //curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    //curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonObj);
   //curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,50);
   // res = curl_easy_perform(curl);
    
   // log_message(LOG_INFO,pamh,"Invoking lib curl fetching the resp",res);
   // curl_easy_cleanup(curl);

  //}
  char line[LINE_BUFSIZE];
  int linenr;
  FILE *output;
  char *s;
  char *requestId = NULL;
  log_message(LOG_INFO,pamh,"Starting DID Assertion");

  char command[100];
  int len;

  if(userExistLocallyFlag) {
    len = snprintf(command, sizeof(command), "/bin/bash ${cwd}/did.sh %s",user);
    output =popen(command, "r");// update this location based on user path , and copy the script inside src/ to user path (if reqd)
  
    if (output == NULL){
      log_message(LOG_INFO,pamh,"POPEN: Failed to execute");
    } else {
      int count =1;
      char *response;
      int res = 0;
      // Delimiter
      const char delimiter = '=';
      while (fgets(line, LINE_BUFSIZE-1, output) != NULL){
        log_message(LOG_INFO,pamh,"Execution Result %s", line);
        s = myStrStr(line,"");
        if (s){
          log_message(LOG_INFO,pamh,"Authentication First Stage Successful !%d",s);
          printf("Copy paste the URL and login: %s\n", line);
          // Check if there is a second token
          if (response != NULL) {
              char **arr = NULL;
              // Get the second token
              res = split(line, '=',&arr);

              requestId = arr[1];
          } else {
              printf("There is no first item.\n");
          }
          break;
        }
      }
    }
    
    len = snprintf(command, sizeof(command), "/bin/bash ${cwd}/did-2.sh %s", requestId);
    output =popen(command, "r");// update this location based on user path , and copy the script inside src/ to user path (if reqd)
  
    if (output == NULL){
      log_message(LOG_INFO,pamh,"POPEN: Failed to execute");
    } else {
      int count =1;

      while (fgets(line, LINE_BUFSIZE-1, output) != NULL){
        log_message(LOG_INFO,pamh,"Execution Result %s", line);
        s = myStrStr(line,"\"isValid\"\:true");
        if (s){
          log_message(LOG_INFO,pamh,"DID Authentication Successful !%d",s);
          return PAM_SUCCESS;
        }
      }
    }
    log_message(LOG_INFO,pamh,"No Credential Retrieved , Authentication Failure");
    pclose(output);

    log_message(LOG_INFO,pamh,"Do Authentication DID Complete, Pls check /var/log/auth.log for more information");
    
  } else {
    len = snprintf(command, sizeof(command), "/bin/bash ${cwd}/fetchUser.sh %s",user);
    output =popen(command, "r");// update this location based on user path , and copy the script inside src/ to user path (if reqd)
  
    if (output == NULL){
      log_message(LOG_INFO,pamh,"POPEN: Failed to execute");
    } else {
      int count =1;

      while (fgets(line, LINE_BUFSIZE-1, output) != NULL){
        log_message(LOG_INFO,pamh,"Execution Result %s", line);
        s = myStrStr(line, user);
        if (s){
          log_message(LOG_INFO,pamh,"DID Authentication Successful !%d",s);
          return PAM_SUCCESS;
        }
      }
    }
    log_message(LOG_INFO,pamh,"No Credential Retrieved , Authentication Failure");
    pclose(output);

    log_message(LOG_INFO,pamh,"Do Authentication DID Complete, Pls check /var/log/auth.log for more information");
    
  }
    
    return PAM_SUCCESS;//this should be PAM_AUTH_ERR when running , make it SUCCESS to login ssh user temporarily
}

int split (char *str, char c, char ***arr)
{
    int count = 1;
    int token_len = 1;
    int i = 0;
    char *p;
    char *t;

    p = str;
    while (*p != '\0')
    {
        if (*p == c)
            count++;
        p++;
    }

    *arr = (char**) malloc(sizeof(char*) * count);
    if (*arr == NULL)
        exit(1);

    p = str;
    while (*p != '\0')
    {
        if (*p == c)
        {
            (*arr)[i] = (char*) malloc( sizeof(char) * token_len );
            if ((*arr)[i] == NULL)
                exit(1);

            token_len = 0;
            i++;
        }
        p++;
        token_len++;
    }
    (*arr)[i] = (char*) malloc( sizeof(char) * token_len );
    if ((*arr)[i] == NULL)
        exit(1);

    i = 0;
    p = str;
    t = ((*arr)[i]);
    while (*p != '\0')
    {
        if (*p != c && *p != '\0')
        {
            *t = *p;
            t++;
        }
        else
        {
            *t = '\0';
            i++;
            t = ((*arr)[i]);
        }
        p++;
    }

    return count;
}