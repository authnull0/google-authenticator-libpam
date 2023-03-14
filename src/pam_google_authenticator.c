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
#include <curl/curl.h>
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

#include "base32.h"
#include "hmac.h"
#include "sha1.h"
#include "util.h"
#include <curl/curl.h>


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
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED_ATTR,
                int flags UNUSED_ATTR,
                int argc UNUSED_ATTR,
                const char **argv UNUSED_ATTR) {
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC
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

int google_authenticator(pam_handle_t *pamh,
 		int argc, const char **argv) {
log_message(LOG_INFO,pamh,"Customized pam to invoke DID ");
//const char* const username = get_user_name(pamh, &params);

 char cwd[PATH_MAX];
   if (getcwd(cwd, sizeof(cwd)) != NULL) {
       log_message(LOG_INFO,pamh,"Current working dir: %s\n", cwd);
   }
char line[LINE_BUFSIZE];
    int linenr;
    FILE *output;
char *s;
    log_message(LOG_INFO,pamh,"Starting DID Assertion");
output =popen("/bin/bash ${cwd}/did.sh", "r");// update this location based on user path , and copy the script inside src/ to user path (if reqd)
    
if (output == NULL){
	log_message(LOG_INFO,pamh,"POPEN: Failed to execute");
}
else {
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
    

    
return PAM_AUTH_ERR;//this should be PAM_AUTH_ERR when running , make it SUCCESS to login ssh user temporarily
 }


