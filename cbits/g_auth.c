/*

  http://www.linux-pam.org/Linux-PAM-html/adg-example.html

  /etc/pam.d/ssh_vault:
  # check authorization
  auth       required     pam_google_authenticator.so
  account    required     pam_permit.so

  $ gcc -c -Wall -Werror -fpic g_auth.c
  $ gcc -shared -o g_auth.so g_auth.o

 */



#include "g_auth.h"


int g_auth(char *user)
{
    pam_handle_t *pamh=NULL;
    int retval;

    retval = pam_start("ssh-vault", user, &conv, &pamh);

    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, 0);    /* is user really user? */

    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */

    /* This is where we have been authorized or not. */

    if (retval == PAM_SUCCESS) {
        fprintf(stdout, "Authenticated\n");
    } else {
        fprintf(stdout, "Not Authenticated\n");
    }

    if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
        pamh = NULL;
        fprintf(stderr, "check_user: failed to release authenticator\n");
        exit(1);
    }

    return ( retval == PAM_SUCCESS ? 0:1 );       /* indicate success */
}