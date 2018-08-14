#ifndef __G_AUTH_H__
#define __G_AUTH_H__

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

#include <HsFFI.h>

int g_auth(char *const un);

static struct pam_conv conv = {
    misc_conv,
    NULL
};

#endif
