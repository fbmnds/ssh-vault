#ifndef __SSH_ADD_H__
#define __SSH_ADD_H__

#define _XOPEN_SOURCE 600
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#define __USE_BSD
#include <termios.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <string.h>
#include <string.h>

#include <HsFFI.h>

int
ssh_add
    ( char *const duration
    , char *const path
    , char *const expect
    , char *const answer
    );

#endif
