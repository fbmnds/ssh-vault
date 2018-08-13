#ifndef __SSH_ADD_H__
#define __SSH_ADD_H__

#include <HsFFI.h>

int
ssh_add
    ( char *const duration
    , char *const path
    , char *const expect
    , char *const answer
    );
#endif

