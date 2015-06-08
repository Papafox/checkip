/*************************************************************************\
*                  Copyright (C) Michael Kerrisk, 2015.                   *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU Lesser General Public License as published   *
* by the Free Software Foundation, either version 3 or (at your option)   *
* any later version. This program is distributed without any warranty.    *
* See the files COPYING.lgpl-v3 and COPYING.gpl-v3 for details.           *
\*************************************************************************/

/* pidfile.h

   Header file for pidfile.c.
*/
#ifndef PIDFILE_H   /* Prevent accidental double inclusion */
#define PIDFILE_H

#include <sys/types.h>

#define CPF_CLOEXEC 1

int createPidFile(const char *progName, const char *pidFile, int flags);

int lockRegion(int fd, int type, int whence, int start, int len);

#endif

