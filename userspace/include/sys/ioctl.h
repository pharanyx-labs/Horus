/*
 * <sys/ioctl.h> for the Horus userspace libc — just enough for a curses program
 * to learn the console geometry. TIOCGWINSZ maps to the console_server's
 * CON_OP_WINSZ (see userspace/posix.c); other requests fail with -1.
 */
#ifndef _HORUS_SYS_IOCTL_H
#define _HORUS_SYS_IOCTL_H

struct winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};

#define TIOCGWINSZ 0x5413

int ioctl(int fd, unsigned long request, ...);

#endif /* _HORUS_SYS_IOCTL_H */
