/*
 * <sys/termios.h> for the Horus userspace libc.
 *
 * Horus's newlib build ships no termios; this supplies the minimal POSIX surface
 * a curses library (and nano) needs to put the console into raw mode. The console
 * is a real VT/ANSI terminal on the serial line, driven by the ring-3
 * console_server. tcsetattr()'s only effect that matters here is switching the
 * console between cooked (line-edited, echoed) and raw (byte-at-a-time, no echo)
 * mode; the implementation lives in userspace/posix.c.
 */
#ifndef _HORUS_SYS_TERMIOS_H
#define _HORUS_SYS_TERMIOS_H

typedef unsigned int   tcflag_t;
typedef unsigned char  cc_t;
typedef unsigned int   speed_t;

#define NCCS 20

struct termios {
    tcflag_t c_iflag;   /* input modes   */
    tcflag_t c_oflag;   /* output modes  */
    tcflag_t c_cflag;   /* control modes */
    tcflag_t c_lflag;   /* local modes   */
    cc_t     c_cc[NCCS];/* control chars  */
    speed_t  c_ispeed;
    speed_t  c_ospeed;
};

/* c_iflag */
#define IGNBRK  0x0001
#define BRKINT  0x0002
#define ICRNL   0x0004
#define INLCR   0x0008
#define ISTRIP  0x0010
#define IXON    0x0020
/* c_oflag */
#define OPOST   0x0001
#define ONLCR   0x0002
/* c_cflag */
#define CS8     0x0001
#define CREAD   0x0002
#define CLOCAL  0x0004
/* c_lflag */
#define ISIG    0x0001
#define ICANON  0x0002
#define ECHO    0x0004
#define ECHOE   0x0008
#define ECHONL  0x0010
#define IEXTEN  0x0020
#define NOFLSH  0x0040

/* c_cc indices */
#define VMIN    0
#define VTIME   1
#define VINTR   2
#define VQUIT   3
#define VERASE  4
#define VEOF    5

/* tcsetattr actions */
#define TCSANOW   0
#define TCSADRAIN 1
#define TCSAFLUSH 2

/* tcflush queue selectors */
#define TCIFLUSH  0
#define TCOFLUSH  1
#define TCIOFLUSH 2

/* baud (nominal; the serial line is fixed, these are accepted and ignored) */
#define B9600   9600
#define B38400  38400

int      tcgetattr(int fd, struct termios *t);
int      tcsetattr(int fd, int actions, const struct termios *t);
int      tcflush(int fd, int queue);
void     cfmakeraw(struct termios *t);
speed_t  cfgetispeed(const struct termios *t);
speed_t  cfgetospeed(const struct termios *t);
int      cfsetispeed(struct termios *t, speed_t s);
int      cfsetospeed(struct termios *t, speed_t s);

#endif /* _HORUS_SYS_TERMIOS_H */
