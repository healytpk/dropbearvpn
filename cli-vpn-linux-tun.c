#include <string.h>          // strncpy, memset
#include <sys/ioctl.h>       // ioctl
#include <fcntl.h>           // open
#include <linux/if.h>        // ifreq
#include <linux/if_tun.h>
#include <unistd.h>          // close
#include <sys/socket.h>      // socket
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>       // htonl

#define nullptr (0)

static int setip(int const fd, char const *const str_dev, char const *const str_ip)
{
    struct ifreq ifr = {0};
    struct sockaddr_in addr = {0};
    char buff[64u] = {0};
    int retval = -1;

    strncpy(ifr.ifr_name, str_dev, IFNAMSIZ);

    addr.sin_family = AF_INET;
    int const s = socket(addr.sin_family, SOCK_DGRAM, 0);
    if ( -1 == s ) return -1;

    if ( 1 != inet_pton(addr.sin_family, str_ip, &addr.sin_addr) ) goto End;

    ifr.ifr_addr = *(struct sockaddr*)&addr;

    /* Next line is just to test if address conversion happened properly */
    if ( nullptr == inet_ntop(AF_INET, &addr.sin_addr, buff, 64u) ) goto End;

    if ( -1 == ioctl(s, SIOCSIFADDR, &ifr) ) goto End;

    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, str_dev, IFNAMSIZ);
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr = htonl(0xFFFFFF00);
    ioctl(s, SIOCSIFNETMASK, &ifr);

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, str_dev, IFNAMSIZ);
    ifr.ifr_flags |= IFF_UP;
    if ( -1 == ioctl(s, SIOCSIFFLAGS, &ifr) ) goto End;

    //wipe_out_ipv6(fd,str_dev);

    retval = fd;

End:
    if ( -1 != s ) close(s);
    return retval;
}

int tun_alloc(void)
{
    struct ifreq ifr = {0};
    int fd, err;

    if ( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) return fd;

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if ( (err = ioctl(fd, TUNSETIFF, &ifr)) < 0 )
    {
        close(fd);
        return err;
    }

    if ( -1 == setip(fd, ifr.ifr_name, "10.10.10.1") )
    {
        close(fd);
        fd = -1;
    }

    return fd;
}
