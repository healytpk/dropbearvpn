#include "cli-vpn-core.h"

#include <iostream>  // cout, endl
#include <vector>
#include <unistd.h>  // read, close

#include "frame.h"     // OFFSET_IP_SRC
#include "checksum.h"  // IsValidIP4

#include <boost/asio/ip/address_v4.hpp>

using std::cout; using std::endl;

extern "C" void dropbear_exit(const char* format, ...) __attribute__((format(printf,1,2))) __attribute__((noreturn)); // defined in dbutil.c

namespace VPN {

bool ParseNetworks(int const a, int const b)
{
    // This is just preliminary test code to see if
    // the SSH client program called 'dbclient' links
    // properly with the libstdc++

    std::vector<int> v;

    for (int i = 0u; i != a; ++i) v.emplace_back(b);

    return v.front() == v.back();
}

}  // close namespace 'VPN'

extern "C" bool VPN_ParseNetworks(int const a, int const b) { return VPN::ParseNetworks(a,b); }

extern "C" int VPN_ThreadEntryPoint_ListenToTun(void *const arg)
{
    int const tun_fd = *static_cast<int*>(arg);

    char unsigned buffer[65535u];

    /* Now read data coming from the kernel */
    for (;;)
    {
        /* Note that "buffer" should be at least the MTU size of the interface, eg 1500 bytes */
        int const nread = read(tun_fd,buffer,sizeof buffer);

        if ( nread < 0 )
        {
            close(tun_fd);
            dropbear_exit("Error encountered when reading from tun device");
        }

        /* Do whatever with the data */
        cout << "Read " << nread << " bytes from TUN device:" << endl;

/*
        for ( int i = 0; i < nread; ++i )
        {
            static char const hex[] = "0123456789abcdef";
            cout << hex[ 0xF & (buffer[i] >> 4u) ]
                 << hex[ 0xF & (buffer[i] >> 0u) ];
        }
*/
        if ( !IsValidIP4(buffer,buffer + nread) )
        {
            cout << "Invalid IPv4 Packet" << endl;
            continue;
        }

        uint32_t ip_src = Get32(buffer + OFFSET_IP_SRC),
                 ip_dst = Get32(buffer + OFFSET_IP_DST);

        using boost::asio::ip::address_v4;

        cout << "    From " << address_v4(ip_src).to_string() << " to " << address_v4(ip_dst).to_string();

        uint8_t const *p_trp = nullptr;

        switch ( buffer[OFFSET_IP_PROTO] ) /* This is OK coz it's 8-Bit */
        {
        case 0x01: cout << " - ICMP"; break;
        case 0x06:

            cout << " - TCP";

            if ( !IsValidIP4_TCP(buffer,buffer + nread) )
            {
                cout << " - invalid segment" << endl;
                continue;
            }

            /* Get a pointer to the start of the segment */
            p_trp = buffer + GetIP4HeaderLen(buffer);

            cout << " from port " << Get16(p_trp+OFFSET_TCP_SRC) << " to port " << Get16(p_trp+OFFSET_TCP_DST);
            break;

        case 0x11:

            cout << " - UDP";

            if ( !IsValidIP4_UDP(buffer,buffer + nread) )
            {
                cout << " - invalid datagram" << endl;
                continue;
            }

            /* Get a pointer to the start of the datagra */
            p_trp = buffer + GetIP4HeaderLen(buffer);

            cout << " from port " << Get16(p_trp+OFFSET_UDP_SRC) << " to port " << Get16(p_trp+OFFSET_UDP_DST);
            break;
        }

        cout << endl;
    }
}
