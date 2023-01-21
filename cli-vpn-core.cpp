#include "cli-vpn-core.h"

#include <vector>

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
