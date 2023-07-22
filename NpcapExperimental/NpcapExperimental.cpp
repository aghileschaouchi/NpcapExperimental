#include "pcap.h"

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <Windows.h>

#include "InterfaceWrapper.h"

int main()
{
    iw::devReturnValues interfaces = iw::discoverInterfaces();

    return 0;
}