#pragma once

#include "pcap.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <Windows.h>

namespace iw
{
    inline std::string myIptos(ULONG ipAdress)
    {
        return "";
    }

    inline std::string myIp6tos(sockaddr* ipAdress, char* returnVal, int size)
    {
        return "";
    }

    struct devReturnValues
    {
        devReturnValues(int result, pcap_if_t* ptrDevices) : _result(result), _ptrDevices(ptrDevices) {}
        int _result;
        pcap_if_t* _ptrDevices;
	};

    inline const devReturnValues discoverInterfaces()
    {
        pcap_if_t* alldevs;
        pcap_if_t* d;
        int i = 0;
        char errbuf[PCAP_ERRBUF_SIZE];

        /* Retrieve the device list from the local machine */
        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
            NULL /* auth is not needed */,
            &alldevs, errbuf) == -1)
        {
            fprintf(stderr,
                "Error in pcap_findalldevs_ex: %s\n",
                errbuf);
            exit(1);
        }

        /* Print the list */
        for (d = alldevs; d != NULL; d = d->next)
        {
            printf("%d. %s", ++i, d->name);
            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }

        if (i == 0)
        {
            printf("\nNo interfaces found! Make sure Npcap is installed.\n");
            return devReturnValues(1, nullptr);
        }

        /* We don't need any more the device list. Free it */
        pcap_freealldevs(alldevs);
        return devReturnValues(0, alldevs);
    }

    inline const void advancedDevInformations(pcap_if_t* d)
    {
        pcap_addr_t* a;
        char ip6str[128];

        /* Name */
        printf("%s\n", d->name);

        /* Description */
        if (d->description)
            printf("\tDescription: %s\n", d->description);

        /* Loopback Address*/
        printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

        /* IP addresses */
        for (a = d->addresses; a; a = a->next) {
			printf("\tAddress Family: #%d\n", a->addr->sa_family);

            switch (a->addr->sa_family)
            {
            case AF_INET:
                printf("\tAddress Family Name: AF_INET\n");
                if (a->addr)
                    printf("\tAddress: %s\n", myIptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr).c_str());
                if (a->netmask)
                    printf("\tNetmask: %s\n", myIptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr).c_str());
                if (a->broadaddr)
                    printf("\tBroadcast Address: %s\n", myIptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr).c_str());
                if (a->dstaddr)
                    printf("\tDestination Address: %s\n", myIptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr).c_str());
                break;

            case AF_INET6:
                printf("\tAddress Family Name: AF_INET6\n");
                if (a->addr)
                    printf("\tAddress: %s\n", myIp6tos(a->addr, ip6str, sizeof(ip6str)).c_str());
                break;

            default:
                printf("\tAddress Family Name: Unknown\n");
                break;
            }
        }
        printf("\n");
	}
}
// Make a networkUtils file and move them there
///* From tcptraceroute, convert a numeric IP address to a string */
//#define IPTOSBUFFERS    12
//char* iptos(u_long in)
//{
//    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
//    static short which;
//    u_char* p;
//
//    p = (u_char*)&in;
//    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
//    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
//    return output[which];
//}
//
//char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen)
//{
//    socklen_t sockaddrlen;
//
//#ifdef WIN32
//    sockaddrlen = sizeof(struct sockaddr_in6);
//#else
//    sockaddrlen = sizeof(struct sockaddr_storage);
//#endif
//
//
//    if (getnameinfo(sockaddr,
//        sockaddrlen,
//        address,
//        addrlen,
//        NULL,
//        0,
//        NI_NUMERICHOST) != 0) address = NULL;
//
//    return address;
//}
