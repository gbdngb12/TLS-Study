//#include <catch2/catch_all.hpp>
#include "tcp_ip.h"
#include <iostream>
#include <string>
int main() {
    TCP_IP::Server sv{2002};
    sv.start([](std::string s) {return "Learn cryptography by implementing TLS";});
}