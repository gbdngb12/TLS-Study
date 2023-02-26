#include "tcp_ip.h"
#include <iostream>

int main() {
    TCP_IP::Client cl{"localhost", 2002};
    cl.send("GET /");
    std::cout << *cl.recv() << std::endl;
}