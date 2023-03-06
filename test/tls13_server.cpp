#include "tcp_ip.h"

int main() {
    TCP_IP::MIDDLE sv{4433};
    sv.start();
    return 0;
}