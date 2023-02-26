#include "tcp_ip.h"
#include "service.h"

int SERVICE::Func::count = 0;

int main() {
    TCP_IP::TLS_SERVER sv{3000};
    SERVICE::Func func;
    sv.start(func);
}