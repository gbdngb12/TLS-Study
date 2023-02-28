#include "tcp_ip.h"
#include "service.h"

int SERVICE::Func::count = 0;

int main() {
   TCP_IP::TLS_CLIENT t{"localhost", 4433};
   t.encode_send("GET /");
   std::cout << *t.recv_decode() << std::endl;
}