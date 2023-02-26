#include "service.h"

using namespace std;

string SERVICE::Func::operator()(string s) {
    string to_send;
    switch(count) {
        case 0:
            t.client_hello(move(s));
            to_send = t.server_hello();
            to_send += t.server_certificate();
            to_send += t.server_key_exchange();
            to_send += t.server_hello_done();
            break;
        case 1:
            t.client_key_exchange(move(s));
            break;
        case 2:
            t.change_cipher_spec(move(s));
            break;
        case 3:
            t.finished(move(s));
            to_send = t.change_cipher_spec();
            to_send += t.finished();
            break;
        default:
            cout << *t.decode(move(s)) << endl;//수신한값 복호화
            to_send = t.encode("Learn cryptography by implementing TLS");
            break;
    }
    count++;
    return to_send;
}