#include "tls.h"
#define private public
#define protected public
#undef private
#undef protected
#include <iostream>
#include <string>
#define CLIENT false
#define SERVER true
#include <catch2/catch_all.hpp>
using namespace std;



void alert_print(const int& desc, bool s, std::string&& procedure) {
    std::cout << procedure << std::endl;
    std::cerr << (s ? "server": "client") << " alert error desc CODE : " << desc <<std::endl;
    return;
}

TEST_CASE("tls") {
    std::cout << "tls" << std::endl;
    TLS::TLS<SERVER> server;
    TLS::TLS<CLIENT> client;
    
    //1. CLIENT HELLO
    auto ret = server.client_hello(client.client_hello());//client가 client hello 메시지 생성후 server가 파싱
    if(ret != "") {
        alert_print(server.alert(std::move(ret)), SERVER, std::move(std::string{"CLIENT HELLO"}));
        exit(1);
    }

    //2. SERVER HELLO
    ret = client.server_hello(server.server_hello());
    if(ret != "") {
        alert_print(client.alert(std::move(ret)), CLIENT, std::move(std::string{"SERVER HELLO"}));
        exit(1);
    }

    //3. CERTIFICATE
    ret = client.server_certificate(server.server_certificate());
    if(ret != "") {
        alert_print(client.alert(std::move(ret)), CLIENT, std::move(std::string{"CERTIFICATE"}));
        exit(1);
    }

    //4. SERVER KEY EXCHANGE
    ret = client.server_key_exchange(server.server_key_exchange());
    if(ret != "") {
        alert_print(client.alert(std::move(ret)), CLIENT, std::move(std::string{"SERVER KEY EXCHANGE"}));
        exit(1);
    }

    //5. SERVER HELLO DONE
    ret = client.server_hello_done(server.server_hello_done());
    if(ret != "") {
        alert_print(client.alert(std::move(ret)), CLIENT, std::move(std::string{"SERVER HELLO DONE"}));
        exit(1);
    }
    
    //6. CLIENT KEY EXCHANGE
    ret = server.client_key_exchange(client.client_key_exchange());
    if(ret != "") {
        alert_print(server.alert(std::move(ret)), SERVER, std::move(std::string{"CLIENT KEY EXCHANGE"}));
        exit(1);
    }

    //7. Change Cipher Spec
    ret = server.change_cipher_spec(client.change_cipher_spec());
    if(ret != "") {
        alert_print(server.alert(std::move(ret)), SERVER, std::move(std::string{"CHANGE CIPHER SPEC"}));
        exit(1);
    }

    //8. CLIENT FINISHED
    ret = server.finished(client.finished());
    if(ret != "") {
        alert_print(server.alert(std::move(ret)), SERVER, std::move(std::string{"CLIENT FINISHED"}));
        exit(1);
    }

    //9. Change Cipher Spec
    ret = client.change_cipher_spec(server.change_cipher_spec());
    if(ret != "") {
        alert_print(client.alert(std::move(ret)), CLIENT, std::move(std::string{"CHANGE CIPHER SPEC"}));
        exit(1);
    }

    //. SERVER FINISHED
    ret = client.finished(server.finished());
    if(ret != "") {
        alert_print(client.alert(std::move(ret)), CLIENT, std::move(std::string{"SERVER FINISHED"}));
        exit(1);
    }

    //REQUIRE(server.rsa_.K == client.rsa_.K);
    REQUIRE(equal(server.master_secret_.begin(), server.master_secret_.end(), client.master_secret_.begin()));
    REQUIRE(equal(server.client_random_.begin(), server.client_random_.end(), client.client_random_.begin()));
    REQUIRE(equal(server.server_random_.begin(), server.server_random_.end(), client.server_random_.begin()));
    for(int i = 0; i < 2; i++) {//check key expansion
        REQUIRE(equal(server.aes_[i].cipher_.schedule_[0], server.aes_[i].cipher_.schedule_[0] + 11 * 16, client.aes_[i].cipher_.schedule_[0]));
        //REQUIRE(equal(begin(server.aes_[i].)));
    }
    REQUIRE(string{"hello world"} == server.decode(client.encode("hello world")));
    REQUIRE(string{"Hello!! world"} == client.decode(server.encode("Hello!! world")));
}