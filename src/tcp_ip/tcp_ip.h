#pragma once
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <functional>
#include <optional>
#include <regex>
#include <string>

#include "service.h"
#include "tls.h"
#include "tls13.h"

#define CLIENT false
#define SERVER true
namespace TCP_IP {

const int buffer_size = 4096;

class TCP_IP {
   public:
    /**
     * @brief TCP_IP 클래스의 생성자, 소켓을 생성한다.
     * @param port TCP_IP를 사용할 포트 번호
     */
    TCP_IP(int port = 2001);

    /**
     * @brief TCP_IP 클래스의 소멸자, 소켓을 닫는다.
     */
    virtual ~TCP_IP();

    /**
     * @brief TCP_IP로 문자열을 전송한다.
     * @param s 보내고자 하는 문자열
     * @param fd 보내는 대상의 socket file descriptor
     */
    void send(const std::string& s, int fd = 0);

    /**
     * @brief TCP_IP로 문자열을 수신하여 리턴한다.
     * @param fd 목적지 file descriptor
     * @return 정상적으로 수신한 문자열 std::string
     * @exception std::optional false
     */
    std::optional<std::string> recv(int fd = 0);

   protected:
    int server_fd_;                                /** Server file descriptor*/
    int client_fd_;                                /** Client file descriptor*/
    struct sockaddr_in server_addr_, client_addr_; /** 서버, 클라이언트 POSIX 주소 구조체 */
    char buffer[buffer_size];                      /** 수신한 데이터를 저장할 buffer */
};

class VRECV : public TCP_IP {
   public:
    VRECV(int port);
    /**
     * @brief TCP_IP 클래스의 recv를 반복적으로 호출하여 정확한 메시지를 리턴 하는 함수
     * @param fd 목적지 file descriptor
     * @return 수신한 정확한 메시지
     * @exception std::optional false
     */
    std::optional<std::string> recv(int fd = 0);

    // 어차피 TCP/IP Header는 socket 객체에서 알아서 처리해 나오므로 http payload, tls header관련만 처리하면된다.
   protected:
    /**
     * @brief recv 함수를 호출하는것 만으로도 긴 길이의 데이터를 모두 수신하기 위해 완전한 메시지의 길이를 리턴해야하는 가상함수
     * @param s 지금 까지 수신한 pakcet의 string
     * @return 완전한 메시지의 길이
     */
    virtual int get_full_length(const std::string& s);
};

class HTTP : public VRECV {
   public:
    /**
     * @brief HTTP 운영 및 접속하는 클래스의 생성자
     * @param port HTTP 클래스 포트 번호
     */
    HTTP(int port);

   protected:
    /**
     * @brief HTTP Header 및 Payload의 길이를 리턴하는 함수
     * @param s 지금까지 수신한 http packet의 string
     * @return HTTP Header + Payload의 길이
     */
    int get_full_length(const std::string& s);
};

class TLS_LAYER : public VRECV {
   public:
    /**
     * @brief TLS Layer를 운영 및 접속하는 클래스의 생성자
     * @param port
     */
    TLS_LAYER(int port);

   protected:
    /**
     * @brief TLS Header 및 TLS Payload의 길이를 리턴하는 함수
     * @param s 지금까지 수신한 TLS Packet의 string
     * @return TLS Header + TLS Payload
     */
    int get_full_length(const std::string& s);
};

class Client : public HTTP {
   public:
    /**
     * @brief ip, port에 해당하는 http socket을 연결한다.
     * @param ip 접속하고자 하는 ip 주소
     * @param port 접속하고자 하는 포트 번호
     */
    Client(std::string ip = "127.0.0.1", int port = 2001);

   private:
    /**
     * @brief 도메인 주소를 ip주소로 변환한다.
     * @param host 도메인 주소 또는 ip 주소
     * @return ip주소 문자열
     */
    std::string get_addr(std::string host);
};

class Server : public HTTP {
   public:
    /**
     * @brief ip, port에 해당하는 http socket을 생성 및 대기 한다.
     * @param port 열고자 하는 포트 번호
     * @param time_out 서버와 클라이언트의 연결 시간 time out
     * @param queue_limit 동시 연결 가능한 큐의 수
     * @param end_string 접속 종료시의 문자
     */
    Server(int port = 2001, unsigned int time_out = 600, int queue_limit = 10, std::string end_string = "end");
    /**
     * @brief http 서버를 시작하는 함수, 클라이언트가 접속시 f 함수 객체의 값을 리턴한다.
     * @param f std::string f(std::string) 함수 객체
     */
    void start(std::function<std::string /*리턴*/ (std::string /*매개변수*/)> f);

   protected:
    std::string end_string_;
    int time_out_;
};

void kill_zombie(int);

class TLS_CLIENT : public Client {
   public:
    TLS_CLIENT(std::string ip, int port);
    void encode_send(std::string s);
    std::optional<std::string> recv_decode();

   private:
    TLS::TLS<CLIENT> t;
    int get_full_length(const std::string& s);
};

class TLS_SERVER : public Server {
   public:
    TLS_SERVER(int port);

   private:
    int get_full_length(const std::string& s);
};

class TLS13_CLIENT : public Client {
   public:
    TLS13_CLIENT(std::string ip, int port) : Client{ip, port} {
        t.handshake(std::bind(&TLS_CLIENT::recv, this, 0 /*fd*/) /*recv*/, std::bind(&TLS_CLIENT::send, this, std::placeholders::_1, 0) /*send*/);
    }

    void encode_send(std::string s) {
        send(t.encode(move(s)));
    }

    std::optional<std::string> recv_decode() {
        return t.decode(*recv());
    }

   private:
    TLS13::TLS13<CLIENT> t;
    int get_full_length(const std::string& s) {
        return s.size() < 5 ? 0 : static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
    }
};

class MIDDLE : public Server {
   public:
    MIDDLE(int outport = 4433, int inport = 2001, int time_out = 1800, int queue_limit = 10, std::string end_string = "end");
    /**
     * @brief CommandLine을 관리하는 Main Thread
    */
    void start();

   protected:
    int inport_;
    bool debug_ = false;

   private:
    /**
     * @brief client와 통신을 유지하는 Thread
     * @param client_fd client file descriptor
    */
    void connected(int client_fd);
    /**
     * @brief 외부와의 접속을 대기하는 Thread
    */
    void conn();
    int get_full_length(const std::string &s);
};
}  // namespace TCP_IP