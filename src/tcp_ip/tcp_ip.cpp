#include "tcp_ip.h"

#include <iostream>
#include <thread>

using namespace std;

TCP_IP::TCP_IP::TCP_IP(int port) {
    memset(&server_addr_, 0, sizeof(server_addr_));
    memset(&client_addr_, 0, sizeof(client_addr_));
    server_addr_.sin_family = AF_INET;                       // ip v4
    server_addr_.sin_port = htons(port);                     // host to network unsigned short (2byte)
    server_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);  // socket 객체 생성
    client_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

TCP_IP::TCP_IP::~TCP_IP() {
    close(server_fd_);
    close(client_fd_);
    std::cout << "destorying TCP_IP" << std::endl;
}

void TCP_IP::TCP_IP::send(const std::string& s, int fd) {
    if (write(!fd ? client_fd_ : fd, s.data(), s.size()) == -1) {
        std::cout << "write() error" << std::endl;
    }
}

optional<string> TCP_IP::TCP_IP::recv(int fd) {
    int i = read(!fd ? client_fd_ : fd, buffer, buffer_size);
    if (i > 0) {
        return string(buffer, i);
    } else {
        return {};  // return false
    }
}

TCP_IP::VRECV::VRECV(int port) : TCP_IP{port} {}

optional<string> TCP_IP::VRECV::recv(int fd) {
    int len;
    static thread_local string trailing_string; /** 지금까지 수신한 누적 메시지*/

    while (!(0 < (len = get_full_length(trailing_string)) && len /*읽어야할 길이*/ <= trailing_string.size() /*현재 읽은 길이*/)) {  // length는 0 보다 커야하고 읽어야할 length가 지금까지 읽은 length보다 작다면 계속 읽어야함
        if (len == -1) return {};                                                                                                    // wrong protocol
        if (auto a = TCP_IP::recv(fd)) {                                                                                             // 계속 읽는다.
            trailing_string += *a;                                                                                                   // 누적
        } else {
            return {};  // 오류
        }
    }

    string r = trailing_string.substr(0, len);      // 0부터 시작하여 len 만큼 r에 저장한다.(HTTP의 경우에는 HTML파일만 남음)
    trailing_string = trailing_string.substr(len);  // trailing_string을 정리한다.
    return r;
}

int TCP_IP::VRECV::get_full_length(const string& s) {  // default로 Packet이 BUFFER_SIZE보다 작게 와서 모두 수신했다고 가정
    return s.size();
}

TCP_IP::HTTP::HTTP(int port) : VRECV{port} {}

int TCP_IP::HTTP::get_full_length(const string& s) {
    smatch m;
    if (regex_search(s, m, regex{R"(Content-Length:\s*(\d+))"})) {  // \s* : 빈공간 0개 이상, (\d+) : 숫자 1개이상 매치
        return stoi(m[1].str()) /*HTML Payload 길이*/ + s.find("\r\n\r\n") /*Http Header의 길이*/ + 4 /*개행 문자 자체의 길이*/;
    } else {
        return VRECV::get_full_length(s);
    }
}

TCP_IP::TLS_LAYER::TLS_LAYER(int port) : VRECV{port} {}
int TCP_IP::TLS_LAYER::get_full_length(const string& s) {
    // 4, 5번째 바이트가 TLS Packet의 길이
    if (s.size() < 5) {
        return -1;
    } else {
        return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5 /*TLS Header의 길이*/;
    }
}

TCP_IP::Client::Client(string ip, int port) : HTTP{port} {
    server_addr_.sin_addr.s_addr = inet_addr(get_addr(ip).c_str());
    if (connect(client_fd_, (sockaddr*)&server_addr_, sizeof(server_addr_)) != -1) {
        std::cout << "connecting to " << ip << ":" << port << std::endl;
    } else {
        std::cout << "connect() error" << std::endl;
    }
}

string TCP_IP::Client::get_addr(string host) {
    auto* a = gethostbyname(host.data());
    return inet_ntoa(*(struct in_addr*)a->h_addr);
}

void TCP_IP::kill_zombie(int) {
    int status;
    waitpid(-1 /*wait for any child process*/, &status, WNOHANG /*non blocking*/);
}

TCP_IP::Server::Server(int port, unsigned int t, int queue, string e) : HTTP{port} {
    end_string_ = e;
    time_out_ = t;
    server_addr_.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(server_fd_, (sockaddr*)&server_addr_, sizeof(server_addr_)) != -1) {
        std::cout << "binding" << std::endl;
    } else {
        std::cout << "bind() error" << std::endl;
    }
    if (listen(server_fd_, queue) != -1) {
        std::cout << "listening port" << port << std::endl;
    } else {
        std::cout << "listen() error" << std::endl;
    }

    struct sigaction sa;
    sa.sa_handler = kill_zombie;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGCHLD, &sa, 0);  // 좀비 프로세스를 제거하기 위한 이벤트 핸들러 등록
}

void TCP_IP::Server::start(function<string(string)> f) {
    int cl_size = sizeof(client_addr_);
    while (1) {
        client_fd_ = accept(server_fd_, (sockaddr*)&client_addr_, (socklen_t*)&cl_size);
        if (client_fd_ == -1) {
            std::cout << "accept() error" << std::endl;
            perror("accpet");
            continue;
        }
        struct timeval tv;
        tv.tv_sec = time_out_;  // 시간 초과
        tv.tv_usec = 0;
        if (setsockopt(client_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
            std::cout << "setsockopt error" << std::endl;
            continue;
        }
        if (!fork()) {
            for (optional<string> s; s = recv(); send(f(*s)))
                ;
            // recv 함수 에러시 루프를 탈출해 접속이 종료
            send(end_string_);  // 솔직히 end_string의 존재이유를 잘모르겠음
            close(client_fd_);
            break;  // fork한 프로세스 종료
        }
    }
}

TCP_IP::TLS_CLIENT::TLS_CLIENT(string ip, int port) : Client{ip, port} {
    send(t.client_hello());
    t.server_hello(*recv());
    t.server_certificate(*recv());
    t.server_key_exchange(*recv());
    t.server_hello_done(*recv());

    string a = t.client_key_exchange();
    string b = t.change_cipher_spec();
    string c = t.finished();
    send(a + b + c);
    t.change_cipher_spec(*recv());
    t.finished(*recv());
}

void TCP_IP::TLS_CLIENT::encode_send(string s) {
    send(t.encode(move(s)));
}

optional<string> TCP_IP::TLS_CLIENT::recv_decode() {
    return t.decode(*recv());
}

int TCP_IP::TLS_CLIENT::get_full_length(const string& s) {
    return s.size() < 5 ? 0 /*아무것도 받지 못한경우 0 반환*/ : static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
}

TCP_IP::TLS_SERVER::TLS_SERVER(int port) : Server{port} {}

int TCP_IP::TLS_SERVER::get_full_length(const string& s) {
    return s.size() < 5 ? 0 : static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
}

int TCP_IP::MIDDLE::get_full_length(const string& s) {
    return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
}
TCP_IP::MIDDLE::MIDDLE(int outport, int inport, int time_out, int queue, string end) : Server{outport, time_out, queue, end}, inport_{inport} {}

void TCP_IP::MIDDLE::conn() {
    int cl_size = sizeof(client_addr_);
    vector<thread> v;
    while (1) {
        client_fd_ = accept(server_fd_, (sockaddr*)&client_addr_, (socklen_t*)&cl_size);  // 접속 대기
        if (client_fd_ == -1) {
            cout << "accept() error" << endl;
        } else {
            v.emplace_back(thread{&MIDDLE::connected, this, client_fd_});
            v.back().detach();  // 현재 Thread가 관리하지 않는다. 생성된 Thread가 알아서 관리하도록
        }
    }
}

void TCP_IP::MIDDLE::connected(int client_fd) {
    TLS13::TLS13<SERVER> t;
    if (t.handshake(bind(&MIDDLE::recv, this, client_fd),
                    bind(&MIDDLE::send, this, placeholders::_1, client_fd))) {
        while (1) {
            // recv from client
            if (auto ret = recv(client_fd)) {
                cout << "Server Received: " << endl;
                cout << *ret << endl;
                // send to client
                send(t.encode(move("This is TLS 1.3 Server!!")), client_fd);
            } else {
                break;
            }
        }
    }
    close(client_fd);
}

void TCP_IP::MIDDLE::start() {
    thread th{&MIDDLE::conn, this};  // 접속 대기 Thread 생성
    string s;
    cout << "starting middle server, enter \'?\' to see commands.\n";
    while (cin >> s) {
        if (s == "end")
            break;
        else if (s == "help" || s == "?") {
            cout << "end, timeout [sec]" << endl
                 << "current timeout " << time_out_ << endl;
        } else if (s == "timeout") {
            cin >> time_out_;
            cout << "time out set " << time_out_ <<endl;
        }
    }
    th.join();//main Thread 종료 -> conn도 종료
}