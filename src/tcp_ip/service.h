#pragma once
#include <string>

#include "tls.h"
namespace SERVICE {
class Func {
   public:
    std::string operator()(std::string s);

   private:
    static int count;
    TLS::TLS<true> t;
};
}  // namespace SERVICE