#include <map>
#include <string>

struct ImportInfo {
  uint64_t iat_value;
  std::string dll_name;
  std::string function_name;
};

extern std::map<uint64_t, ImportInfo> api_map;

