#include <iostream>
#include <string>
#include <vector>

#include <android-base/file.h>

#include <property_info_serializer/property_info_serializer.h>

using android::base::ReadFileToString;
using android::properties::BuildTrie;
using android::properties::ParsePropertyInfoFile;
using android::properties::PropertyInfoEntry;

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "A list of property info files to be checked is expected on the command line"
              << std::endl;
    return -1;
  }

  auto property_info_entries = std::vector<PropertyInfoEntry>{};

  for (int i = 1; i < argc; ++i) {
    auto filename = argv[i];
    auto file_contents = std::string{};
    if (!ReadFileToString(filename, &file_contents)) {
      std::cerr << "Could not read properties from '" << filename << "'" << std::endl;
      return -1;
    }

    auto errors = std::vector<std::string>{};
    ParsePropertyInfoFile(file_contents, &property_info_entries, &errors);
    if (!errors.empty()) {
      for (const auto& error : errors) {
        std::cerr << "Could not read line from '" << filename << "': " << error << std::endl;
      }
      return -1;
    }
  }

  auto serialized_contexts = std::string{};
  auto build_trie_error = std::string{};

  if (!BuildTrie(property_info_entries, "u:object_r:default_prop:s0", "\\s*", &serialized_contexts,
                 &build_trie_error)) {
    std::cerr << "Unable to serialize property contexts: " << build_trie_error << std::endl;
    return -1;
  }

  return 0;
}
