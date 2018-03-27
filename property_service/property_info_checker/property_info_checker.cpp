#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <property_info_parser/property_info_parser.h>
#include <property_info_serializer/property_info_serializer.h>
#include <sepol/context.h>
#include <sepol/context_record.h>
#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>

using android::base::ReadFileToString;
using android::properties::BuildTrie;
using android::properties::ParsePropertyInfoFile;
using android::properties::PropertyInfoArea;
using android::properties::PropertyInfoEntry;

class ContextChecker {
 public:
  ContextChecker()
      : policy_file_(nullptr),
        sepol_handle_(nullptr),
        sepol_policy_file_(nullptr),
        sepol_policy_db_(nullptr) {}

  ~ContextChecker() {
    if (sepol_policy_db_ != nullptr) {
      sepol_policydb_free(sepol_policy_db_);
    }

    if (sepol_policy_file_ != nullptr) {
      sepol_policy_file_free(sepol_policy_file_);
    }

    if (sepol_handle_ != nullptr) {
      sepol_handle_destroy(sepol_handle_);
    }

    if (policy_file_ != nullptr) {
      fclose(policy_file_);
    }
  }

  bool Initialize(const char* policy_file) {
    policy_file_ = fopen(policy_file, "re");
    if (policy_file_ == nullptr) {
      std::cerr << "Could not open policy file, " << policy_file << std::endl;
      return false;
    }

    sepol_handle_ = sepol_handle_create();
    if (sepol_handle_ == nullptr) {
      std::cerr << "Could not create policy handle." << std::endl;
      return false;
    }

    if (sepol_policy_file_create(&sepol_policy_file_) < 0) {
      std::cerr << "Could not create policy file." << std::endl;
      return false;
    }

    if (sepol_policydb_create(&sepol_policy_db_) < 0) {
      std::cerr << "Could not create policy db." << std::endl;
      return false;
    }

    sepol_policy_file_set_fp(sepol_policy_file_, policy_file_);
    sepol_policy_file_set_handle(sepol_policy_file_, sepol_handle_);

    if (sepol_policydb_read(sepol_policy_db_, sepol_policy_file_) < 0) {
      std::cerr << "Could not read policy file into policy db." << std::endl;
      return false;
    }

    auto* attr =
        reinterpret_cast<type_datum*>(hashtab_search(policy_db_->p_types.table, "property_type"));
    if (attr == nullptr || attr->flavor != TYPE_ATTRIB) {
      std::cerr << "'property_type' is not defined correctly." << std::endl;
      return false;
    }

    property_type_bit_ = attr->s.value - 1;

    return true;
  }

  bool CheckContext(const char* context) {
    sepol_context_t* sepol_context_raw;
    if (sepol_context_from_string(sepol_handle_, context, &sepol_context_raw) < 0) {
      std::cerr << "Could not allocate context for " << context << std::endl;
      return false;
    }
    auto sepol_context = std::unique_ptr<sepol_context_t, decltype(&sepol_context_free)>{
        sepol_context_raw, sepol_context_free};

    if (sepol_context_check(sepol_handle_, sepol_policy_db_, sepol_context.get()) < 0) {
      std::cerr << "Sepol context check failed for " << context << std::endl;
      return false;
    }

    const char* context_type = sepol_context_get_type(sepol_context.get());

    auto* type =
        reinterpret_cast<type_datum*>(hashtab_search(policy_db_->p_types.table, context_type));
    if (type == nullptr) {
      std::cerr << "Could not find context '" << context << "' in policy database" << std::endl;
      return false;
    }

    if (type->flavor != TYPE_TYPE) {
      std::cerr << "Context '" << context << "' is not defined as a type in policy database"
                << std::endl;
      return false;
    }

    if (!ebitmap_get_bit(&policy_db_->type_attr_map[type->s.value - 1], property_type_bit_)) {
      std::cerr << "Context '" << context << "' does not have property_type attribute" << std::endl;
      return false;
    }

    return true;
  }

 private:
  FILE* policy_file_;
  sepol_handle_t* sepol_handle_;
  sepol_policy_file_t* sepol_policy_file_;
  union {
    sepol_policydb_t* sepol_policy_db_;
    policydb_t* policy_db_;
  };
  unsigned int property_type_bit_;
};

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "usage: " << argv[0]
              << " COMPILED_SEPOLICY PROPERTY_INFO_FILE [PROPERTY_INFO_FILE]..." << std::endl;
    return -1;
  }

  auto property_info_entries = std::vector<PropertyInfoEntry>{};

  for (int i = 2; i < argc; ++i) {
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

  auto checker = ContextChecker{};
  if (!checker.Initialize(argv[1])) {
    return -1;
  }

  auto property_info_area = reinterpret_cast<PropertyInfoArea*>(serialized_contexts.data());
  for (size_t i = 0; i < property_info_area->num_contexts(); ++i) {
    if (!checker.CheckContext(property_info_area->context(i))) {
      return -1;
    }
  }

  return 0;
}
