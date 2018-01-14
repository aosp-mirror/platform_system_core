#include <property_info_serializer/property_info_serializer.h>

#include <android-base/strings.h>

#include "space_tokenizer.h"

using android::base::Split;
using android::base::StartsWith;
using android::base::Trim;

namespace android {
namespace properties {

bool ParsePropertyInfoLine(const std::string& line, PropertyInfoEntry* out, std::string* error) {
  auto tokenizer = SpaceTokenizer(line);

  auto property = tokenizer.GetNext();
  if (property.empty()) {
    *error = "Did not find a property entry in '" + line + "'";
    return false;
  }

  auto context = tokenizer.GetNext();
  if (context.empty()) {
    *error = "Did not find a context entry in '" + line + "'";
    return false;
  }

  // It is not an error to not find these, as older files will not contain them.
  auto exact_match = tokenizer.GetNext();
  auto type = tokenizer.GetRemaining();

  *out = {property, context, type, exact_match == "exact"};
  return true;
}

void ParsePropertyInfoFile(const std::string& file_contents,
                           std::vector<PropertyInfoEntry>* property_infos,
                           std::vector<std::string>* errors) {
  // Do not clear property_infos to allow this function to be called on multiple files, with
  // their results concatenated.
  errors->clear();

  for (const auto& line : Split(file_contents, "\n")) {
    auto trimmed_line = Trim(line);
    if (trimmed_line.empty() || StartsWith(trimmed_line, "#")) {
      continue;
    }

    auto property_info_entry = PropertyInfoEntry{};
    auto parse_error = std::string{};
    if (!ParsePropertyInfoLine(trimmed_line, &property_info_entry, &parse_error)) {
      errors->emplace_back(parse_error);
      continue;
    }

    property_infos->emplace_back(property_info_entry);
  }
}

}  // namespace properties
}  // namespace android
