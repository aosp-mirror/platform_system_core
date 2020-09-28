#pragma once
#include <string>

static const std::string kFormatChars = std::string("duoxXfFeEgGaAcsp");
static constexpr int32_t kMaxFormatFlagValue = INT16_MAX;
enum FormatChar : uint8_t {
    SIGNED_DECIMAL = 0,
    UNSIGNED_DECIMAL = 1,
    UNSIGNED_OCTAL = 2,
    UNSIGNED_HEX_LOWER = 3,
    UNSIGNED_HEX_UPPER = 4,
    // Uppercase/lowercase floating point impacts 'inf', 'infinity', and 'nan'
    FLOAT_LOWER = 5,
    FLOAT_UPPER = 6,
    // Upper/lower impacts the "e" in exponents.
    EXPONENT_LOWER = 7,
    EXPONENT_UPPER = 8,
    // %g will use %e or %f, whichever is shortest
    SHORT_EXP_LOWER = 9,
    // %G will use %E or %F, whichever is shortest
    SHORT_EXP_UPPER = 10,
    HEX_FLOAT_LOWER = 11,
    HEX_FLOAT_UPPER = 12,
    CHAR = 13,
    STRING = 14,
    POINTER = 15,
    // Used by libfuzzer
    kMaxValue = POINTER
};

bool canApplyFlag(FormatChar formatChar, char modifier) {
    if (modifier == '#') {
        return formatChar == UNSIGNED_OCTAL || formatChar == UNSIGNED_HEX_LOWER ||
               formatChar == UNSIGNED_HEX_UPPER || formatChar == FLOAT_LOWER ||
               formatChar == FLOAT_UPPER || formatChar == SHORT_EXP_LOWER ||
               formatChar == SHORT_EXP_UPPER;
    } else if (modifier == '.') {
        return formatChar == SIGNED_DECIMAL || formatChar == UNSIGNED_DECIMAL ||
               formatChar == UNSIGNED_OCTAL || formatChar == UNSIGNED_HEX_LOWER ||
               formatChar == UNSIGNED_HEX_UPPER || formatChar == FLOAT_LOWER ||
               formatChar == FLOAT_UPPER || formatChar == SHORT_EXP_LOWER ||
               formatChar == SHORT_EXP_UPPER || formatChar == STRING;
    }
    return true;
}
