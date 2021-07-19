/**
 * @file
 * \ingroup unittest
 */
#include "testlib.hpp"

#include "../make_ite.hpp"

#include <string>


/** Print the desired repr of the expression: if (4 == (x * 3)) then "Hello" else y */
static std::string make_solution(const std::string &str, const Constants::UInt len) {
    using namespace std::string_literals;
    const auto bl { std::to_string(8_ui * len) };

    // Leaf ops
    const auto op_x { R"|({ "name":"Symbol", "symbol":"x" })|"s };
    const auto op_y { R"|({ "name":"Symbol", "symbol":"y" })|"s };
    const auto op_3 { R"|({ "name":"Literal", "value":3 })|"s };
    const auto op_4 { R"|({ "name":"Literal", "value":4 })|"s };
    const auto op_hello { R"|({ "name":"Literal", "value":")|" + str + "\" }" };

    // Simple fp
    const auto fp_x { R"|({ "type":"FP", "symbolic":true, "bit_length":64, "op":)|"s + op_x +
                      " }" };
    const auto fp_3 { R"|({ "type":"FP", "symbolic":false, "bit_length":64, "op":)|"s + op_3 +
                      " }" };
    const auto fp_4 { R"|({ "type":"FP", "symbolic":false, "bit_length":64, "op":)|"s + op_4 +
                      " }" };

    // Simple string
    const auto string_y { R"|({ "type":"String", "symbolic":true, "bit_length":)|" + bl +
                          R"|(, "op":)|"s + op_y + " }" };
    const auto string_hello { R"|({ "type":"String", "symbolic":false, "bit_length":)|" + bl +
                              R"|(, "op":)|"s + op_hello + " }" };

    // mul
    const auto op_mul { R"|({ "name":"FP::Mul", "mode":0, "left":)|"s + fp_x + R"|(, "right":)|" +
                        fp_3 + " }" };
    const auto fp_mul { R"|({ "type":"FP", "symbolic":true, "bit_length":64, "op":)|"s + op_mul +
                        " }" };

    // eq
    const auto op_eq { R"|({ "name":"Eq", "consider_size":true, "left":)|"s + fp_4 +
                       R"|(, "right":)|" + fp_mul + " }" };
    const auto bool_eq { R"|({ "type":"Bool", "symbolic":true, "op":)|"s + op_eq + " }" };

    // if
    const auto op_if { R"|({ "name":"If", "cond":)|" + bool_eq + R"|(, "if_true":)|" +
                       string_hello + R"|(, "if_false":)|" + string_y + " }" };
    return R"|({ "type":"String", "symbolic":true, "bit_length":)|" + bl + R"|(, "op":)|" + op_if +
           " }";
}

/** Print the repr of the expression: if (4 == (x * 3)) then "Hello" else y */
void repr() {

    // Make the ite
    std::string str { "Hello" };
    const auto ite { make_ite(str) };

    // repr
    std::ostringstream s;
    s << ite;

    // Compare
    Utils::Log::warning(s.str());
    Utils::Log::warning(make_solution(str, str.size()));
    UNITTEST_ASSERT(s.str() == make_solution(str, str.size()));
}

// Define the test
UNITTEST_DEFINE_MAIN_TEST(repr)