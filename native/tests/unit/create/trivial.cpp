/**
 * @file
 * \ingroup unittest
 */
#include "binary.hpp"
#include "flat.hpp"
#include "int_binary.hpp"
#include "unary.hpp"


/** Test the trivial create functions */
void trivial() {
    namespace Log = Utils::Log;
    namespace Ex = Expression;
    namespace Cr = Create;

    /********************************************************************/
    /*                              Unary                               */
    /********************************************************************/

    Log::debug("Testing abs...");
    unary<Ex::BV, Op::Abs, Cr::abs<Expression::BV>>();
    unary<Ex::FP, Op::Neg, Cr::neg<Expression::FP>>();

    Log::debug("Testing neg...");
    unary<Ex::BV, Op::Neg, Cr::neg<Expression::BV>>();
    unary<Ex::FP, Op::Neg, Cr::neg<Expression::FP>>();

    Log::debug("Testing invert...");
    unary<Ex::BV, Op::Invert, Cr::invert<Expression::BV>>();
    unary<Ex::Bool, Op::Invert, Cr::invert<Expression::Bool>>();

    Log::debug("Testing reverse...");
    unary<Ex::BV, Op::Reverse, Cr::reverse>();

    /********************************************************************/
    /*                            Int Binary                            */
    /********************************************************************/

    Log::debug("Testing sign_ext...");
    int_binary<Ex::BV, Op::SignExt, SM::Add, Cr::sign_ext>();

    Log::debug("Testing zero_ext...");
    int_binary<Ex::BV, Op::ZeroExt, SM::Add, Cr::zero_ext>();

    /********************************************************************/
    /*                              Binary                              */
    /********************************************************************/

    // Comparisons

    Log::debug("Testing eq...");
    binary<Ex::Bool, Ex::FP, Op::Eq, SM::First, Cr::eq<Expression::FP>>();
    binary<Ex::Bool, Ex::BV, Op::Eq, SM::First, Cr::eq<Expression::BV>>();
    binary<Ex::Bool, Ex::Bool, Op::Eq, SM::First, Cr::eq<Expression::Bool>>();
    binary<Ex::Bool, Ex::String, Op::Eq, SM::First, Cr::eq<Expression::String>>();

/** A macro used to test a comparison function */
#define TEST_COMPARE(T_, MASK)                                                                    \
    binary<Ex::Bool, T_, Op::Compare<MASK>, SM::First, Cr::compare<T_, MASK>>();

/** A macro used to test a comparison function for all values of Less and Equals */
#define TEST_COMPARE_MULTI(T_, S_)                                                                \
    TEST_COMPARE(T_, S_ | C::Less | C::Eq)                                                        \
    TEST_COMPARE(T_, S_ | C::Less)                                                                \
    TEST_COMPARE(T_, S_ | C::Eq)                                                                  \
    TEST_COMPARE(T_, S_)

    Log::debug("Testing compare...");
    {
        using C = Mode::Compare;
        TEST_COMPARE_MULTI(Ex::FP, C::Signed) // FP comparisons must be signed
        TEST_COMPARE_MULTI(Ex::BV, C::Signed) // BV can be either
        TEST_COMPARE_MULTI(Ex::BV, C::None)
    }

// Cleanup
#undef TEST_COMPARE
#undef TEST_COMPARE_MULTI

    // Math

    Log::debug("Testing sub...");
    binary<Ex::BV, Op::Sub, SM::First, Cr::sub>();

    Log::debug("Testing div...");
    binary<Ex::BV, Op::Div<true>, SM::First, Cr::div<true>>();
    binary<Ex::BV, Op::Div<false>, SM::First, Cr::div<false>>();

    Log::debug("Testing pow...");
    binary<Ex::BV, Op::Pow, SM::First, Cr::pow>();

    Log::debug("Testing mod...");
    binary<Ex::BV, Op::Mod<true>, SM::First, Cr::mod<true>>();
    binary<Ex::BV, Op::Mod<false>, SM::First, Cr::mod<false>>();

    // Bitwise

    Log::debug("Testing shift...");
    binary<Ex::BV, Op::Shift<true, true>, SM::First, Cr::arithmetic_shift<true, true>>();
    binary<Ex::BV, Op::Shift<true, false>, SM::First, Cr::arithmetic_shift<true, false>>();
    binary<Ex::BV, Op::Shift<false, false>, SM::First, Cr::arithmetic_shift<false, false>>();

    Log::debug("Testing rotate...");
    binary<Ex::BV, Op::Rotate<true>, SM::First, Cr::rotate<true>>();
    binary<Ex::BV, Op::Rotate<false>, SM::First, Cr::rotate<false>>();

    // Misc

    Log::debug("Testing widen...");
    binary<Ex::BV, Op::Widen, SM::First, Cr::widen>();

    Log::debug("Testing union...");
    binary<Ex::BV, Op::Union, SM::First, Cr::union_>();

    Log::debug("Testing intersection...");
    binary<Ex::BV, Op::Intersection, SM::First, Cr::intersection_<Expression::BV>>();
    binary<Ex::Bool, Op::Intersection, SM::First, Cr::intersection_<Expression::Bool>>();

    Log::debug("Testing concat...");
    binary<Ex::BV, Op::Concat, SM::Add, Cr::concat<Expression::BV>>();
    binary<Ex::String, Op::Concat, SM::Add, Cr::concat<Expression::String>>();

    /********************************************************************/
    /*                               Flat                               */
    /********************************************************************/

    // Math

    Log::debug("Testing add...");
    flat<Ex::BV, Op::Add, SM::First, Cr::add>();

    Log::debug("Testing mul...");
    flat<Ex::BV, Op::Mul, SM::First, Cr::mul>();

    // Logical

    Log::debug("Testing or...");
    flat<Ex::BV, Op::Or, SM::First, Cr::or_<Expression::BV>>();
    flat<Ex::Bool, Op::Or, SM::First, Cr::or_<Expression::Bool>>();

    Log::debug("Testing and...");
    flat<Ex::BV, Op::And, SM::First, Cr::and_<Expression::BV>>();
    flat<Ex::Bool, Op::And, SM::First, Cr::and_<Expression::Bool>>();

    Log::debug("Testing xor...");
    flat<Ex::BV, Op::Xor, SM::First, Cr::xor_>();
}

// Define the test
UNITTEST_DEFINE_MAIN_TEST(trivial)