/**
 * @file
 * \ingroup unittest
 */
#include "create.hpp"
#include "testlib.hpp"


/** Verify that the abs function compiles and can be run without issue */
void abs() {

    // Create input
    const auto a { UnitTest::TestLib::Factories::t_literal<Expression::BV>() };

    // Test
    (void) Create::abs<Expression::BV>(Create::EAnVec {}, a);
}

// Define the test
UNITTEST_DEFINE_MAIN_TEST(abs)
