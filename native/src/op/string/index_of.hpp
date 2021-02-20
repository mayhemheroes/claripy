/**
 * @file
 * @brief This file defines the String::IndexOf class
 */
#ifndef __OP_STRING_INDEXOF_HPP__
#define __OP_STRING_INDEXOF_HPP__

#include "../base.hpp"


namespace Op::String {

    /** The op class: String::IndexOf */
    class IndexOf final : public Base {
        OP_FINAL_INIT(IndexOf)
      public:
        /** String to search: This must be an Expression::String pointer
         *  Note: We leave it as a base for optimizations purposes
         */
        const Expression::BasePtr str;
        /** Pattern to search for: This must be an Expression::String pointer
         *  Note: We leave it as a base for optimizations purposes
         */
        const Expression::BasePtr pattern;
        /** Start Index */
        Constants::UInt start_index;

      private:
        /** Protected constructor
         *  Ensure that str and pattern are of type String
         */
        explicit inline IndexOf(const Hash::Hash &h, const Expression::BasePtr &s,
                                const Expression::BasePtr &pat, const Constants::UInt si)
            : Base { h, static_cuid }, str { s }, pattern { pat }, start_index { si } {
            using Err = Error::Expression::Type;
            Utils::affirm<Err>(Expression::is_t<Expression::String>(str),
                               WHOAMI_WITH_SOURCE "str expression must be a String");
            Utils::affirm<Err>(Expression::is_t<Expression::String>(pattern),
                               WHOAMI_WITH_SOURCE "pattern expression must be a String");
        }
    };

} // namespace Op::String

#endif
