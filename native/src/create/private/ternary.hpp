/**
 * @file
 * @brief This file defines a method to create Exprs with standard ternary ops
 */
#ifndef R_CREATE_PRIVATE_TERNARY_HPP_
#define R_CREATE_PRIVATE_TERNARY_HPP_

#include "size_mode.hpp"

#include "../constants.hpp"


namespace Create::Private {

    /** Create a Expr with a ternary op
     *  Expr pointers may not be nullptr
     */
    template <typename Out, typename In, typename OpT, SizeMode Mode, typename... Allowed>
    inline EBasePtr ternary(const EBasePtr &first, const EBasePtr &second, const EBasePtr &third,
                            Annotation::SPAV &&sp) {
        namespace Ex = Expr;
        using namespace Simplification;
        namespace Err = Error::Expr;

        // Static checks
        static_assert(Util::is_ancestor<Ex::Base, Out>,
                      "Create::Private::ternary requires Out be an Expr");
        static_assert(Util::is_ancestor<Ex::Base, In>,
                      "Create::Private::ternary requires In be an Expr");
        static_assert(Op::is_ternary<OpT>, "Create::Private::ternary requires a ternary OpT");
        if constexpr (Util::is_ancestor<Ex::Bits, Out>) {
            const constexpr bool sized_in { Util::is_ancestor<Ex::Bits, In> };
            static_assert(Util::TD::boolean<sized_in, In>,
                          "Create::Private::ternary does not support sized output types without "
                          "sized input types");
        }
        static_assert(Util::qualified_is_in<In, Allowed...>,
                      "Create::Private::ternary requires In is in Allowed");

        // Dynamic checks
        Util::affirm<Err::Usage>(first != nullptr, second != nullptr && third != nullptr,
                                 WHOAMI_WITH_SOURCE "Expr pointer arguments may not be nullptr");
        Util::affirm<Err::Type>(CUID::is_t<In>(first),
                                WHOAMI_WITH_SOURCE "first operand of incorrect type");

        // Construct expr (static casts are safe because of previous checks)
        if constexpr (Util::is_ancestor<Ex::Bits, Out>) {
            static_assert(Util::TD::boolean<Mode != SizeMode::NA, Out>,
                          "SizeMode::NA not allowed with sized output type");
            // Construct size
            UInt new_bit_length { Ex::get_bit_length(first) };
            if constexpr (Mode == SizeMode::Add) {
                Util::affirm<Err::Type>(CUID::is_t<In>(second),
                                        WHOAMI_WITH_SOURCE "second operand of incorrect type");
                Util::affirm<Err::Type>(CUID::is_t<In>(third),
                                        WHOAMI_WITH_SOURCE "third operand of incorrect type");
                new_bit_length += Ex::get_bit_length(second) + Ex::get_bit_length(third);
            }
            else {
                static_assert(Util::TD::false_<Out>,
                              "Create::Private::ternary does not support the given SizeMode");
            }
            // Actually construct expr
            return simplify(Ex::factory<Out>(
                first->symbolic || second->symbolic || third->symbolic,
                Op::factory<OpT>(first, second, third), new_bit_length, std::move(sp)));
        }
        else {
            static_assert(Mode == Util::TD::id<SizeMode::NA>,
                          "SizeMode should be NA for non-sized type");
            return simplify(
                Ex::factory<Out>(first->symbolic || second->symbolic || third->symbolic,
                                 Op::factory<OpT>(first, second, third), std::move(sp)));
        }
    }

    /** Create a Expr with a ternary op
     *  Expr pointers may not be nullptr
     *  A specialization where In = Out
     */
    template <typename InOut, typename OpT, SizeMode Mode, typename... Allowed>
    inline EBasePtr ternary(const EBasePtr &first, const EBasePtr &second, const EBasePtr &third,
                            Annotation::SPAV &&sp) {
        return ternary<InOut, InOut, OpT, Mode, Allowed...>(first, second, third, std::move(sp));
    }

} // namespace Create::Private

#endif
