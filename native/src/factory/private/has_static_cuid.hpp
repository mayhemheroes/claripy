/**
 * @file
 * @brief This file defines a method used to determine if a class has a static cuid defined
 */
#ifndef __FACTORY_PRIVATE_HASSTATICCUID_HPP__
#define __FACTORY_PRIVATE_HASSTATICCUID_HPP__

#include <type_traits>


namespace Factory::Private {

    /** Used to determine if T has a static member called static_cuid
     *  False case
     */
    template <typename T, typename = int> struct HasStaticCUID : std::false_type {};

    /** Used to determine if T has a static Constants::UInt called static_cuid
     *  True case
     *  The comma operator returns the second item, so "(A, B)" returns B
     *  If static_cuid does not exist, T::static_cuid fails is not resolvable so this
     * specialization is rejected (via SFINAE) in favor if the previous, more general, definition.
     *  If static_cuid exists, then (T::static_cuid,  0) returns 0, and we have specialized
     *  with int = 0. Note that specializations are prioritized over the general definition
     */
    template <typename T>
    struct HasStaticCUID<T, decltype((void) T::static_cuid, 0)> : std::true_type {};

    /** Used to determien of T has a static_cuid variable */
    template <typename T> constexpr bool has_static_cuid_v = HasStaticCUID<T>::value;

} // namespace Factory::Private

#endif
