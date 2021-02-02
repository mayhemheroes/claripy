/**
 * @file
 * @brief This file defines a macro a class can use to define a static_cuid
 */
#ifndef __FACTORY_STATICUID_HPP__
#define __FACTORY_STATICUID_HPP__

#include "../utils.hpp"


/** Used to define a static_cuid in a class */
#define FACTORY_DEFINE_STATIC_CUID                                                                \
    /** Define a static_cuid */                                                                   \
    static const constexpr static_cuid = UTILS_FILE_LINE_HASH;


#endif
