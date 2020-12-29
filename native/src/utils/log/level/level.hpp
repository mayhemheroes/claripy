/**
 * @file
 * @brief This file defines the Utils::Log::Level typesafe enum
 * Also defines the << stream operator for this class
 * Also defines useful related macros
 */
#ifndef __UTILS_LOG_LEVEL_LEVEL_HPP__
#define __UTILS_LOG_LEVEL_LEVEL_HPP__


#ifdef CONSTANT_LOG_LEVEL
    /** Constexpr if and only if the log level is immutable */
    #define UTILS_LOG_LEVEL_CONSTEXPR constexpr
#else
    /** Constexpr if and only if the log level is immutable */
    #define UTILS_LOG_LEVEL_CONSTEXPR
#endif

/** Used to determine if log level A implies log level B */
#define UTILS_LOG_LEVEL_IMPLIES(A, B) (A <= B)


namespace Utils::Log::Level {

    /** A typesafe enum denoting different log levels
     *  The higher the level the more serious the error
     */
    enum class Level { Verbose = 0, Debug, Info, Warning, Error, Critical, Disabled };

} // namespace Utils::Log::Level


#endif