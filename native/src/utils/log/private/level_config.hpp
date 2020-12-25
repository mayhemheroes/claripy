/**
 * @file
 * @brief This file defines which log levels are enabled
 */
#ifndef __UTILS_LOG_PRIVATE_LEVELCONFIG_HPP__
#define __UTILS_LOG_PRIVATE_LEVELCONFIG_HPP__


namespace Utils::Log::Private::Enabled {

    /** Enable / disable verbose log level */
    constexpr const bool verbose =
#ifdef VERBOSE_LOG
        true;
#else
        false;
#endif

    /** Enable / disable debug log level */
    constexpr const bool debug =
#ifdef DEBUG_LOG
        true;
#else
        false;
#endif

    /** Enable / disable info log level */
    constexpr const bool info =
#ifdef INFO_LOG
        true;
#else
        false;
#endif

    /** Enable / disable warning log level */
    constexpr const bool warning =
#ifdef WARNING_LOG
        true;
#else
        false;
#endif

    /** Enable / disable error log level */
    constexpr const bool error =
#ifdef ERROR_LOG
        true;
#else
        false;
#endif

    /** Enable / disable critical log level */
    constexpr const bool critical =
#ifdef CRITICAL_LOG
        true;
#else
        false;
#endif

} // namespace Utils::Log::Private::Enabled

#endif
