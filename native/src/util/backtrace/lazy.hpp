/**
 * @file
 * \ingroup util
 * @brief Define a lazy traceback type
 */
#ifndef R_SRC_UTIL_BACKTRACE_LAZY_HPP_
#define R_SRC_UTIL_BACKTRACE_LAZY_HPP_

#include "backtrace.hpp"

#include "../fallback_error_log.hpp"

#include <memory>
#include <ostream>
#include <sstream>
#include <variant>


namespace Util::Backtrace {
    /** The lazy backtrace holder type */
    class Lazy {
      public:
        /** For brevity */
        using Ptr = std::shared_ptr<const Lazy>;
        /** Generate and store an unevaluated backtrace */
        [[nodiscard]] static inline Ptr create(const uint16_t ignore_frames,
                                               const int16_t max_frames = 0x1000) noexcept {
            try {
                std::ostringstream o;
                backward(o, static_cast<uint32_t>(ignore_frames) + 1, max_frames);
                return Ptr { new Lazy { std::move(o) } }; // no make_shared b/c priv ctor
            }
            UTIL_FALLBACKLOG_CATCH("failed");
            return {};
        }

        /** As string */
        inline std::string str() const {
            if (std::holds_alternative<std::ostringstream>(o)) {
                o = std::get<std::ostringstream>(o).str();
            }
            return std::get<std::string>(o);
        }

      private:
        /** Constructor */
        inline Lazy(std::ostringstream &&_o) : o { std::move(_o) } {}
        /** Representation */
        mutable std::variant<std::string, std::ostringstream> o;
    };
} // namespace Util::Backtrace

#endif