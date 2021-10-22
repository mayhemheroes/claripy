/**
 * @file
 * \ingroup util
 * @brief This file defines a move-able lock
 */
#ifndef R_UTIL_THREADSAFE_MOVELOCK_HPP_
#define R_UTIL_THREADSAFE_MOVELOCK_HPP_

#include "../../macros.hpp"

#include <shared_mutex>


namespace Util::ThreadSafe {

    /** A move-able scoped lock
     *  If Mutex is not a shareable mutex, Shared must be false
     *  Compilation requires that if Shared then the class
     *  Mutex must implement lock_shared and unlock_shared
     */
    template <typename Mutex, bool Shared = false> class [[nodiscard]] MoveLock final {
      public:
        /** Constructor
         *  Lock on construction
         *  Shared lock if Shared, else exclusive lock
         */
        explicit MoveLock(Mutex &m) : mutex { &m } {
            if constexpr (Shared) {
                mutex->lock_shared();
            }
            else {
                mutex->lock();
            }
        }

        /** Move constructor
         *  Disables the auto-locking on destruction of old
         */
        explicit MoveLock(MoveLock &&old) noexcept : mutex { old.mutex } { old.mutex = nullptr; }

        /** Move assignment */
        MoveLock &operator=(MoveLock &&old) noexcept {
            UTILS_AFFIRM_NOT_NULL_DEBUG(old.mutex); // It is probably never intended to hit this
            if (this != &old) {
                mutex = old.mutex;
                old.mutex = nullptr;
            }
            return *this;
        }

        /** Destructor
         *  On destruction, unlock if the mutex pointer is valid
         *  If the mutex fails to unlock, the program is aborted
         */
        ~MoveLock() noexcept {
            if (mutex) { // NOLINT (false positive)
                if constexpr (Shared) {
                    mutex->unlock_shared();
                }
                else {
                    mutex->unlock();
                }
            }
        }

      private:
        /** The mutex to lock */
        Mutex *mutex;

        /** Delete default constructor */
        MoveLock() = delete;
        /** Delete copy constructor */
        MoveLock(const MoveLock &) = delete;
        /** Disable copy assignment */
        MoveLock &operator=(const MoveLock &) = delete;
    };

} // namespace Util::ThreadSafe

#endif