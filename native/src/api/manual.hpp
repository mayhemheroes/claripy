#ifndef R_API_MANUAL_HPP_
#define R_API_MANUAL_HPP_

#include <functional>
#include <pybind11/pybind11.h>

namespace API {

    /** Called by our API to insert additional non-autogenerated bindings */
    void bind_manual(std::function<pybind11::module &(std::string const &namespace_)> &m);

} // namespace API

#endif