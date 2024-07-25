/// @file safetyhook/easy.hpp
/// @brief Easy to use API for creating hooks.

#pragma once

#include "safetyhook/inline_hook.hpp"
#include "safetyhook/mid_hook.hpp"
#include "safetyhook/utility.hpp"
#include "safetyhook/vmt_hook.hpp"

namespace safetyhook {
/// @brief Easy to use API for creating an InlineHook.
/// @param target The address of the function to hook.
/// @param destination The address of the destination function.
/// @param flags The flags to use.
/// @return The InlineHook object.
template <typename Target, typename Destination>
inline InlineHook create_inline(Target target, Destination destination, InlineHook::Flags flags = InlineHook::Default) {
    if (auto hook = InlineHook::create(target, destination, flags)) {
        return std::move(*hook);
    } else {
        return {};
    }
}

/// @brief Easy to use API for creating a MidHook.
/// @param target the address of the function to hook.
/// @param destination The destination function.
/// @param flags The flags to use.
/// @return The MidHook object.
template <typename Target, typename Destination>
inline MidHook create_mid(Target target, MidHookFn destination, MidHook::Flags flags = MidHook::Default) {
    if (auto hook = MidHook::create(target, destination, flags)) {
        return std::move(*hook);
    } else {
        return {};
    }
}

/// @brief Easy to use API for creating a VmtHook.
/// @param object The object to hook.
/// @return The VmtHook object.
inline VmtHook create_vmt(void* object) {
    if (auto hook = VmtHook::create(object)) {
        return std::move(*hook);
    } else {
        return {};
    }
}

/// @brief Easy to use API for creating a VmHook.
/// @param vmt The VmtHook to use to create the VmHook.
/// @param index The index of the method to hook.
/// @param destination The destination function.
/// @return The VmHook object.
template <typename Destination>
inline VmHook create_vm(VmtHook& vmt, size_t index, Destination destination) {
    if (auto hook = vmt.hook_method(index, FnPtr(destination))) {
        return std::move(*hook);
    } else {
        return {};
    }
}

} // namespace safetyhook