/// @file safetyhook/inline_hook.hpp
/// @brief Inline hooking class.

#pragma once

#ifndef SAFETYHOOK_USE_CXXMODULES
#include <cstdint>
#include "tl/expected.hpp"
#include <memory>
#include <mutex>
#include <utility>
#include <vector>
#else
import std.compat;
#endif

#include "safetyhook/allocator.hpp"
#include "safetyhook/common.hpp"
#include "safetyhook/utility.hpp"

namespace safetyhook {
/// @brief An inline hook.
class InlineHook final {
public:
    /// @brief Error type for InlineHook.
    struct Error {
        /// @brief The type of error.
        enum : uint8_t {
            BAD_ALLOCATION,                        ///< An error occurred when allocating memory.
            FAILED_TO_DECODE_INSTRUCTION,          ///< Failed to decode an instruction.
            SHORT_JUMP_IN_TRAMPOLINE,              ///< The trampoline contains a short jump.
            IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE,  ///< An IP-relative instruction is out of range.
            UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE, ///< An unsupported instruction was found in the trampoline.
            FAILED_TO_UNPROTECT,                   ///< Failed to unprotect memory.
            NOT_ENOUGH_SPACE,                      ///< Not enough space to create the hook.
        } type;

        /// @brief Extra information about the error.
        union {
            Allocator::Error allocator_error; ///< Allocator error information.
            uint8_t* ip;                      ///< IP of the problematic instruction.
        };

        /// @brief Create a BAD_ALLOCATION error.
        /// @param err The Allocator::Error that failed.
        /// @return The new BAD_ALLOCATION error.
        static Error bad_allocation(Allocator::Error err) {
            Error e; e.type = BAD_ALLOCATION; e.allocator_error = err;
            return e;
        }

        /// @brief Create a FAILED_TO_DECODE_INSTRUCTION error.
        /// @param ip The IP of the problematic instruction.
        /// @return The new FAILED_TO_DECODE_INSTRUCTION error.
        static Error failed_to_decode_instruction(uint8_t* ip) {
            Error e; e.type = FAILED_TO_DECODE_INSTRUCTION; e.ip = ip;
            return e;
        }

        /// @brief Create a SHORT_JUMP_IN_TRAMPOLINE error.
        /// @param ip The IP of the problematic instruction.
        /// @return The new SHORT_JUMP_IN_TRAMPOLINE error.
        static Error short_jump_in_trampoline(uint8_t* ip) {
            Error e; e.type = SHORT_JUMP_IN_TRAMPOLINE; e.ip = ip;
            return e;
        }

        /// @brief Create a IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE error.
        /// @param ip The IP of the problematic instruction.
        /// @return The new IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE error.
        static Error ip_relative_instruction_out_of_range(uint8_t* ip) {
            Error e; e.type = IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE; e.ip = ip;
            return e;
        }

        /// @brief Create a UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE error.
        /// @param ip The IP of the problematic instruction.
        /// @return The new UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE error.
        static Error unsupported_instruction_in_trampoline(uint8_t* ip) {
            Error e; e.type = UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE; e.ip = ip;
            return e;
        }

        /// @brief Create a FAILED_TO_UNPROTECT error.
        /// @param ip The IP of the problematic instruction.
        /// @return The new FAILED_TO_UNPROTECT error.
        static Error failed_to_unprotect(uint8_t* ip) { 
             Error e; e.type = FAILED_TO_UNPROTECT; e.ip = ip;
             return e;
        }

        /// @brief Create a NOT_ENOUGH_SPACE error.
        /// @param ip The IP of the problematic instruction.
        /// @return The new NOT_ENOUGH_SPACE error.
        static Error not_enough_space(uint8_t* ip) {
            Error e; e.type = NOT_ENOUGH_SPACE; e.ip = ip;
            return e;
        }
    };

    /// @brief Flags for InlineHook.
    enum Flags : int {
        Default = 0,            ///< Default flags.
        StartDisabled = 1 << 0, ///< Start the hook disabled.
    };

    /// @brief Create an inline hook.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @param flags The flags to use.
    /// @return The InlineHook or an InlineHook::Error if an error occurred.
    /// @note This will use the default global Allocator.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_inline).
    static tl::expected<InlineHook, Error> create(
        void* target, void* destination, Flags flags = Default);

    /// @brief Create an inline hook.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @param flags The flags to use.
    /// @return The InlineHook or an InlineHook::Error if an error occurred.
    /// @note This will use the default global Allocator.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_inline).
   template <typename Target, typename Destination>
    static tl::expected<InlineHook, Error> create(
       Target target, Destination destination, Flags flags = Default) {
        return create(FnPtr(target), FnPtr(destination), flags);
    }

    /// @brief Create an inline hook with a given Allocator.
    /// @param allocator The allocator to use.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @param flags The flags to use.
    /// @return The InlineHook or an InlineHook::Error if an error occurred.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_inline).
    static tl::expected<InlineHook, Error> create(
        const std::shared_ptr<Allocator>& allocator, void* target, void* destination, Flags flags = Default);

    /// @brief Create an inline hook with a given Allocator.
    /// @param allocator The allocator to use.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @param flags The flags to use.
    /// @return The InlineHook or an InlineHook::Error if an error occurred.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_inline).
    template <typename Target, typename Destination>
    static tl::expected<InlineHook, Error> create(
        const std::shared_ptr<Allocator>& allocator, Target target, Destination destination, Flags flags = Default) {
        return create(allocator, FnPtr(target), FnPtr(destination), flags);
    }

    InlineHook() = default;
    InlineHook(const InlineHook&) = delete;
    InlineHook(InlineHook&& other) noexcept;
    InlineHook& operator=(const InlineHook&) = delete;
    InlineHook& operator=(InlineHook&& other) noexcept;
    ~InlineHook();

    /// @brief Reset the hook.
    /// @details This will restore the original function and remove the hook.
    /// @note This is called automatically in the destructor.
    void reset();

    /// @brief Get a pointer to the target.
    /// @return A pointer to the target.
    uint8_t* target() const { return m_target; }

    /// @brief Get the target address.
    /// @return The target address.
    uintptr_t target_address() const { return reinterpret_cast<uintptr_t>(m_target); }

    /// @brief Get a pointer ot the destination.
    /// @return A pointer to the destination.
    uint8_t* destination() const { return m_destination; }

    /// @brief Get the destination address.
    /// @return The destination address.
    uintptr_t destination_address() const { return reinterpret_cast<uintptr_t>(m_destination); }

    /// @brief Get the trampoline Allocation.
    /// @return The trampoline Allocation.
    const Allocation& trampoline() const { return m_trampoline; }

    /// @brief Tests if the hook is valid.
    /// @return True if the hook is valid, false otherwise.
    explicit operator bool() const { return static_cast<bool>(m_trampoline); }

    /// @brief Returns the address of the trampoline to call the original function.
    /// @tparam T The type of the function pointer.
    /// @return The address of the trampoline to call the original function.
    template <typename T> T original() const { return reinterpret_cast<T>(m_trampoline.address()); }

    /// @brief Returns a vector containing the original bytes of the target function.
    /// @return A vector of the original bytes of the target function.
    const auto& original_bytes() const { return m_original_bytes; }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the default calling convention set by your compiler.
    template <typename RetT = void, typename... Args> RetT call(Args... args) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_trampoline ? original<RetT (*)(Args...)>()(args...) : RetT();
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __cdecl calling convention.
    template <typename RetT = void, typename... Args> RetT ccall(Args... args) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_trampoline ? original<RetT(SAFETYHOOK_CCALL*)(Args...)>()(args...) : RetT();
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __thiscall calling convention.
    template <typename RetT = void, typename... Args> RetT thiscall(Args... args) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_trampoline ? original<RetT(SAFETYHOOK_THISCALL*)(Args...)>()(args...) : RetT();
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __stdcall calling convention.
    template <typename RetT = void, typename... Args> RetT stdcall(Args... args) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_trampoline ? original<RetT(SAFETYHOOK_STDCALL*)(Args...)>()(args...) : RetT();
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __fastcall calling convention.
    template <typename RetT = void, typename... Args> RetT fastcall(Args... args) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_trampoline ? original<RetT(SAFETYHOOK_FASTCALL*)(Args...)>()(args...) : RetT();
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the default calling convention set by your compiler.
    /// @note This function is unsafe because it doesn't lock the mutex. Only use this if you don't care about unhook
    /// safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> RetT unsafe_call(Args... args) {
        return original<RetT (*)(Args...)>()(args...);
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __cdecl calling convention.
    /// @note This function is unsafe because it doesn't lock the mutex. Only use this if you don't care about unhook
    /// safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> RetT unsafe_ccall(Args... args) {
        return original<RetT(SAFETYHOOK_CCALL*)(Args...)>()(args...);
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __thiscall calling convention.
    /// @note This function is unsafe because it doesn't lock the mutex. Only use this if you don't care about unhook
    /// safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> RetT unsafe_thiscall(Args... args) {
        return original<RetT(SAFETYHOOK_THISCALL*)(Args...)>()(args...);
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __stdcall calling convention.
    /// @note This function is unsafe because it doesn't lock the mutex. Only use this if you don't care about unhook
    /// safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> RetT unsafe_stdcall(Args... args) {
        return original<RetT(SAFETYHOOK_STDCALL*)(Args...)>()(args...);
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __fastcall calling convention.
    /// @note This function is unsafe because it doesn't lock the mutex. Only use this if you don't care about unhook
    /// safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> RetT unsafe_fastcall(Args... args) {
        return original<RetT(SAFETYHOOK_FASTCALL*)(Args...)>()(args...);
    }

    /// @brief Enable the hook.
    tl::expected<void, Error> enable();

    /// @brief Disable the hook.
    tl::expected<void, Error> disable();

    /// @brief Check if the hook is enabled.
    bool enabled() const { return m_enabled; }

private:
    friend class MidHook;

    enum class Type {
        Unset,
        E9,
        FF,
    };

    uint8_t* m_target{};
    uint8_t* m_destination{};
    Allocation m_trampoline{};
    std::vector<uint8_t> m_original_bytes{};
    uintptr_t m_trampoline_size{};
    std::recursive_mutex m_mutex{};
    bool m_enabled{};
    Type m_type{Type::Unset};

    tl::expected<void, Error> setup(
        const std::shared_ptr<Allocator>& allocator, uint8_t* target, uint8_t* destination);
    tl::expected<void, Error> e9_hook(const std::shared_ptr<Allocator>& allocator);

#if SAFETYHOOK_ARCH_X86_64
    tl::expected<void, Error> ff_hook(const std::shared_ptr<Allocator>& allocator);
#endif

    void destroy();
};
} // namespace safetyhook
