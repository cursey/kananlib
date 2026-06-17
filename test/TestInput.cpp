#include <cstdint>
#include <iostream>

#include <Windows.h>

#include <utility/Input.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Input tests
// ============================================================================

int test_was_key_down_unpressed() {
    // VK_F24 is almost certainly not pressed during testing.
    // First call: current state is not pressed, previous was not pressed => false.
    auto result = utility::was_key_down(VK_F24);
    TEST_ASSERT(result == false);

    return 0;
}

int test_was_key_down_tracking() {
    // Call twice for the same unpressed key.
    // First call: not pressed now, not pressed before => false.
    // Second call: not pressed now, not pressed before => false.
    // The key_states tracking should not cause false positives.
    auto r1 = utility::was_key_down(VK_F23);
    auto r2 = utility::was_key_down(VK_F23);
    TEST_ASSERT(r1 == false);
    TEST_ASSERT(r2 == false);

    return 0;
}

int test_was_key_down_various_keys() {
    // Test with several different virtual keys that are unlikely to be pressed.
    // All should return false.
    uint32_t keys[] = { VK_F20, VK_F21, VK_F22, VK_OEM_CLEAR, 0xFF };
    for (auto key : keys) {
        auto result = utility::was_key_down(key);
        TEST_ASSERT(result == false);
    }

    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib Input test =====" << std::endl;

    // Input.
    RUN_TEST(test_was_key_down_unpressed);
    RUN_TEST(test_was_key_down_tracking);
    RUN_TEST(test_was_key_down_various_keys);

    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception." << std::endl;
    return 1;
}
