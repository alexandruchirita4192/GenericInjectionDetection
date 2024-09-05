#include <memory>
#include <iostream>

#ifdef _WIN32
#include "windows_injection_detector.h"
#elif __linux__
#include "linux_injection_detector.h"
#endif

int main() {
    std::unique_ptr<InjectionDetector> detector;

#ifdef _WIN32
    detector = std::make_unique<WindowsInjectionDetector>();
#elif __linux__
    detector = std::make_unique<LinuxInjectionDetector>();
#endif

    if (detector) {
        detector->DetectModuleInjection();
        detector->DetectIATInjection();
        detector->DetectFunctionPointerInjection();
    } else {
        std::cerr << "Unsupported platform!" << std::endl;
    }

    return 0;
}
