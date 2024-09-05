#ifndef INJECTION_DETECTOR_H
#define INJECTION_DETECTOR_H

class InjectionDetector {
public:
    virtual ~InjectionDetector() {}

    // Detect DLL or SO injection
    virtual void DetectModuleInjection() = 0;

    // Detect IAT or similar injection
    virtual void DetectIATInjection() = 0;

    // Detect FAT or function pointer injections
    virtual void DetectFunctionPointerInjection() = 0;
};

#endif // INJECTION_DETECTOR_H
