#ifndef INJECTION_DEPENDENCY_H
#define INJECTION_DEPENDENCY_H

#include <iostream>

class MyClass {
public:
    virtual void MyFunction() {
        std::cout << "MyClass::MyFunction" << std::endl;
    }
};

#endif // INJECTION_DEPENDENCY_H
