#ifndef LINUX_INJECTION_DETECTOR_H
#define LINUX_INJECTION_DETECTOR_H

#include "injection_detector.h"
#include "injection_dependency.h"
#include <dlfcn.h>          // Required for dlsym, RTLD_NEXT, RTLD_DEFAULT

#ifdef USE_SHA256_CTX
#include <openssl/sha.h>     // Required for SHA256 checksum calculation
#else
#include <openssl/evp.h> // Required for the new EVP API
#endif

#include <iostream>
#include <fstream>
#include <sstream>           // Required for stringstream
#include <iomanip>           // Required for setw, setfill
#include <vector>            // Required for std::vector
#include <string>
#include <link.h>            // For ELF-related functions
#include <algorithm>         // For std::find

// Function to verify the integrity of dlsym
void VerifyDlsymIntegrity() {
    void* actualDlsymAddr = dlsym(RTLD_NEXT, "dlsym");
    void* originalDlsymAddr = dlsym(RTLD_DEFAULT, "dlsym");

    if (actualDlsymAddr != originalDlsymAddr) {
        std::cerr << "Potential dlsym hook detected!" << std::endl;
        std::cerr << "Original dlsym address: " << originalDlsymAddr << std::endl;
        std::cerr << "Current dlsym address: " << actualDlsymAddr << std::endl;
    } else {
        std::cout << "dlsym integrity verified." << std::endl;
    }
}

// Function to verify the integrity of GOT (Global Offset Table) entries
void VerifyGOTIntegrity() {
    std::cout << "Verifying GOT integrity..." << std::endl;
    // Normally, you would need access to the ELF binary structure to extract the GOT addresses
    // Here we check a few standard library functions
    void* printfAddr = dlsym(RTLD_DEFAULT, "printf");
    void* correctPrintfAddr = (void*)&printf;  // This is the actual address of printf

    if (printfAddr != correctPrintfAddr) {
        std::cerr << "GOT hook detected for printf!" << std::endl;
        std::cerr << "Original address: " << correctPrintfAddr << std::endl;
        std::cerr << "Current address: " << printfAddr << std::endl;
    } else {
        std::cout << "GOT integrity verified for printf." << std::endl;
    }
}

// Function to verify vtable integrity
void VerifyVtableIntegrity(MyClass* obj) {
    void** vtable = *(void***)obj;  // Get the vtable of the object
    void (MyClass::*expectedFunc)() = &MyClass::MyFunction;  // Get the correct member function pointer
    //void* expectedFuncAddr = (void*)&MyClass::MyFunction;
    //void* expectedFuncAddr = (void*)&printf; // This is the actual address of printf

    std::cout << "Checking vtable for MyClass object..." << std::endl;
    //if (vtable[0] != expectedFuncAddr) {
    if (*(void**)&expectedFunc != vtable[0]) {
        std::cerr << "Potential vtable hijack detected! Function address in vtable: "
                  //<< vtable[0] << ", Expected address: " << expectedFuncAddr << std::endl;
                  //<< vtable[0] << ", Expected address: " << expectedFunc << std::endl;
                  << vtable[0] << ", Expected address: " << *(void**)&expectedFunc << std::endl;
    } else {
        std::cout << "Vtable integrity verified." << std::endl;
    }
}

bool isSystemLibrary(const std::string& libPath) {
    //std::cout << "find(/lib/): " << libPath.find("/lib/") << std::endl;
    //std::cout << "find(/usr/lib/): " << libPath.find("/usr/lib/") << std::endl;
    return libPath.find("/lib/") == 0 || libPath.find("/usr/lib/") == 0;
}


// Compute the SHA256 checksum of a file
std::string ComputeFileChecksum(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return "";
    }

#ifdef USE_SHA256_CTX
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
#else
// Use the EVP API instead of SHA256_CTX
EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
const EVP_MD* md = EVP_sha256();

if (mdctx == nullptr || EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
    std::cerr << "Failed to initialize EVP context" << std::endl;
    return "";
}
#endif

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
#ifdef USE_SHA256_CTX
        SHA256_Update(&sha256, buffer, file.gcount());
#else
        EVP_DigestUpdate(mdctx, buffer, file.gcount());
#endif
    }

#ifdef USE_SHA256_CTX
    SHA256_Update(&sha256, buffer, file.gcount()); // For remaining bytes
#else
    EVP_DigestUpdate(mdctx, buffer, file.gcount()); // For remaining bytes
#endif

#ifdef USE_SHA256_CTX
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len = SHA256_DIGEST_LENGTH;
    SHA256_Final(hash, &sha256);
#else
unsigned char hash[EVP_MAX_MD_SIZE];
unsigned int hash_len;
EVP_DigestFinal_ex(mdctx, hash, &hash_len);

// Clean up
EVP_MD_CTX_free(mdctx);
#endif

    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}


class LinuxInjectionDetector : public InjectionDetector {
public:
    // Verify the checksums of loaded shared objects
    void DetectModuleInjection() override {
        std::cout << "Checking for shared object injection..." << std::endl;
        std::ifstream mapsFile("/proc/self/maps");
        std::string line;
        // Example of legitimate shared objects
        std::vector<std::string> monitoredLibs = {
            "/lib/x86_64-linux-gnu/libc.so.6", 
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libm.so.6",
            "/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30",
            "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
            // Add more legitimate libraries here for comparison
        };

        while (std::getline(mapsFile, line)) {
            std::cout << "Memory map entry: " << line << std::endl;

            // Check for suspicious entries or unexpected shared objects.
            if (line.find(".so") != std::string::npos) {
                std::string libPath = ExtractPathFromMap(line);
                std::cout << "Checking library: " << libPath << std::endl;

                if (isSystemLibrary(libPath)) {
                    std::cout << "System library detected '" << libPath << "'. Skipping..." << std::endl;
                    continue;  // Skip system libraries
                }

                if (std::find(monitoredLibs.begin(), monitoredLibs.end(), libPath) == monitoredLibs.end()) {
                    std::cout << "Suspicious shared object detected: " << libPath << std::endl;
                    continue;
                }

                std::string checksum = ComputeFileChecksum(libPath);
                std::cout << "SHA256 Checksum for " << libPath << ": " << checksum << std::endl;
                // You can store and compare this checksum with a previously computed "good" checksum
            }
        }
        mapsFile.close();
    }

    void DetectIATInjection() override {
        // In Linux, "IAT-like" injections could be checked by verifying dlsym or library hooking
        // This would involve checking the function resolution system (similar to IAT) for integrity.
        // Typically, Linux does not have a direct IAT, but you can monitor for manipulation via dlsym or by LD_PRELOAD.

        std::cout << "Checking for IAT-like injection (Linux shared objects)..." << std::endl;
        VerifyDlsymIntegrity();
        VerifyGOTIntegrity();
    }

    void DetectFunctionPointerInjection() override {
        // FAT-like injection in Linux could involve monitoring virtual function tables.
        // FAT injection detection can be specific to vtable manipulation or function pointer overwrites

        std::cout << "Checking for function pointer injections (virtual table or function hook monitoring)..." << std::endl;
        MyClass obj;
        VerifyVtableIntegrity(&obj);
    }

private:
    // Extract the path of the shared object from the memory map entry
    std::string ExtractPathFromMap(const std::string& mapEntry) {
        std::size_t pos = mapEntry.find("/");
        if (pos != std::string::npos) {
            return mapEntry.substr(pos);
        }
        return "";
    }
};

#endif // LINUX_INJECTION_DETECTOR_H
