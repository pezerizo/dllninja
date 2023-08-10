#include <iostream>
#include "include\StaticInjector.h"

int main(int argc, char** argv){
    StaticInjector test;
    test.LoadPE(argv[1]);
    test.InjectDLL("AAAAAAAAAA");
    return 0;
}