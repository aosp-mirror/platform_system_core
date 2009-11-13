// See http://b/2071670

int main() {
    float f = 10.0f;
    float* floatPointer = &f;
    // The following line used to incorrectly error: "Incompatible pointer or array types"
    int* buffer = (int*) floatPointer;
    return *buffer;
}
