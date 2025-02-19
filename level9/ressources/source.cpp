#include <string.h>
#include <memory.h>

class Foo {
    public:
        Foo(int value) : value(value) {}

        void setAnnotation(const char *str) {
            memcpy(buffer, str, strlen(str));
        }

        virtual int operator+(const Foo& rhs) {
            return value + rhs.value;
        }

        virtual int operator-(const Foo& rhs) {
            return value - rhs.value;
        }

    private:
        char buffer[100];
        int value;
};

int main(int argc, char **argv) {
    if (argc != 2) {
        return 1;
    }

    Foo *instance1 = new Foo(5);
    Foo *instance2 = new Foo(6);

    return *instance2 + *instance1;
}