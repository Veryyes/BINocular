// Single class with virtual methods, no inheritance.
// Tests baseline vtable extraction: one class, one vtable, no RTTI type hierarchy.
#include <cstdio>
#include <cstring>

class Logger {
public:
    char tag[32];
    int  level;

    Logger(const char* t, int lvl) : level(lvl) {
        strncpy(tag, t, sizeof(tag) - 1);
        tag[sizeof(tag) - 1] = '\0';
    }

    virtual ~Logger() {}

    virtual void log(const char* msg) {
        printf("[%s] %s\n", tag, msg);
    }

    virtual void warn(const char* msg) {
        printf("[%s] WARN: %s\n", tag, msg);
    }

    virtual void error(const char* msg) {
        printf("[%s] ERROR: %s\n", tag, msg);
    }

    virtual int get_level() const {
        return level;
    }
};

int main() {
    Logger l("app", 1);
    l.log("started");
    l.warn("low memory");
    l.error("disk full");
    printf("level=%d\n", l.get_level());
    return 0;
}
