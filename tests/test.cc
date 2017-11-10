#include <stdio.h>
#include <string.h>

// #define DONT_USE_SSE
#include <uuid/uuid.h>
#include "../uuid.h"

int
main()
{
    rapiduuid::Value uuid;
    rapiduuid::Parser parser;
    parser.generate(uuid);
    std::string s = parser.toString(uuid);
    rapiduuid::Value uuid2;
    if (!parser.fromString(s, uuid2)) {
        printf("fail in %d\n", __LINE__);
        return 1;
    }
    if (memcmp(&uuid.value[0], &uuid2.value[0], sizeof(uuid)) == 0) {
        printf("success\n");
        return 0;
    } else {
        printf("fail in %d\n", __LINE__);
        return 1;
    }
}
