#ifndef RAPIDUUID_UUID_H
#define RAPIDUUID_UUID_H

#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>

#include <string>

#if defined(__SSE2__) && !defined(DONT_USE_SSE)
    #include <x86intrin.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define likely(x) __builtin_expect(!!(x), 1)
    #define unlikely(x) __builtin_expect(!!(x), 0)
#else
    #define likely(x) (x)
    #define unlikely(x) (x)
#endif

namespace rapiduuid {

typedef struct {
    uint64_t value[2];
} Value;

class Parser {
public:

    Parser() {
        initSeed();
    }

    /*
     * Used xoroshiro128 (http://xoroshiro.di.unimi.it/)
     */
    void generate(Value& value) {
#if defined(__SSE2__) && !defined(DONT_USE_SSE)
        __m128i s0 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&seed_[0].value[0]));
        __m128i s1 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&seed_[1].value[0]));
        /*  result = s0 + s1  */
        _mm_store_si128(reinterpret_cast<__m128i *>(&value.value[0]), _mm_add_epi64(s0, s1));
        /*  s1 ^= s0  */
        s1 = _mm_xor_si128(s0, s1);
        /*  s[0] = ((s0 << 55) | (s0 >> 9)) ^ s1 ^ (s1 << 14)  */
        _mm_store_si128(reinterpret_cast<__m128i *>(&seed_[0].value[0]), 
            _mm_xor_si128(
                _mm_xor_si128(
                    _mm_or_si128(
                        _mm_slli_epi64(s0, 55),
                        _mm_srli_epi64(s0, 9)
                    ),
                    s1
                ),
                _mm_slli_epi64(s1, 14)
            )
        );
        /*  s[1] = (s1 << 36) | (s1 >> 28) */
        _mm_store_si128(reinterpret_cast<__m128i *>(&seed_[1].value[0]), 
            _mm_or_si128(
                _mm_slli_epi64(s1, 36),
                _mm_srli_epi64(s1, 28)
            )
        );
#else
        uint64_t *s = &seed_[0].value[0];
        uint64_t *v = &value.value[0];
        /*  first step  */
        uint64_t s0 = s[0];
        uint64_t s1 = s[1];
        v[0] = s0 + s1;
        s1 ^= s0;
        s[0] = ((s0 << 55) | (s0 >>9)) ^ s1 ^ (s1 << 14);
        s[1] = (s1 << 36) | (s1 >> 28);
        /*  second step  */
        s0 = s[2];
        s1 = s[3];
        v[1] = s0 + s1;
        s1 ^= s0;
        s[2] = ((s0 << 55) | (s0 >>9)) ^ s1 ^ (s1 << 14);
        s[3] = (s1 << 36) | (s1 >> 28);
#endif
    }

    bool fromString(const char *p, Value& value) const {
#if defined(__SSE2__) && !defined(DONT_USE_SSE)
        __m128i c_0 = _mm_set1_epi8('0');
        __m128i c_10 = _mm_set1_epi8(10);
        __m128i c_15 = _mm_set1_epi8(15);
        __m128i c_a = _mm_set1_epi8('a' - '0' - 10);
        /*  first 16 bytes  */
        __m128i src = _mm_loadu_si128(reinterpret_cast<const __m128i *>(p));
        /*  ensure only two hypers is symbols lower than '0'  */
        if (unlikely(_mm_movemask_epi8(_mm_cmplt_epi8(src, c_0)) != 0x2100)) {
            return false;
        }
        /*  substract '0' from all bytes  */
        __m128i d = _mm_sub_epi8(src, c_0);
        /*  create mask where result bytes greater than 10 so its a-f symbols  */
        __m128i m = _mm_cmpgt_epi8(d, c_10);
        /*  apply mask to left only needed bytes  */
        __m128i af = _mm_and_si128(c_a, m);
        /*  substract 'a' - '0' - 10 from each byte greater than 9  */
        d = _mm_sub_epi8(d, af);
        /*  ensure all values between 0 and 15  */
        if (unlikely(_mm_movemask_epi8(_mm_cmpgt_epi8(d, c_15)) != 0)) {
            printf("%d: false\n", __LINE__);
            return false;
        }
        /**/
        uint8_t *u = reinterpret_cast<uint8_t *>(&value.value[0]);
        uint8_t *u1 = reinterpret_cast<uint8_t *>(&d);
        *u++ = (u1[0] << 4) | u1[1];
        *u++ = (u1[2] << 4) | u1[3];
        *u++ = (u1[4] << 4) | u1[5];
        *u++ = (u1[6] << 4) | u1[7];
        *u++ = (u1[9] << 4) | u1[10];
        *u++ = (u1[11] << 4) | u1[12];
        *u++ = (u1[14] << 4) | u1[15];
        /*  next 16 bytes  */
        p += 16;
        src = _mm_loadu_si128(reinterpret_cast<const __m128i *>(p));
        /*  ensure only two hypers is symbols lower than '0'  */
        if (unlikely(_mm_movemask_epi8(_mm_cmplt_epi8(src, c_0)) != 0x84)) {
            return false;
        }
        d = _mm_sub_epi8(src, c_0);
        m = _mm_cmpgt_epi8(d, c_10);
        af = _mm_and_si128(c_a, m);
        d = _mm_sub_epi8(d, af);
        if (unlikely(_mm_movemask_epi8(_mm_cmpgt_epi8(d, c_15)) != 0)) {
            printf("%d: false\n", __LINE__);
            return false;
        }
        u1 = reinterpret_cast<uint8_t *>(&d);
        /**/
        *u++ = (u1[0] << 4) | u1[1];
        *u++ = (u1[3] << 4) | u1[4];
        *u++ = (u1[5] << 4) | u1[6];
        *u++ = (u1[8] << 4) | u1[9];
        *u++ = (u1[10] << 4) | u1[11];
        *u++ = (u1[12] << 4) | u1[13];
        *u++ = (u1[14] << 4) | u1[15];
        /*  last 4 bytes  */
        p += 4;
        src = _mm_loadu_si128(reinterpret_cast<const __m128i *>(p));
        /*  ensure only two hypers is symbols lower than '0'  */
        if (unlikely(_mm_movemask_epi8(_mm_cmplt_epi8(src, c_0)) & 0xf000)) {
            return false;
        }
        d = _mm_sub_epi8(src, c_0);
        m = _mm_cmpgt_epi8(d, c_10);
        af = _mm_and_si128(c_a, m);
        d = _mm_sub_epi8(d, af);
        if (unlikely(_mm_movemask_epi8(_mm_cmpgt_epi8(d, c_15)) & 0xf000)) {
            return false;
        }
        u1 = (uint8_t *) &d;
        /**/
        *u++ = (u1[12] << 4) | u1[13];
        *u++ = (u1[14] << 4) | u1[15];

        return true;
#else
        unsigned char c, c1, c2;

#define HEX(_c, _n) \
    if (_c >= '0' && _c <= '9') { \
        _n = _c - '0'; \
    } else { \
        c = _c | 0x20; \
        if (c >= 'a' && c <= 'f') { \
            _n = c - 'a' + 10; \
        } else { \
            return false; \
        } \
    }

#define PARSE() \
    HEX(p[0], c1); \
    HEX(p[1], c2); \
    p += 2; \
    *u++ = (c1 << 4) | c2;

        uint8_t *u = reinterpret_cast<uint8_t *>(&value.value[0]);
        PARSE(); PARSE(); PARSE(); PARSE();
        if (*p++ != '-') {
            return false;
        }
        PARSE(); PARSE();
        if (*p++ != '-') {
            return false;
        }
        PARSE(); PARSE();
        if (*p++ != '-') {
            return false;
        }
        PARSE(); PARSE();
        if (*p++ != '-') {
            return false;
        }
        PARSE(); PARSE(); PARSE(); PARSE(); PARSE(); PARSE();

        return true;
#undef HEX
#undef PARSE
#endif
    }

    bool fromString(const std::string& s, Value& value) const {
        return fromString(s.c_str(), value);
    }

    void toChars(Value& value, char *p) const {
        static const char *hex = "0123456789abcdef";
        uint8_t *u = reinterpret_cast<uint8_t *>(&value.value[0]);

#define PRINT() \
    *p++ = hex[*u >> 4]; \
    *p++ = hex[*u & 0x0f]; \
    u++;

        PRINT(); PRINT(); PRINT(); PRINT();
        *p++ = '-';
        PRINT(); PRINT();
        *p++ = '-';
        PRINT(); PRINT();
        *p++ = '-';
        PRINT(); PRINT();
        *p++ = '-';
        PRINT(); PRINT(); PRINT(); PRINT(); PRINT(); PRINT();

#undef PRINT
    }

    std::string toString(Value& value) const {
        static const char *hex = "0123456789abcdef";
        uint8_t *u = reinterpret_cast<uint8_t *>(&value.value[0]);
        std::string r;
        r.reserve(38);

#define PRINT() \
    r.push_back(hex[*u >> 4]); \
    r.push_back(hex[*u & 0x0f]); \
    u++;

        PRINT(); PRINT(); PRINT(); PRINT();
        r.push_back('-');
        PRINT(); PRINT();
        r.push_back('-');
        PRINT(); PRINT();
        r.push_back('-');
        PRINT(); PRINT();
        r.push_back('-');
        PRINT(); PRINT(); PRINT(); PRINT(); PRINT(); PRINT();

        return r;
#undef PRINT
    }

private:

    void initSeed() {
        /*  try to read from urandom  */
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd != -1) {
            int rc = read(fd, seed_, sizeof(seed_));
            close(fd);
            if (rc == sizeof(seed_)) {
                /*  success  */
                return;
            }
        }
        /*  init from random  */
        struct timeval now;
        gettimeofday(&now, NULL);
        srandom(now.tv_usec);
        long *p = reinterpret_cast<long *>(seed_);
        for (int i = 0; i < sizeof(seed_) / sizeof(long); i++) {
            p[i] = random();
        }
    }

    Value seed_[2];
};

}

#endif
