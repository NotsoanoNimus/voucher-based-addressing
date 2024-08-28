#include "generator.h"


static inline uint64_t rotl( const uint64_t x, int k ) {
    return ( (x << k) | (x >> (64 - k)) );
}


static uint64_t s[2];
static int s_seeded = 0;

uint64_t
Xoshiro128p__next_bounded(uint64_t low, uint64_t high)
{
    const uint64_t range = 1 + high - low;

    const uint64_t s0 = s[0];
    uint64_t s1 = s[1];
    const uint64_t result = s0 + s1;

    s1 ^= s0;
    s[0] = rotl( s0, 24 ) ^ s1 ^ (s1 << 16);
    s[1] = rotl( s1, 37 );

    return (
        ( high > low )
        * (
            (
                result
                % (
                    (
                        ( ( 0 == range ) * 1 )
                        + range
                    )
                )
            )
            + low
        )
    );
}

uint64_t Xoshiro128p__next_bounded_any()
{
    return Xoshiro128p__next_bounded(0, UINT64_MAX - 1);
}

void
Xoshiro128p__init()
{
    uint64_t seed_value;
    unsigned int lo, hi;
    tinymt64_t* p_prng_init;

    // Get the amount of cycles since the processor was powered on.
    //   This should act as a sufficient non-time-based PRNG seed.
    __asm__ __volatile__ (  "rdtsc" : "=a" (lo), "=d" (hi)  );
    seed_value = ( ((uint64_t)hi << 32) | lo );

    p_prng_init = (tinymt64_t*)calloc( 1, sizeof(tinymt64_t) );
    tinymt64_init( p_prng_init, seed_value );

    // Seed Xoshiro128+.
    s[0] = tinymt64_generate_uint64( p_prng_init );
    s[1] = tinymt64_generate_uint64( p_prng_init );

    free( p_prng_init );
    s_seeded = 1;
}
