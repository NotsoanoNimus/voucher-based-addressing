#include "vba.h"

#include "generator.h"

#include <string.h>
#include <stdio.h>



#define ASSERT(x) \
    if (!(x)) { \
        fprintf(stderr, "ERROR: Failed assertion at line %d of '%s'.\n", __LINE__, __FILE__); \
        goto Label__ErrorExit; \
    }



static pseudo_net_dev_t THIS_INTERFACE = {
    .iem                    = VBA_IEM_AGV,
    .active_voucher         = NULL,
    .link_layer_id          = {
        .id = {0xAB, 0xCD, 0xEF, 0x11, 0x22, 0x33},
        .length = 6
    },
    .subnet_prefixes        = NULL,
    .subnet_prefixes_count  = 0,
    .address_pool           = NULL,
    .address_count          = 0
};

static const subnet_t LINK_LOCAL_SUBNET_PREFIX = {
    .prefix = {0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .length = 8
};

static const subnet_t OTHER_LOCAL_SUBNET_PREFIX = {
    .prefix = {0x20, 0x01, 0x0D, 0xB8, 0xFF, 0xFF, 0x00, 0x00},
    .length = 6
};



int
main(int argc,
     char **argv)
{
    int status = 0;
    uint16_t work_factor = 0;

    uint32_t argon_memory_size = 0;
    uint8_t *argon_memory_size_scroll = NULL;

    /* Ready the PRNG. */
    Xoshiro128p__init();

    /* Initialize the dummy interface used for these tests. */
    THIS_INTERFACE.subnet_prefixes = (subnet_t *)calloc(MAX_PSEDUO_SUBNETS, sizeof(subnet_t));
    THIS_INTERFACE.subnet_prefixes_count = 2;

    memcpy(&(THIS_INTERFACE.subnet_prefixes[0]), &LINK_LOCAL_SUBNET_PREFIX, sizeof(subnet_t));
    memcpy(&(THIS_INTERFACE.subnet_prefixes[1]), &OTHER_LOCAL_SUBNET_PREFIX, sizeof(subnet_t));

    THIS_INTERFACE.address_pool = (vba_t *)calloc(MAX_PSEUDO_ADDRESSES, sizeof(vba_t));
    THIS_INTERFACE.address_count = 2;

    memcpy(&(THIS_INTERFACE.address_pool[0].prefix), &(LINK_LOCAL_SUBNET_PREFIX.prefix), LINK_LOCAL_SUBNET_PREFIX.length);
    THIS_INTERFACE.address_pool[0].prefix_length = LINK_LOCAL_SUBNET_PREFIX.length;
    THIS_INTERFACE.address_pool[0].suffix.Z = 0x1234;
    memset(&(THIS_INTERFACE.address_pool[0].suffix.H), 0xAB, 6);

    memcpy(&(THIS_INTERFACE.address_pool[1].prefix), &(OTHER_LOCAL_SUBNET_PREFIX.prefix), OTHER_LOCAL_SUBNET_PREFIX.length);
    THIS_INTERFACE.address_pool[1].prefix_length = OTHER_LOCAL_SUBNET_PREFIX.length;
    THIS_INTERFACE.address_pool[1].suffix.Z = 0xAABB;
    memset(&(THIS_INTERFACE.address_pool[1].suffix.H), 0x05, 6);

    /* Create a raw blob to feed to the LV option parser. */
    uint8_t raw_ndopt[] = {
        /* 0  */ VBA_LINK_VOUCHER_TYPE,   /* Type */
        /* 1  */ 0x08,   /* Length */
        /* 2  */ 0x12, 0x34,   /* Expiration */
        /* 4  */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   /* Reserved */
        /* 12 */ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,   /* Timestamp */
        /* 20 */ 0xDE, 0xAD, 0xBE, 0xEF,   /* Voucher ID */
        /* Leaving a gap here to randomize a seed. Offset 24. */
        /* 24 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Begin Algorithm Type object... */
        /* 40 */ 0x00, 0x00,   /* The type will be set dynamically. */
        /* 42 */ 0x00, 0x02,   /* Fortunately, all default types have a length of 2. */
        /* 44 */ 0x00, 0x00, 0x00, 0x00,   /* The value here is randomized based on the set type. */
        /* End Algorithm Type object. */
        /* Include the publickey DER block, this content doesn't matter for this sample code. */
        /* 48 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Padding, etc. etc. ... */
    };

    *((uint64_t *)(&raw_ndopt[24]))   = Xoshiro128p__next_bounded_any();
    *((uint64_t *)(&raw_ndopt[24+8])) = Xoshiro128p__next_bounded_any();

    raw_ndopt[41] = Xoshiro128p__next_bounded_any() % 3;
    if (0 == raw_ndopt[41])         raw_ndopt[41] = VBA_PBKDF2_TYPE;
    else if (1 == raw_ndopt[41])    raw_ndopt[41] = VBA_ARGON2_TYPE;
    else                            raw_ndopt[41] = VBA_SCRYPT_TYPE;

    switch (raw_ndopt[41]) {
        case VBA_PBKDF2_TYPE:
            /* Set the ITERATIONS_FACTOR. */
            *((uint16_t *)&raw_ndopt[44]) = (uint16_t)Xoshiro128p__next_bounded_any() % 256;
            break;
        case VBA_ARGON2_TYPE:
            raw_ndopt[44] = (uint8_t)Xoshiro128p__next_bounded_any();   /* Write in the Parallelism value here. */
            for (size_t i = 1; i < 4; ++i) raw_ndopt[44 + i] = (uint8_t)Xoshiro128p__next_bounded_any();
            break;
        case VBA_SCRYPT_TYPE:
            raw_ndopt[44] = (uint8_t)(Xoshiro128p__next_bounded_any() % 6);   /* SCALING_FACTOR */
            break;
    }

    printf("Parsing Link Voucher option...  "); fflush(stdout);
    status = ndopt__process_link_voucher((void *)raw_ndopt,
                                         &THIS_INTERFACE,
                                         &(THIS_INTERFACE.active_voucher));
    if (0 != status) goto Label__ErrorExit;
    ASSERT(NULL != THIS_INTERFACE.active_voucher);
    printf("OK\n");

    /* Generate two link-local VBAs and one for the other prefix. */
    printf("Generating VBAs...  "); fflush(stdout);

    for (size_t i = 0; i < 3; ++i) {
        printf("%lu ", i); fflush(stdout);
        vba_t *new_vba = NULL;

        work_factor = (uint16_t)Xoshiro128p__next_bounded_any();
        status = vba__generate(&THIS_INTERFACE, (i < 2) ? 0 : 1, work_factor, &new_vba);
        if (0 != status) break;

        memcpy(&(THIS_INTERFACE.address_pool[i + 2]), new_vba, sizeof(vba_t));
        THIS_INTERFACE.address_count++;
        free(new_vba);

        ASSERT(0 != THIS_INTERFACE.address_pool[i].suffix.Z);
    }

    if (0 != status) goto Label__ErrorExit;
    printf("OK\n");

    printf("Self-verifying interface addresses...  "); fflush(stdout);
    for (size_t i = 0; i < THIS_INTERFACE.address_count; ++i) {
        printf("%lu ", i); fflush(stdout);
        status = vba__verify(&THIS_INTERFACE,
                             &(THIS_INTERFACE.address_pool[i]),
                             &(THIS_INTERFACE.link_layer_id));

        if (VBA_IEM_AGV == THIS_INTERFACE.iem) {
            if (i < 2) {
                ASSERT(0 != status);   /* The first two addresses are STATIC and NOT VBAs. */
            } else {
                ASSERT(0 == status);   /* The other addresses ARE valid VBAs. */
            }
        }
    }
    printf("OK\n");

    printf("\n\nSUMMARY\nMac Address:\n");
    printf("\t");
    for (size_t i = 0; i < THIS_INTERFACE.link_layer_id.length; ++i) {
        printf("%02X%c", THIS_INTERFACE.link_layer_id.id[i], (i < (THIS_INTERFACE.link_layer_id.length - 1) ? '-' : ' '));
    }

    printf("\nAddresses:\n");
    for (size_t i = 0; i < THIS_INTERFACE.address_count; ++i) {
        printf("\t");
        vba__print(&(THIS_INTERFACE.address_pool[i]), THIS_INTERFACE.active_voucher);
        printf("\n");
    }

    printf("Important Voucher Details:\n");
    printf("\tSeed: 0x");
    for (int i = 0; i < VBA_SEED_LENGTH; ++i)
        printf("%02X", THIS_INTERFACE.active_voucher->seed[i]);

    printf("\n\tAlgorithm: "); fflush(stdout);
    switch (THIS_INTERFACE.active_voucher->algorithm_spec->type) {
        case VBA_PBKDF2_TYPE:
            printf(
                "PBKDF2  (ITERATIONS_FACTOR: %u)",
                THIS_INTERFACE.active_voucher->algorithm_spec->data.pbkdf2_spec.iterations_factor
            );
            break;
        case VBA_ARGON2_TYPE:
            argon_memory_size_scroll = THIS_INTERFACE.active_voucher->algorithm_spec->data.argon2d_spec.memory_size;
            for (int i = 0; i < 3; ++i) {
                argon_memory_size += (0xFF & *(argon_memory_size_scroll + i)) << ((3-1-i) * 8);
            }

            printf(
                "Argon2  (Parallelism: %u // MemorySize: %u)",
                THIS_INTERFACE.active_voucher->algorithm_spec->data.argon2d_spec.parallelism,
                argon_memory_size
            );
            break;
        case VBA_SCRYPT_TYPE:
            printf(
                "Scrypt  (SCALING_FACTOR: %u)",
                THIS_INTERFACE.active_voucher->algorithm_spec->data.scrypt_spec.scaling_factor
            );
            break;
        default:
            printf("UNKNOWN");
            break;
    }

    printf("\n\nAll checks passed!\n\n");
    return 0;

Label__ErrorExit:
    fprintf(stderr, "ERROR: Exit code '%d'.\n", status);
    return status;
}
