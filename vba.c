#include "vba.h"

#include "generator.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>
#include <libscrypt.h>

#include <string.h>
#include <stdbool.h>



static int calculate_address_suffix(
    vba_t                       *vba,
    nd_link_voucher_option_t    *voucher,
    subnet_t                    *subnet,
    llid_t                      *link_layer_id,
    uint16_t                    work_factor
);



int
ndopt__process_link_voucher(void *input_data,
                            pseudo_net_dev_t *net_device,
                            nd_link_voucher_option_t **new_voucher)
{
    uint8_t *input = (uint8_t *)input_data;

    uint32_t argon_memory_size = 0;
    uint8_t *argon_memory_size_scroll = NULL;

    nd_link_voucher_option_t *voucher =
        (nd_link_voucher_option_t *)calloc(1, sizeof(nd_link_voucher_option_t));
    vba_algorithm_type_t *algo =
        (vba_algorithm_type_t *)calloc(1, sizeof(vba_algorithm_type_t));
    if (NULL == voucher || NULL == algo) return -1;

    if (VBA_LINK_VOUCHER_TYPE != input[0]) return -2;
    if (input[1] < 6) return -3;   /* vouchers should be a minimum of 48 bytes in length */

    voucher->type = VBA_LINK_VOUCHER_TYPE;
    voucher->length = input[1];
    voucher->expiration = *((uint16_t *)&input[2]);
    voucher->timestamp = *((uint64_t *)&input[12]);
    voucher->voucher_id = *((uint32_t *)&input[20]);
    memcpy(&(voucher->seed), &input[24], VBA_SEED_LENGTH);

    algo->type   = (input[40] << 8) | input[41];
    algo->length = (input[42] << 8) | input[43];
    switch (algo->type) {
        case VBA_PBKDF2_TYPE:
        case VBA_SCRYPT_TYPE:
            memcpy(&(algo->data), &input[44], sizeof(uint32_t));
            break;
        case VBA_ARGON2_TYPE:
            memcpy(&(algo->data), &input[44], sizeof(uint32_t));

            /* Readjust and confine the Argon MemorySize and Parallelism parameters here. */
            algo->data.argon2d_spec.parallelism = MAX(1, MIN(8, algo->data.argon2d_spec.parallelism >> 4));
            
            /* Although the spec doesn't limit the memory size, I really don't want to program to crash. */
            argon_memory_size_scroll = algo->data.argon2d_spec.memory_size;
            for (int i = 0; i < 3; ++i) {
                argon_memory_size += (0xFF & *(argon_memory_size_scroll + i)) << ((3-1-i) * 8);
            }

            /* MemorySize must be a multiple of 8*Parallelism */
            argon_memory_size += (argon_memory_size % (8 * algo->data.argon2d_spec.parallelism));

            /* I don't want 64KiB chosen every. single. time. So rather than below, I'm using a mod. */
            // argon_memory_size = MIN(64 *1024, argon_memory_size);   /* limit to 64 KiB */
            argon_memory_size %= (64 * 1024);

            /* Commit the adjusted memory size. */
            for (int i = 0; i < 3; ++i) {
                algo->data.argon2d_spec.memory_size[i] = 0xFF & (argon_memory_size >> ((3-1-i) * 8));
            }

            break;
        default: printf("%02X", input[41]); printf("  and Type: %u", algo->type); return -3;
    }

    voucher->algorithm_spec = algo;

    if (NULL != new_voucher) {
        *new_voucher = voucher;
    } else {
        /* Just free them if no one's going to use them. */
        free(algo);
        free(voucher);
    }

    return 0;
}


int
vba__generate(pseudo_net_dev_t *net_device,
              size_t subnet_index,
              uint16_t work_factor,
              vba_t **new_vba)
{
    int status = 0;
    vba_t *vba = NULL;

    if (NULL == net_device) {
        return -1;
    }

    if (subnet_index + 1 > net_device->subnet_prefixes_count) return -7;

    /* Copy in prefix information to the VBA. */
    vba = (vba_t *)calloc(1, sizeof(vba_t));
    vba->prefix_length = net_device->subnet_prefixes[subnet_index].length;
    memcpy(vba->prefix, net_device->subnet_prefixes[subnet_index].prefix, sizeof(vba->prefix));

    /* If the prefix length is less than 8 bytes, create some random noise. */
    if (vba->prefix_length < VBA_PREFIX_LENGTH) {
        for (size_t i = (VBA_PREFIX_LENGTH - 1); i >= vba->prefix_length; --i) {
            vba->prefix[i] = (uint8_t)Xoshiro128p__next_bounded_any();
        }
    }

    status = calculate_address_suffix(vba,
                                      net_device->active_voucher,
                                      &(net_device->subnet_prefixes[subnet_index]),
                                      &(net_device->link_layer_id),
                                      work_factor);
    if (0 != status) {
        free(vba);
        return -2;   /* Exception while calculating the address suffix. */
    }

    if (NULL != new_vba) {
        *new_vba = vba;
    } else {
        free(vba);
    }

    return 0;
}


int
vba__verify(pseudo_net_dev_t *verifier_device,
            ipv6_addr_t *ndar_ip,
            llid_t *ndar_link_layer_id)
{
    int status = 0;
    bool is_verified = false;
    uint16_t extracted_work_factor = 0;
    uint16_t z = 0;
    subnet_t addr_net = {0};
    vba_t *new_vba = NULL;

    if (
        NULL == verifier_device
        || NULL == ndar_ip
        || NULL == ndar_link_layer_id
    ) {
        return -1;   /* Invalid input parameter. */
    }

    new_vba = (vba_t *)calloc(1, sizeof(vba_t));

    /*
     * VBAs cannot use subnets smaller than /64 (8 bytes).
     *   If the indicated subnet is smaller, it can't be a VBA.
     */
    if ((ndar_ip->prefix_length * 8) > 64) goto Label__verify_RenderDecision;

    /* Copy all the current VBA info into the new one, then clear the suffix. */
    memcpy(new_vba, (vba_t *)ndar_ip, sizeof(vba_t));
    memset(new_vba->suffix.raw, 0x00, sizeof(new_vba->suffix.raw));

    /* NOTE: Really should have just made VBA prefix info a subnet_t type, but alas. */
    addr_net.length = new_vba->prefix_length,
    memcpy(addr_net.prefix, new_vba->prefix, sizeof(new_vba->prefix));

    /* First, extract the work factor component (L) from the NDAR IP address given by the neighbor. */
    z = ndar_ip->suffix.Z;
    /* L = ~(Z ^ Seed[0..1]) */
    extracted_work_factor = ~(z ^ *((uint16_t *)&(verifier_device->active_voucher->seed)));

    /* Now use these components to regenerate the address suffix. */
    status = calculate_address_suffix(new_vba,
                                      verifier_device->active_voucher,
                                      &addr_net,
                                      ndar_link_layer_id,
                                      extracted_work_factor);
    if (0 != status) {
        free(new_vba);
        return -2;   /* Exception while calculating the address suffix. */
    }

    /*
     * If the two VBAs match -- that is, both the one we computed locally AND the one given
     *   during NDP address resolution -- then the binding of the LLID to the IP address is
     *   legitimate. When this verification function returns a SUCCESS, the NDP implementation
     *   should continue caching and processing the communication with the neighbor. Otherwise,
     *   the neighbor should be denied communications, depending on IEM.
     */
    is_verified = (0 == memcmp(ndar_ip, new_vba, sizeof(vba_t)));
    // printf("\nIN:  ");
    // for (size_t i = 0; i < sizeof(vba_t); ++i) printf("%02X ", ((uint8_t *)ndar_ip)[i]);
    // printf("\nOUT: ");
    // for (size_t i = 0; i < sizeof(vba_t); ++i) printf("%02X ", ((uint8_t *)new_vba)[i]);
    // printf("\n");
    // fflush(stdout);

Label__verify_RenderDecision:

    /* NOTE: The `new_vba` object is not freed up here because cases would theoretically use it to enter NC entries. */

    switch (verifier_device->iem) {
        /* Neither AAD nor AGO regard verification results. */
        case VBA_IEM_AAD:
        case VBA_IEM_AGO:
            free(new_vba);
            return 0;
        case VBA_IEM_AGVL:
            /* Set the cache entry on the net device regardless of `is_verified`. */
            /* If the verification succeeded, tag the cache entry as SECURED. */
            /* If not, tag it as UNSECURED. */
            free(new_vba);
            return 0;   /* AGVL should always succeed here because the entry is cached. */
        case VBA_IEM_AGV:
            /* In strict mode, the address either passes or fails verification. */
            /* If the address is verified, make sure to cache it on the net device here. */
            free(new_vba);
            return (true == is_verified) ? 0 : -5;   /* Either SUCCESS or a verification failure. */
        default:
            free(new_vba);
            return -10;   /* Invalid IEM setting */
    }
}


void
vba__print(vba_t *vba,
           nd_link_voucher_option_t *voucher)
{
    printf("Prefix (/%u subnet): ", vba->prefix_length * 8);
    for (int i = 0; i < VBA_PREFIX_LENGTH; ++i) {
        printf("%02X", vba->prefix[i]);
        if (i > 0 && i < (VBA_PREFIX_LENGTH - 1) && (i % 2)) printf(":");
    }

    printf(" //  Suffix: ");
    for (int i = 0; i < VBA_PREFIX_LENGTH; ++i) {
        printf("%02X", vba->suffix.raw[i]);
        if (i > 0 && i < (VBA_PREFIX_LENGTH - 1) && (i % 2)) printf(":");
    }

    // printf(" //  Z: 0x"); for (int i = 0; i < 2; ++i) printf("%02X", ((uint8_t *)&(vba->suffix.Z))[i]);
    printf(" //  Z: 0x%04X", vba->suffix.Z);
    if (NULL != voucher) {
        printf(" //  L: 0x%04X", (uint16_t)~(vba->suffix.Z ^ *((uint16_t *)(voucher->seed))));
    }

    printf(" //  H: 0x"); for (int i = 0; i < 6; ++i) printf("%02X", vba->suffix.H[i]);
}



static
int
calculate_address_suffix(vba_t *vba,
                         nd_link_voucher_option_t *voucher,
                         subnet_t *subnet,
                         llid_t *link_layer_id,
                         uint16_t work_factor)
{
    const uint8_t hash_result_length = 32;
    uint8_t hash_result[hash_result_length] = {0};
    uint8_t *salt = NULL;
    uint16_t Z = 0;
    const char *vba_salt_string = VBA_SALT_STRING;

    uint8_t *memory_size_scroll = NULL;
    uint32_t memory_size = 0;

    uint8_t scaling_factor = 0;

    /* NOTE: The salt always uses the full 8 bytes of the prefix, even if the actual mask length is less. */
    /*   This is because generating nodes can pad their prefixes with noise; that can be used no problem. */
    size_t salt_length = link_layer_id->length + VBA_SALT_STRING_LENGTH + VBA_PREFIX_LENGTH;

    if (
        NULL == vba
        || NULL == voucher
        || NULL == subnet
        || NULL == link_layer_id
        || 0 == work_factor
    ) {
        return -1;   /* Invalid parameter. */
    }

    /* Calculate Z. */
    Z = ~(work_factor ^ *((uint16_t *)(voucher->seed)));

    /* Construct the KDF salt. */
    salt = (uint8_t *)calloc(1, salt_length);
    memcpy(salt, link_layer_id->id, link_layer_id->length);
    memcpy((salt + link_layer_id->length), vba_salt_string, VBA_SALT_STRING_LENGTH);
    memcpy((salt + link_layer_id->length + VBA_SALT_STRING_LENGTH), vba->prefix, VBA_PREFIX_LENGTH);

    /* Now get the hash results based on the algorithm from the voucher. */
    switch (voucher->algorithm_spec->type) {
        case VBA_PBKDF2_TYPE:
            if (0 != PKCS5_PBKDF2_HMAC((const char *)voucher->seed,
                                       VBA_SEED_LENGTH,
                                       (const uint8_t *)salt,
                                       (int)salt_length,
                                       (int)((int)work_factor * MAX(1, voucher->algorithm_spec->data.pbkdf2_spec.iterations_factor)),
                                       EVP_sha256(),
                                       (int)hash_result_length,
                                       hash_result)
            ) {
                fprintf(stderr, "The PBKDF2 KDF failed!\n");
                free(salt);
                return -3;
            }
            break;
        case VBA_ARGON2_TYPE:
            memory_size_scroll = (uint8_t *)&(voucher->algorithm_spec->data) + 1;

            /* Really having a big think on this 24-bit big-endian value. */
            for (int i = 0; i < 3; ++i) {
                memory_size += (0xFF & *(memory_size_scroll + i)) << ((3-1-i) * 8);
            }

            if (0 != argon2d_hash_raw((work_factor >> 8) + 1,
                                      (const uint32_t)memory_size,
                                      (const uint32_t)voucher->algorithm_spec->data.argon2d_spec.parallelism,
                                      (void *)voucher->seed,
                                      VBA_SEED_LENGTH,
                                      (void *)salt,
                                      salt_length,
                                      hash_result,
                                      (const size_t)hash_result_length)
            ) {
                fprintf(stderr, "The Argon2 KDF failed!\n");
                free(salt);
                return -3;
            }
            break;
        case VBA_SCRYPT_TYPE:
            scaling_factor = MIN(5, voucher->algorithm_spec->data.scrypt_spec.scaling_factor);

            if (0 != libscrypt_scrypt(voucher->seed,
                                      VBA_SEED_LENGTH,
                                      salt,
                                      salt_length,
                                      MAX(1 << (MIN(11, MAX(1, ((work_factor & 0xFF00) >> 8) / 24))), 2) << scaling_factor,   /* N */
                                      MAX(1, (work_factor & 0x0F)),   /* r */
                                      MAX(1, (work_factor & 0xF0)),   /* p */
                                      hash_result,
                                      hash_result_length)
            ) {
                fprintf(stderr, "The Scrypt KDF failed!\n");
                free(salt);
                return -3;
            }
            break;
        default:
            free(salt);
            return -2;   /* Unknown KDF/algo type. */
    }

    /* Now that the H value is computed and placed, compute Z. */
    memcpy(vba->suffix.raw, hash_result, VBA_SUFFIX_LENGTH);
    memcpy(vba->suffix.raw, &Z, sizeof(uint16_t));

    /* All done! */
    free(salt);
    return 0;
}
