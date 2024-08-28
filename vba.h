#ifndef LIB_VBA_H
#define LIB_VBA_H

#include <stddef.h>
#include <stdint.h>



#define VBA_LINK_VOUCHER_TYPE       63

#define VBA_PREFIX_LENGTH           8
#define VBA_SUFFIX_LENGTH           8
#define VBA_HASH_LENGTH             6
#define VBA_SEED_LENGTH             16
#define VBA_MAX_ALGO_TYPE_LENGTH    14

#define VBA_SALT_STRING             "vba"
#define VBA_SALT_STRING_LENGTH      3

#define VBA_TAG_SECURED             2
#define VBA_TAG_UNSECURED           1


#define MAX_PSEUDO_ADDRESSES        16
#define MAX_PSEDUO_SUBNETS          16



#define MAX(a,b) \
	((a) > (b) ? (a) : (b))
#define MIN(a,b) \
	((a) <= (b) ? (a) : (b))



/**
 * The set of predefined interface enforcement modes.
 */
typedef
enum {
    VBA_IEM_AAD,
    VBA_IEM_AGO,
    VBA_IEM_AGVL,
    VBA_IEM_AGV
} interface_enforcement_mode_t;

/**
 * Resulting VBA structure. It's just an IPv6 address.
 */
typedef
struct {
    uint8_t prefix[VBA_PREFIX_LENGTH];
    uint8_t prefix_length;
    union {
        struct {
            uint16_t Z;
            uint8_t H[VBA_HASH_LENGTH];
        };
        uint8_t raw[VBA_SUFFIX_LENGTH];
    } suffix;
} __attribute__((packed)) vba_t;

/**
 * IMPORTANT: There is nothing that distinguishes an IPv6 address from a VBA.
 *      They are one and the same and the types can be used interchangeably.
 */
typedef vba_t ipv6_addr_t;

/**
 * An inner packet object used in vouchers to specify the KDF parameters.
 * 
 * Rather than being parsed directly from an input packet data stream,
 *    this has to be dynamically created.
 */
typedef
struct {
    uint16_t     type;
    uint16_t     length;
    union {        
        struct {
            uint16_t    iterations_factor;
            uint8_t     __padding[2];
        } pbkdf2_spec;
        struct {
            uint8_t     parallelism;
            uint8_t     memory_size[3];
        } argon2d_spec;
        struct {
            uint8_t     scaling_factor;
            uint8_t     __padding[3];
        } scrypt_spec;
    } data;
} __attribute__((packed)) vba_algorithm_type_t;

/**
 * Specification-dictated type IDs for each KDF and an enum to easily reference them.
 */
#define VBA_PBKDF2_TYPE     1
#define VBA_ARGON2_TYPE     10
#define VBA_SCRYPT_TYPE     20
typedef
enum {
    VBA_ALGO_PBKDF2,
    VBA_ALGO_ARGON2,
    VBA_ALGO_SCRYPT
} vba_kdf_t;

/**
 * The parsed structure of an NDP LV option.
 */
typedef
struct {
    uint8_t                 type;
    uint8_t                 length;
    uint16_t                expiration;
    uint8_t                 __reserved[8];
    uint64_t                timestamp;
    uint32_t                voucher_id;
    uint8_t                 seed[VBA_SEED_LENGTH];
    vba_algorithm_type_t    *algorithm_spec;
    void                    *der_structure;   /* This is not used in this sample. */
    uint8_t                 __padding[8];
} __attribute__((packed)) nd_link_voucher_option_t;


/**
 * Subnet structure.
 */
typedef
struct {
    uint8_t prefix[VBA_PREFIX_LENGTH];
    size_t  length;
} subnet_t;

typedef
struct {
    uint8_t id[6];
    size_t  length;
} llid_t;

/**
 * A pseudo network interface to use for generating VBAs.
 */
typedef
struct {
    interface_enforcement_mode_t    iem;
    nd_link_voucher_option_t        *active_voucher;
    llid_t                          link_layer_id;
    subnet_t                        *subnet_prefixes;
    size_t                          subnet_prefixes_count;
    vba_t                           *address_pool;
    size_t                          address_count;
} __attribute__((packed)) pseudo_net_dev_t;



/**
 * Process raw input data into a new link voucher object.
 */
int
ndopt__process_link_voucher(
    void                        *input_data,
    pseudo_net_dev_t            *net_device,
    nd_link_voucher_option_t    **new_voucher
);

/**
 * Generate a new VBA object and return it.
 */
int
vba__generate(
    pseudo_net_dev_t    *net_device,
    size_t              subnet_index,
    uint16_t            work_factor,
    vba_t               **new_vba
);

/**
 * Verify an input VBA based on the currently-stored Voucher information.
 */
int
vba__verify(
    pseudo_net_dev_t            *verifier_device,
    ipv6_addr_t                 *ndar_ip,
    llid_t                      *ndar_link_layer_id
);

/**
 * Print the contents of a VBA.
 */
void
vba__print(
    vba_t *vba
);



#endif   /* LIB_VBA_H */
