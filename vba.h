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

#define VBA_SALT_STRING             {'v', 'b', 'a'}

#define VBA_TAG_SECURED             2
#define VBA_TAG_UNSECURED           1



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
    union {
        struct {
            uint16_t Z;
            uint8_t H[VBA_HASH_LENGTH];
        };
        uint8_t raw[VBA_SUFFIX_LENGTH];
    } suffix;
} __attribute__((packed)) vba_t;

/**
 * A pseudo network interface to use for generating VBAs.
 */
typedef
struct {
    uint8_t     *link_layer_id;
    size_t      link_layer_id_length;
    uint8_t     *subnet_prefix;
    size_t      subnet_prefix_length;
} __attribute__((packed)) pseudo_net_dev_t;

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
            uint8_t     __padding[1];
            uint16_t     memory_size[2];
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
 * Process raw input data into a new link voucher object.
 */
int ndopt__process_link_voucher(
    void                        *input_data,
    nd_link_voucher_option_t    **new_voucher
);

/**
 * Generate a new VBA object and return it.
 */
int vba__generate(
    pseudo_net_dev_t    *net_device,
    uint16_t            *work_factor,
    vba_t               **new_vba
);

/**
 * Verify an input VBA based on the currently-stored Voucher information.
 */
int vba__verify(
    vba_t   *vba,
    uint8_t *ndar_link_layer_id,
    size_t  ndar_link_layer_id_length
);



#endif   /* LIB_VBA_H */
