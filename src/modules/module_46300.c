/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "ZIP PKWARE strong encryption AES-128";
static const u64   KERN_TYPE      = 23001;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_NOT_SALTED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS15
                                  | OPTS_TYPE_COMBI_PURE_SWAP;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$zip$3$*660e*128*1*b4630625c92b6e7848f6fd86*df2f62611b3d02d2c7e05a48dad57c7d93b0bac1362261ab533807afb69db856676aa6e350320130b5cbf27c55a48c0f75739654ac312f1cf5c37149557fc88a92c7e3dde8d23edd2b839036e88092a708b7e818bf1b6de92f0efb5cce184cceb11db6b3ca0527d0bdf1f1137ee6660d9890928cd80542ac1f439515519147c14d965b5ba107c6227f971e3e115170bf*$/zip$";

#define ZIP3_BITS 128

#include "hooks_common.c"

#include "zip_strong.c"
