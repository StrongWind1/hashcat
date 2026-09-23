/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_MD2_H
#define INC_HASH_MD2_H

typedef struct md2_ctx
{
  u32 h[4];
  u32 C[4];
  u32 L;

  u32 w0[4];

  int len;

} md2_ctx_t;

DECLSPEC void md2_transform (PRIVATE_AS u32 *h, PRIVATE_AS u32 *C, PRIVATE_AS u32 *L_ptr, PRIVATE_AS const u32 *block);
DECLSPEC void md2_init (PRIVATE_AS md2_ctx_t *ctx);
DECLSPEC void md2_update_64 (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len);
DECLSPEC void md2_update (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void md2_update_swap (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void md2_update_utf16le (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void md2_update_global (PRIVATE_AS md2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md2_update_global_swap (PRIVATE_AS md2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md2_update_global_utf16le (PRIVATE_AS md2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md2_final (PRIVATE_AS md2_ctx_t *ctx);

#endif
