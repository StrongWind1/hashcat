/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The line that carries the three internal keys of ZIP traditional encryption, shared by modes
// 46400 and 46410. A module defines ZIP4_TYPE and includes this file as one translation unit.
//
//   $zip$4$*type*key0*key1*key2$/zip$
//
//   type  0 for mode 46400, which tries whole passwords, and 1 for mode 46410, which works the
//         last six bytes of a password out of the keys and tries only what stands in front
//   key   8 hex digits each, the state of the cipher after the password has gone through it
//
// The keys come out of a known plaintext attack. They decrypt the archive as they are, and these
// modes find the password that produces them. The 24 hex digits modes 20500 and 20510 take are
// read as well and are written back in the form above.

static const char *SIGNATURE_ZIP4      = "$zip$4$";
static const char *SIGNATURE_ZIP4_STOP = "$/zip$";

static bool zip4_is_hex (const char *buf, const u32 len)
{
  for (u32 i = 0; i < len; i++)
  {
    if (is_valid_hex_char ((u8) buf[i]) == false) return false;
  }

  return true;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  const char *key[3];

  if (line_len == 24)
  {
    key[0] = &line_buf[0];
    key[1] = &line_buf[8];
    key[2] = &line_buf[16];
  }
  else
  {
    // signature, type and three keys with a separator in front of each, then the stop signature

    if (line_len != 7 + 2 + (3 * 9) + 6) return (PARSER_SIGNATURE_UNMATCHED);

    if (memcmp (line_buf, SIGNATURE_ZIP4, 7) != 0) return (PARSER_SIGNATURE_UNMATCHED);

    if (memcmp (&line_buf[line_len - 6], SIGNATURE_ZIP4_STOP, 6) != 0) return (PARSER_SIGNATURE_UNMATCHED);

    if ((line_buf[7] != '*') || (line_buf[9] != '*') || (line_buf[18] != '*') || (line_buf[27] != '*')) return (PARSER_SEPARATOR_UNMATCHED);

    // the other type belongs to the other mode

    if (line_buf[8] != '0' + ZIP4_TYPE) return (PARSER_HASH_VALUE);

    key[0] = &line_buf[10];
    key[1] = &line_buf[19];
    key[2] = &line_buf[28];
  }

  for (u32 i = 0; i < 3; i++)
  {
    if (zip4_is_hex (key[i], 8) == false) return (PARSER_HASH_ENCODING);

    // the kernel of mode 20500 takes a key as the number it is, that of mode 20510 as its bytes

    const u32 value = hex_to_u32 ((const u8 *) key[i]);

    digest[i] = (ZIP4_TYPE == 0) ? byte_swap_32 (value) : value;
  }

  digest[3] = 0;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u32 key[3];

  for (u32 i = 0; i < 3; i++) key[i] = (ZIP4_TYPE == 0) ? digest[i] : byte_swap_32 (digest[i]);

  return snprintf (line_buf, line_size, "%s*%d*%08x*%08x*%08x%s", SIGNATURE_ZIP4, ZIP4_TYPE, key[0], key[1], key[2], SIGNATURE_ZIP4_STOP);
}
