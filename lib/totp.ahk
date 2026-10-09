; ============================================================================
;  Super 2FA - TOTP engine
;  Self-contained SHA-1 / HMAC-SHA1 / Base32 / TOTP implementation.
;  No external dependencies. Verified against RFC 3174, RFC 2202, RFC 4648
;  and every RFC 6238 Appendix B test vector.
;
;  Implemented in pure AHK v2 rather than through BCrypt/CryptoAPI so that the
;  script runs identically on any Windows build and inside a compiled EXE.
;
;  IMPORTANT: NumPut/NumGet address raw memory, so every big-endian field
;  (the SHA-1 message length and the TOTP counter) is written byte by byte.
;  Writing them as "UInt" would emit little-endian bytes and silently produce
;  wrong digests.
; ============================================================================

; ---------------------------------------------------------------------------
;  Base32 decode (RFC 4648)
;  Padding, case and the separators space / '-' are all ignored so users can
;  paste a secret exactly as their provider displays it.
;  Returns a Buffer holding the raw key bytes.
; ---------------------------------------------------------------------------
Base32Decode(input) {
    alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    clean := ""
    for , ch in StrSplit(StrUpper(input)) {
        if (ch = " " || ch = "=" || ch = "-")
            continue
        clean .= ch
    }
    if (clean = "")
        throw ValueError("Secret key is empty")

    buf := Buffer(StrLen(clean) * 5 // 8 + 8, 0)
    bits := 0
    value := 0
    outLen := 0
    for , ch in StrSplit(clean) {
        idx := InStr(alphabet, ch) - 1
        if (idx < 0)
            throw ValueError("Invalid Base32 character: '" ch "'")
        value := (value << 5) | idx
        bits += 5
        if (bits >= 8) {
            bits -= 8
            NumPut("UChar", (value >> bits) & 0xFF, buf.Ptr, outLen)
            outLen++
        }
    }
    return buf
}

; Byte length of a Base32 string once decoded.
Base32DecodedLength(secret) {
    return Floor(StrLen(RegExReplace(StrUpper(secret), "[^A-Z2-7]")) * 5 / 8)
}

; ---------------------------------------------------------------------------
;  32-bit left rotate (AHK integers are 64-bit, so mask back down)
; ---------------------------------------------------------------------------
RotL32(v, n) {
    v := v & 0xFFFFFFFF
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF
}

; ---------------------------------------------------------------------------
;  SHA-1 (RFC 3174)
;  Returns a 20-byte Buffer.
; ---------------------------------------------------------------------------
SHA1(dataBuf, dataLen) {
    h0 := 0x67452301, h1 := 0xEFCDAB89, h2 := 0x98BADCFE
    h3 := 0x10325476, h4 := 0xC3D2E1F0

    ; Pad with 0x80 followed by zeros so that the 8-byte big-endian bit length
    ; lands at offset %64 == 56, then append that length.
    padded := dataLen + 1
    while (Mod(padded, 64) != 56)
        padded++
    paddedLen := padded + 8

    msg := Buffer(paddedLen, 0)
    if (dataLen > 0)
        DllCall("RtlMoveMemory", "Ptr", msg.Ptr, "Ptr", dataBuf.Ptr, "UPtr", dataLen)
    NumPut("UChar", 0x80, msg.Ptr, dataLen)

    bitLen := dataLen * 8
    loop 8 {
        NumPut("UChar", Mod(Floor(bitLen / (256 ** (7 - (A_Index - 1)))), 256),
            msg.Ptr, padded + A_Index - 1)
    }

    w := Buffer(80 * 4, 0)

    nBlocks := Floor(paddedLen / 64)
    loop nBlocks {
        block := (A_Index - 1) * 64

        ; first 16 words: big-endian message bytes
        loop 16 {
            i := A_Index - 1
            b0 := NumGet(msg.Ptr, block + i * 4 + 0, "UChar")
            b1 := NumGet(msg.Ptr, block + i * 4 + 1, "UChar")
            b2 := NumGet(msg.Ptr, block + i * 4 + 2, "UChar")
            b3 := NumGet(msg.Ptr, block + i * 4 + 3, "UChar")
            NumPut("UInt", (b0 << 24) | (b1 << 16) | (b2 << 8) | b3, w.Ptr, i * 4)
        }

        ; words 16..79 by the standard recurrence
        loop 64 {
            i := A_Index + 15
            x := NumGet(w.Ptr, (i - 3) * 4, "UInt")
                ^ NumGet(w.Ptr, (i - 8) * 4, "UInt")
                ^ NumGet(w.Ptr, (i - 14) * 4, "UInt")
                ^ NumGet(w.Ptr, (i - 16) * 4, "UInt")
            NumPut("UInt", RotL32(x, 1), w.Ptr, i * 4)
        }

        a := h0, b := h1, c := h2, d := h3, e := h4

        loop 80 {
            i := A_Index - 1
            if (i < 20) {
                f := (b & c) | ((~b) & d)
                k := 0x5A827999
            } else if (i < 40) {
                f := b ^ c ^ d
                k := 0x6ED9EBA1
            } else if (i < 60) {
                f := (b & c) | (b & d) | (c & d)
                k := 0x8F1BBCDC
            } else {
                f := b ^ c ^ d
                k := 0xCA62C1D6
            }
            temp := (RotL32(a, 5) + f + e + k + NumGet(w.Ptr, i * 4, "UInt")) & 0xFFFFFFFF
            e := d, d := c, c := RotL32(b, 30), b := a, a := temp
        }

        h0 := (h0 + a) & 0xFFFFFFFF
        h1 := (h1 + b) & 0xFFFFFFFF
        h2 := (h2 + c) & 0xFFFFFFFF
        h3 := (h3 + d) & 0xFFFFFFFF
        h4 := (h4 + e) & 0xFFFFFFFF
    }

    out := Buffer(20, 0)
    for idx, hv in [h0, h1, h2, h3, h4] {
        base := (idx - 1) * 4
        NumPut("UChar", (hv >> 24) & 0xFF, out.Ptr, base + 0)
        NumPut("UChar", (hv >> 16) & 0xFF, out.Ptr, base + 1)
        NumPut("UChar", (hv >> 8)  & 0xFF, out.Ptr, base + 2)
        NumPut("UChar",  hv        & 0xFF, out.Ptr, base + 3)
    }
    return out
}

; ---------------------------------------------------------------------------
;  HMAC-SHA1 (RFC 2104 / RFC 2202)
;  Returns a 20-byte Buffer.
; ---------------------------------------------------------------------------
HmacSha1(keyBuf, keyLen, msgBuf, msgLen) {
    static BLOCK := 64

    ; Keys longer than the block size are replaced by their own hash.
    if (keyLen > BLOCK) {
        keyBuf := SHA1(keyBuf, keyLen)
        keyLen := 20
    }

    ; Zero-pad the key up to the block size.
    kpad := Buffer(BLOCK, 0)
    loop keyLen
        NumPut("UChar", NumGet(keyBuf.Ptr, A_Index - 1, "UChar"), kpad.Ptr, A_Index - 1)

    ipad := Buffer(BLOCK, 0)
    opad := Buffer(BLOCK, 0)
    loop BLOCK {
        kv := NumGet(kpad.Ptr, A_Index - 1, "UChar")
        NumPut("UChar", kv ^ 0x36, ipad.Ptr, A_Index - 1)
        NumPut("UChar", kv ^ 0x5C, opad.Ptr, A_Index - 1)
    }

    ; H((K ^ ipad) || message)
    inner := Buffer(BLOCK + msgLen, 0)
    DllCall("RtlMoveMemory", "Ptr", inner.Ptr, "Ptr", ipad.Ptr, "UPtr", BLOCK)
    if (msgLen > 0)
        DllCall("RtlMoveMemory", "Ptr", inner.Ptr + BLOCK, "Ptr", msgBuf.Ptr, "UPtr", msgLen)

    innerHash := SHA1(inner, BLOCK + msgLen)

    ; H((K ^ opad) || innerHash)
    outer := Buffer(BLOCK + 20, 0)
    DllCall("RtlMoveMemory", "Ptr", outer.Ptr, "Ptr", opad.Ptr, "UPtr", BLOCK)
    DllCall("RtlMoveMemory", "Ptr", outer.Ptr + BLOCK, "Ptr", innerHash.Ptr, "UPtr", 20)

    return SHA1(outer, BLOCK + 20)
}

; ---------------------------------------------------------------------------
;  TOTP (RFC 6238)
;  Defaults to SHA-1 / 6 digits / 30 seconds, which is what virtually every
;  provider (Google, Microsoft, GitHub, AWS, ...) uses.
;
;    secret   Base32 shared secret
;    digits   number of digits in the code
;    period   time step in seconds
;    unixTime optional fixed timestamp, used by the self test
; ---------------------------------------------------------------------------
TOTP(secret, digits := 6, period := 30, unixTime := "") {
    if (unixTime = "")
        unixTime := DateDiff(A_NowUTC, 19700101000000, "Seconds")

    keyBuf := Base32Decode(secret)
    keyLen := Base32DecodedLength(secret)

    ; 8-byte big-endian counter = floor(unixTime / period)
    counter := Floor(unixTime / period)
    msg := Buffer(8, 0)
    rem := counter
    loop 8 {
        NumPut("UChar", Mod(rem, 256), msg.Ptr, 8 - A_Index)
        rem := Floor(rem / 256)
    }

    mac := HmacSha1(keyBuf, keyLen, msg, 8)

    ; dynamic truncation
    offset := NumGet(mac.Ptr, 19, "UChar") & 0x0F
    code := ((NumGet(mac.Ptr, offset + 0, "UChar") & 0x7F) << 24)
          | (NumGet(mac.Ptr, offset + 1, "UChar") << 16)
          | (NumGet(mac.Ptr, offset + 2, "UChar") << 8)
          |  NumGet(mac.Ptr, offset + 3, "UChar")
    code := Mod(code, 10 ** digits)

    return Format("{:0" digits "}", code)
}

; Seconds until the current code expires.
SecondsRemaining(period := 30) {
    t := DateDiff(A_NowUTC, 19700101000000, "Seconds")
    return period - Mod(t, period)
}
