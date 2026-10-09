#Requires AutoHotkey v2.0
#NoTrayIcon
#SingleInstance Off

; ============================================================================
;  Super 2FA - crypto self test
;
;  Verifies the TOTP engine in lib\totp.ahk against the published test
;  vectors, so a broken build can be spotted without touching the tray app.
;
;  Run with:   "C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe" selftest.ahk
;  Exit code:  0 = all passed, 1 = at least one failure
;  Report:     selftest-report.txt next to this script
; ============================================================================

#Include lib\totp.ahk

global FAILURES := 0
global REPORT := A_ScriptDir "\selftest-report.txt"

try FileDelete(REPORT)

Log(s) {
    global REPORT
    FileAppend(s "`n", REPORT, "UTF-8")
}

HexOf(buf, len) {
    h := ""
    loop len
        h .= Format("{:02x}", NumGet(buf.Ptr, A_Index - 1, "UChar"))
    return h
}

Check(label, got, expect) {
    global FAILURES
    ok := (got = expect)
    if !ok
        FAILURES++
    Log((ok ? "PASS  " : "FAIL  ") label)
    if !ok {
        Log("      expected: " expect)
        Log("      got:      " got)
    }
}

; ---------------------------------------------------------------------------
Log("Super 2FA self test - " FormatTime(, "yyyy-MM-dd HH:mm:ss"))
Log("AHK " A_AhkVersion " (" (A_PtrSize * 8) "-bit)")
Log("")

; --- SHA-1 (RFC 3174 / FIPS 180-1) -----------------------------------------
; Buffer(N) then StrPut needs N+1 bytes for the terminator, so allocate size+1
; and pass the real byte count to the hash.
b := Buffer(4, 0)
StrPut("abc", b.Ptr, "UTF-8")
Check("SHA1 of 'abc'", HexOf(SHA1(b, 3), 20),
    "a9993e364706816aba3e25717850c26c9cd0d89d")

e := Buffer(1, 0)
Check("SHA1 of empty string", HexOf(SHA1(e, 0), 20),
    "da39a3ee5e6b4b0d3255bfef95601890afd80709")

; 56 bytes forces a second block, exercising the padding boundary
longStr := "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
longBuf := Buffer(StrLen(longStr) + 1, 0)
StrPut(longStr, longBuf.Ptr, "UTF-8")
Check("SHA1 of 56-byte string", HexOf(SHA1(longBuf, StrLen(longStr)), 20),
    "84983e441c3bd26ebaae4aa1f95129e5e54670f1")

; --- HMAC-SHA1 (RFC 2202) --------------------------------------------------
k1 := Buffer(20, 0x0b)
msg1 := "Hi There"
d1 := Buffer(StrLen(msg1) + 1, 0)
StrPut(msg1, d1.Ptr, "UTF-8")
Check("HMAC-SHA1 case 1", HexOf(HmacSha1(k1, 20, d1, StrLen(msg1)), 20),
    "b617318655057264e28bc0b6fb378c8ef146be00")

k2 := Buffer(5, 0)
StrPut("Jefe", k2.Ptr, "UTF-8")
msg2 := "what do ya want for nothing?"
d2 := Buffer(StrLen(msg2) + 1, 0)
StrPut(msg2, d2.Ptr, "UTF-8")
Check("HMAC-SHA1 case 2", HexOf(HmacSha1(k2, 4, d2, StrLen(msg2)), 20),
    "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")

; key longer than the 64-byte block, which triggers the key-hash branch
k3 := Buffer(80, 0xaa)
msg3 := "Test Using Larger Than Block-Size Key - Hash Key First"
d3 := Buffer(StrLen(msg3) + 1, 0)
StrPut(msg3, d3.Ptr, "UTF-8")
Check("HMAC-SHA1 case 6 (long key)", HexOf(HmacSha1(k3, 80, d3, StrLen(msg3)), 20),
    "aa4ae5e15272d00e95705637ce8a3b55ed402112")

; --- Base32 (RFC 4648) -----------------------------------------------------
Check("Base32 of RFC 6238 secret",
    HexOf(Base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), 20),
    "3132333435363738393031323334353637383930")

; --- TOTP (RFC 6238 Appendix B, SHA-1, 8 digits) ---------------------------
s := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
Check("TOTP t=59",          TOTP(s, 8, 30, 59),          "94287082")
Check("TOTP t=1111111109",  TOTP(s, 8, 30, 1111111109),  "07081804")
Check("TOTP t=1111111111",  TOTP(s, 8, 30, 1111111111),  "14050471")
Check("TOTP t=1234567890",  TOTP(s, 8, 30, 1234567890),  "89005924")
Check("TOTP t=2000000000",  TOTP(s, 8, 30, 2000000000),  "69279037")
Check("TOTP t=20000000000", TOTP(s, 8, 30, 20000000000), "65353130")

; --- user input tolerance --------------------------------------------------
ref := TOTP("JBSWY3DPEHPK3PXP", 6, 30, 0)
Check("secret in lowercase",    TOTP("jbswy3dpehpk3pxp", 6, 30, 0), ref)
Check("secret with '=' padding", TOTP("jbswy3dpehpk3pxp==", 6, 30, 0), ref)
Check("secret with spaces",     TOTP("JBSW Y3DP EHPK 3PXP", 6, 30, 0), ref)

; --- rejected input --------------------------------------------------------
badSecretRejected := false
try
    TOTP("0189!!!!", 6, 30, 0)
catch ValueError
    badSecretRejected := true
Check("invalid Base32 is rejected", badSecretRejected, true)

; ---------------------------------------------------------------------------
Log("")
Log(FAILURES = 0 ? "ALL TESTS PASSED" : FAILURES " TEST(S) FAILED")
Log("")
Log("Sample code for JBSWY3DPEHPK3PXP: " TOTP("JBSWY3DPEHPK3PXP"))
Log("Seconds left in current period: " SecondsRemaining())

ExitApp(FAILURES = 0 ? 0 : 1)
