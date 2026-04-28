#!/usr/bin/env python3
"""
Offline dumper for encrypted embedded resources in the uploaded Zhgcllfd source tree.

It does not execute the target application. It copies all embedded resources,
decrypts the confirmed resource payloads, and provides a parser for the
VM-decrypted string table once CoreUtils.byte_1 has been dumped in a sandbox.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

RESOURCES = {
    "string_table_encrypted": "pjCvA5e88oGlCYclfo.iTkRnou2uybvuMxWn8",
    "vm_bytecode": "QweDNjNWrkMuFjhOOY.7PhYAwGiHKPtcJlEoL",
    "rsa_xml_encrypted": "r4JutVgxFonyP9i9Tx.MG7FmYrAOfQK2prLU1",
    "embedded_assembly_encrypted": "x0y6b3U8enEOD9FDxN.teZHJmdV98NX3nlK2L",
}

# Final key for x0... after the XOR adjustment in EmbeddedAssemblyResolver.LoadEmbeddedAssembly().
X0_FINAL_KEY = bytes([
    177, 143, 172, 0, 162, 105, 109, 100,
    139, 70, 128, 151, 68, 144, 3, 68,
    192, 207, 0, 149, 42, 11, 101, 113,
    60, 196, 6, 112, 53, 99, 180, 104,
])

# Recovered from VM method 0 instructions 52-1567.
R4_AES_KEY = bytes.fromhex("ae9f905bc5797ac31b8bb4dc443d5ea3f69264afc323b2fbe1ca1ab059c5ccc5")
R4_AES_IV = bytes.fromhex("6a2fa8c399e7020aab789823ed037800")

# Recovered from VM method 0 final CoreUtils.method_1 call for pj...
# The second byte[] argument at that call is ignored by CoreUtils.method_1.
PJ_BLOCK_KEY = bytes.fromhex("7a147683fbe80c0e828bda06d7169f4c9a52217cb8b4b22ff77bf9b4d9745f41")
PJ_UNUSED_ARG = bytes.fromhex("f9ae00d241ac63cc023ec2bcd7ba957a")

# Signed emulation of w_w_init field initializer. Used to resolve source expressions:
#   CoreUtils.DecryptString(NUM ^ w_w_init.FIELD)
FIELD_VALUES = {
  "m_035b6ca06f6e470ab9a8c286697ef6d4": 0,
  "m_03ff6234b5ed4c8e9adb46e4574d7fad": 0,
  "m_100b7112fe2a47e080faefef30b45e2a": 506646568,
  "m_102b861aca554c87b68e5cb69d5bdd29": 917401311,
  "m_169403f4427d45199917bc1f8c3a3133": 721019653,
  "m_1730fcfeb13f4872989b03edced03445": 0,
  "m_1881c708a29f44d8b4cdd91502944a3e": 0,
  "m_1a741304e2b142ab94f75396253c2497": 1333237347,
  "m_1a8c17a27ec14c7484719d202c955137": 0,
  "m_1fbf7d08f39941f8922b1ad9beb87458": 329235098,
  "m_210fee39d55d4d6bad694eed571e3a70": 1919701228,
  "m_23d5f4e2f786497dbbf1ace2f3f79caa": 1091208039,
  "m_2beb39c75d9b4951873644897556a1a3": 1561979285,
  "m_2d16dc59b87a44bf9b25740af8feaaaa": 0,
  "m_2d54e40271f04380b33032fb5764bfec": 1615241337,
  "m_2e1f33cd77494db5806512749809a778": 0,
  "m_301eb42ce72840ac91d5f3e8cf23e0fe": 0,
  "m_31a2d4590f894aa4bd81e36ff36c666c": 0,
  "m_334c286cd5e444999ffa058ee49fff2a": 1294510024,
  "m_3434fe139b234603ab11c77d1b0299e9": 0,
  "m_352fbe0f2b1f49749a789a24d7510b4d": 1441451246,
  "m_3563a5140c9242ed899df441c057e313": 0,
  "m_3800866ccaba4035a22aaca2b412a724": 0,
  "m_3ce4b38e4ee04c55baa2826bd39f174e": 716954967,
  "m_3d3308cd9d3d40f89ff2743984eff2e2": 0,
  "m_3ea1ed2fd2224252b73b102ab3ea37a6": 0,
  "m_3fec4728cba14d41bf8520c179496a15": 2090036010,
  "m_4612b9fc528a4f12a0a26351ff217784": 1413336386,
  "m_46b4bb49c593421aa86738ab913b5dad": 0,
  "m_4af34bafb56445dba8b5e58edf93f97e": 1418940171,
  "m_4f9ab44761974fe7b2d55e2ae986f649": 0,
  "m_562061dd10024b73b834219fce15741a": 0,
  "m_5815cbd5645241108d7b3b54698f68df": 1168653215,
  "m_581d87da4a7b4df19f3a210e52393b7b": 211340940,
  "m_5b39dfff475f4acd96e8ebf7dcc94307": 1585575879,
  "m_5d4f9af24c2d4827a87977a2bc811d53": 0,
  "m_5e564226cad44991976b07ba4e87e991": 1858198012,
  "m_629087e072ff4c5ab551c1447a98f209": 1446325557,
  "m_62dc7d4ad59f409ca9142254f43af2af": 422127815,
  "m_64fd4ad3707b40c5aec7ed096eee6d3c": 0,
  "m_759f6f99f6ff4acfb432d4418b4950e8": 0,
  "m_76d73a8e4f0c4ae7bb32532ac75d385c": 812430323,
  "m_78c8d4f4ede5424b888af4fb126de53f": 1375655513,
  "m_794ca674c0ec43ab9ffcdc22745875fe": 0,
  "m_7dd283836f174eb2a71c3584cf5e3f1c": 1213345869,
  "m_7f12dad4ce024e4cbad052dc32a5c5f1": 1048381692,
  "m_802af64c10544611928a2523815897e4": 0,
  "m_81dd0bdfc9f3462aa16d3463e5cd6fdf": 1620121475,
  "m_82260a1789d64346b2f13a493ddbbda1": 0,
  "m_870ddef22be643a284187c9edeed0399": 0,
  "m_8cfa2f59790b44ab9519e8dbaf16fa3f": 0,
  "m_8f75a0a4cf4f4a81a390ee9d7eaa4c25": 0,
  "m_917a3e3ec91d4bbdb156faf4da57745b": 0,
  "m_91b1f58d9aa648d99385ca564a07ff38": 1414250909,
  "m_92b4a1e277c84f268e3f070fff082b38": 821861951,
  "m_9500f3afea2e4d9094b44c1e5976afdc": 0,
  "m_9550a94905c04d88a26fe1fb6836fb6f": 0,
  "m_97950e7d29b14a0b950582160034d54e": 266803523,
  "m_9a6f5c1af2fe4f7aa07ecb88cded01fc": 486555252,
  "m_a40143fe48144c3e9e21b4b54aa9f679": 0,
  "m_a4872f8a2f0f4424a5211527eb51db70": 0,
  "m_a7ac05c9d80944608e53cfa37cb165cc": 1515791557,
  "m_a7dc239f473c4d21b6de2590d1cd9aaa": 1317075904,
  "m_a93b1f247e544260b732808e5f503610": 1094569094,
  "m_aa03b7bebfd14dfeacea670364b8c91a": 2034042992,
  "m_adab15cea28343b8884497afb1d77b1c": 211823198,
  "m_aec67166448e46a491bf940babf9f23b": 0,
  "m_b063ae10d36a44c9855c0511db2a529d": 1605448848,
  "m_b0e48acae5184bf28078647a4e96df1e": 289224785,
  "m_b25750aad3b4472a806c95f2b61ac2bf": 913196530,
  "m_b60b5f6b15144051859fda82005ee052": 0,
  "m_b6adc311de254882876684f566e9dbcf": 1944279332,
  "m_b91a8a1975034982853e3e738e47e6bf": 2058383186,
  "m_bc3036a82f014754bf10642e5f03e8a3": 0,
  "m_bc3a9d91abb74229b735038f708c8b3f": 0,
  "m_bc67cf73b0eb4edfb75c7575d7e42fdf": 0,
  "m_bf4e01b994e9452b9e77b0907bb42707": 0,
  "m_c0ab27d440894e7296d8a65e3c94cf94": 0,
  "m_c19f7daddc294369aac84284c48261cb": 1553860429,
  "m_c1da106b895c42c7afd7535baf109f7b": 0,
  "m_c1f3435eb58a455a8a0a15c07cd00517": 0,
  "m_c392adfee3984e9e843c4bb5c1f86ce6": 0,
  "m_c7ee1c91195c404eb532b164b5349838": 961552783,
  "m_c888e2c088984a68abed9152b5dcdeec": 0,
  "m_ca62a4ac997f439aa13862cb61fda3ce": 1112201757,
  "m_cc046ef63d944710b418593c0cdb0394": 0,
  "m_cffa546edc3a4db68d6d5a4ef3b0a112": 0,
  "m_d429c2314cfa4c84a7455f8922387564": 1733704064,
  "m_d45cde37c91849a39ea7beda9ccf0a66": 231134715,
  "m_d4e7d0deeca549ac81b347483b503f1f": 0,
  "m_d62365e6581f47aab1a81e8c54a04a9b": 2055304925,
  "m_db40e2d911d64ea6955986de6b0d91a2": 1879536294,
  "m_e030648cb7dd42b7bbd93533bdea4843": 976890214,
  "m_e3c32e59b8694189af9b1d7db448742a": 424700829,
  "m_e41b9d37a37842fdba7f8580aaea07c0": 0,
  "m_e844675453974384b2858b7f6158f9e5": 626894280,
  "m_eb781ce6f87d4d7da96c2b9254a9daf4": 0,
  "m_eca4160cb9344da5a2bb9687c5878f77": 1413518956,
  "m_ee172d5d81e048d58452dfa4182f4134": 0,
  "m_ee205ef25ad3429c94b58c7a97a4d855": 0,
  "m_f190ea1f4bda49edacdca5cd363db49a": 0,
  "m_f3e6ac1b1500444e8a7d83787fde8150": 1791078909,
  "m_f57023e5f75846a29acf679e7c84ecce": 1244322156,
  "m_f75e94968ebf41e0874e57891797c7d3": 0,
  "m_f9cdc75c19e64e4da31ba2466ba813a8": 1970530940,
  "m_fa8e4fdc62a44115b4a310d10007635b": 0,
  "m_fd71ab44afbc4c5b958cc26ec292a240": 0,
  "m_fe1eddd5e76040fdb29c6d7e0bd54a08": 0
}
KNOWN_STRING_OFFSETS = [
  0,
  68,
  88,
  156,
  176,
  244,
  288,
  356,
  370,
  438,
  466,
  534,
  564,
  632,
  650,
  718,
  748,
  816,
  834,
  902,
  930,
  998,
  1014,
  1082,
  1110,
  1178,
  1204,
  1272,
  1288,
  1356,
  1386,
  1454,
  1504,
  1572,
  1610,
  1678,
  1692,
  1760,
  1802,
  1870,
  1900,
  1968,
  1984,
  2052,
  2080,
  2148,
  2174,
  2242,
  2260,
  2328,
  2362,
  2430,
  2458,
  2526,
  2554,
  2622,
  2640,
  2708,
  2736,
  2804,
  2820,
  2888,
  2904,
  2972,
  3002,
  3070,
  3084,
  3152,
  3168,
  3236,
  3250,
  3318,
  3354,
  3422,
  3436,
  3504,
  3532,
  3600,
  3616,
  3684,
  3752,
  3820,
  3888,
  3932,
  4000,
  4068,
  4136,
  4166,
  4234,
  4302,
  4330,
  4372,
  4392,
  4444,
  4460,
  4522,
  4602,
  4616,
  4670,
  4682,
  4742,
  4764,
  4834,
  4858,
  4898,
  4916,
  4964,
  4978,
  5026,
  5052,
  5090,
  5106,
  5146,
  5164,
  5202,
  5218,
  5276,
  5296,
  5362,
  5390,
  5444,
  5456,
  5564,
  5586,
  5652,
  5668,
  5720,
  5736,
  5774,
  5790,
  5832,
  5852,
  5892,
  5910,
  5962,
  5978,
  6024,
  6038,
  6074,
  6088,
  6126,
  6142,
  6204,
  6228,
  6270,
  6290,
  6330,
  6348,
  6404,
  6422,
  6464,
  6484,
  6538,
  6554,
  6588,
  6630,
  6650,
  6700,
  6712,
  6728,
  6758,
  6776,
  6806,
  6864,
  6888,
  6906,
  6930,
  6976,
  6994,
  7014,
  7034,
  7054,
  7070,
  7100,
  7136,
  7158,
  7170,
  7232,
  7258,
  7272,
  7278,
  7296,
  7332,
  7360,
  7380,
  7396,
  7422,
  7456,
  7464,
  7474,
  7516,
  7524,
  7530,
  7564,
  7592,
  7626,
  7652,
  7696,
  7740,
  7804,
  7830,
  7836,
  7842,
  7860,
  7884,
  7970,
  7988,
  7994,
  8016,
  8026,
  8052,
  8058,
  8080,
  8088,
  8112,
  8120,
  8144,
  8156,
  8198,
  8210,
  8252,
  8264,
  8306,
  8318,
  8360,
  8384,
  8546,
  8622,
  8644,
  8716,
  8810,
  9394,
  9942,
  10026,
  13646,
  13660,
  13682,
  13760,
  13774
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rd_u32_le(buf: bytes, off: int = 0) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def block_decrypt(key: bytes, data: bytes) -> bytes:
    """Python port of CoreUtils.method_1(byte_2, byte_3, byte_4).

    The original routine ignores byte_3 and writes the result into CoreUtils.byte_1.
    """
    if len(key) < 4 or len(key) % 4:
        raise ValueError("key length must be a non-zero multiple of 4")

    block_count = len(data) // 4 + (1 if len(data) % 4 else 0)
    remainder = len(data) % 4
    key_words = len(key) // 4
    out = bytearray(len(data))
    state = 0

    for i in range(block_count):
        state = (state + rd_u32_le(key, (i % key_words) * 4)) & 0xFFFFFFFF

        if i == block_count - 1 and remainder:
            enc = 0
            for j in range(remainder):
                if j > 0:
                    enc = (enc << 8) & 0xFFFFFFFF
                enc |= data[len(data) - 1 - j]
        else:
            enc = rd_u32_le(data, i * 4)

        original_state = state
        num14 = 47755737
        num15 = (3942225760 ^ state) & 0xFFFFFFFF
        num16 = num15 & 0x00FF00FF
        num15 &= 0xFF00FF00
        num17 = ((num15 >> 8) | (num16 << 8)) & 0xFFFFFFFF
        num19 = (-num17) & 0xFFFFFFFF
        num13 = state or 0xFFFFFFFF
        num20 = (num17 // num13 + num13) & 0xFFFFFFFF
        num13 = (num17 - num20) & 0xFFFFFFFF
        num19 = (10476 * (num19 & 0xFFFF) - (num19 >> 16)) & 0xFFFFFFFF
        num17 = (22014 * num17 + num13) & 0xFFFFFFFF
        num13 = (num13 ^ ((num13 << 9) & 0xFFFFFFFF)) & 0xFFFFFFFF
        num13 = (num13 + num19) & 0xFFFFFFFF
        num13 = (num13 ^ ((num13 << 1) & 0xFFFFFFFF)) & 0xFFFFFFFF
        num13 = (num13 + num13) & 0xFFFFFFFF
        num13 = (num13 ^ (num13 >> 5)) & 0xFFFFFFFF
        num13 = (num13 + num14) & 0xFFFFFFFF
        num13 = (((((num19 << 11) & 0xFFFFFFFF) + num17) ^ num19) + num13) & 0xFFFFFFFF
        state = (original_state + num13) & 0xFFFFFFFF

        dec = state ^ enc
        dec_bytes = struct.pack("<I", dec)
        if i == block_count - 1 and remainder:
            out[i * 4:] = dec_bytes[:remainder]
        else:
            out[i * 4:i * 4 + 4] = dec_bytes

    return bytes(out)


def qclz_decompress(src: bytes, offset: int = 0) -> bytes:
    """Decompress the QCLZ-like payload used by the x0 resource."""
    if src[offset:offset + 4] != b"QCLZ":
        return src[offset:]

    def u32_at(o: int) -> int:
        if o + 4 > len(src):
            return 0
        return rd_u32_le(src, o)

    out_len = u32_at(offset + 12)
    mode = u32_at(offset + 16)
    if out_len == 0:
        return b""
    if mode != 1:
        return src[offset + 32:offset + 32 + out_len]

    p = offset + 32
    out = bytearray()
    bitbuf = 1
    literal_lengths = [4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0]
    literal_tail_limit = out_len - 4

    while len(out) < literal_tail_limit:
        if bitbuf == 1:
            bitbuf = u32_at(p)
            p += 4
        num3 = u32_at(p)
        if bitbuf & 1:
            bitbuf >>= 1
            if (num3 & 3) == 0:
                distance = (num3 & 0xFF) >> 2
                length = 3
                p += 1
            elif (num3 & 2) == 0:
                distance = (num3 & 0xFFFF) >> 2
                length = 3
                p += 2
            elif (num3 & 1) == 0:
                distance = (num3 & 0xFFFF) >> 6
                length = ((num3 >> 2) & 0xF) + 3
                p += 2
            elif (num3 & 4) == 0:
                distance = (num3 & 0xFFFFFF) >> 8
                length = ((num3 >> 3) & 0x1F) + 3
                p += 3
            elif (num3 & 8) == 0:
                distance = num3 >> 15
                length = ((num3 >> 4) & 0x7FF) + 3
                p += 4
            else:
                b = (num3 >> 16) & 0xFF
                length = (num3 >> 4) & 0xFFF
                p += 3
                out.extend([b] * length)
                continue
            if distance == 0 or distance > len(out):
                raise ValueError(f"invalid QCLZ back-reference distance={distance}, out={len(out)}")
            for _ in range(length):
                out.append(out[-distance])
        else:
            n = literal_lengths[bitbuf & 0xF]
            out.extend(src[p:p + n])
            p += n
            bitbuf >>= n

    while len(out) < out_len:
        if bitbuf == 1:
            p += 4
            bitbuf = 0x80000000
        if p >= len(src):
            break
        out.append(src[p])
        p += 1
        bitbuf >>= 1

    return bytes(out[:out_len])


def find_resource(root: Path, name: str) -> Optional[Path]:
    direct = root / name
    if direct.exists():
        return direct
    matches = list(root.rglob(name))
    return matches[0] if matches else None


def pkcs7_strip(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data


def openssl_aes256_cbc_nopad(ciphertext: bytes, key: bytes, iv: bytes) -> Tuple[Optional[bytes], Optional[str]]:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / "in.bin"
        outp = Path(td) / "out.bin"
        inp.write_bytes(ciphertext)
        cmd = [
            "openssl", "enc", "-d", "-aes-256-cbc",
            "-K", key.hex(), "-iv", iv.hex(), "-nopad",
            "-in", str(inp), "-out", str(outp),
        ]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        except FileNotFoundError:
            return None, "openssl command not found"
        if proc.returncode != 0:
            return None, proc.stderr.decode(errors="replace")
        return outp.read_bytes(), None


def parse_utf16_string_at(buf: bytes, offset: int) -> Optional[str]:
    if offset < 0 or offset + 4 > len(buf):
        return None
    length = rd_u32_le(buf, offset)
    if length < 0 or offset + 4 + length > len(buf) or length % 2:
        return None
    try:
        return buf[offset + 4:offset + 4 + length].decode("utf-16le")
    except UnicodeDecodeError:
        return None


def parse_all_known_strings(buf: bytes, offsets: Iterable[int]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for off in sorted(set(offsets)):
        s = parse_utf16_string_at(buf, off)
        if s is not None:
            result[str(off)] = s
    return result


def resolve_string_offset_expressions(source_root: Path) -> List[dict]:
    """Resolve CoreUtils.DecryptString(NUM ^ w_w_init.FIELD) calls in the source."""
    pattern = re.compile(r"CoreUtils\.DecryptString\((\d+)\s*\^\s*w_w_init\.[A-Za-z0-9_]+\.([A-Za-z0-9_]+)\)")
    records: List[dict] = []
    for cs in sorted(source_root.rglob("*.cs")):
        try:
            text = cs.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        line_starts = [0]
        for m in re.finditer("\n", text):
            line_starts.append(m.end())
        for m in pattern.finditer(text):
            literal = int(m.group(1))
            field = m.group(2)
            value = FIELD_VALUES.get(field)
            offset = None if value is None else (literal ^ int(value))
            # Compute 1-based line number cheaply.
            line = 1
            lo, hi = 0, len(line_starts)
            pos = m.start()
            while lo < hi:
                mid = (lo + hi) // 2
                if line_starts[mid] <= pos:
                    lo = mid + 1
                else:
                    hi = mid
            line = lo
            records.append({
                "file": str(cs.relative_to(source_root)),
                "line": line,
                "literal": literal,
                "field": field,
                "field_value": value,
                "resolved_offset": offset,
            })
    return records


def main() -> int:
    ap = argparse.ArgumentParser(description="Dump/decrypt confirmed encrypted resources from the Zhgcllfd source tree")
    ap.add_argument("source_root", type=Path, help="Path to extracted Zhgcllfd source directory")
    ap.add_argument("output_dir", type=Path, help="Directory to write output")
    ap.add_argument("--decrypted-string-table", type=Path, default=None,
                    help="Optional full CoreUtils.byte_1 dump from pj...; parse known UTF-16 strings")
    args = ap.parse_args()

    root = args.source_root.resolve()
    outdir = args.output_dir.resolve()
    rawdir = outdir / "raw"
    decdir = outdir / "decrypted"
    vmdir = outdir / "vm"
    rawdir.mkdir(parents=True, exist_ok=True)
    decdir.mkdir(parents=True, exist_ok=True)
    vmdir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "source_root": str(root),
        "resources": {},
        "decryption": {},
        "vm": {},
        "safety": "This dumper only reads/writes local files and does not execute the target application.",
    }

    located: Dict[str, Path] = {}
    for label, name in RESOURCES.items():
        path = find_resource(root, name)
        if not path:
            manifest["resources"][label] = {"name": name, "found": False}
            continue
        data = path.read_bytes()
        located[label] = path
        raw_out = rawdir / name
        shutil.copyfile(path, raw_out)
        manifest["resources"][label] = {
            "name": name,
            "found": True,
            "size": len(data),
            "sha256": sha256(data),
            "raw_dump": str(raw_out.relative_to(outdir)),
            "first16_hex": data[:16].hex(),
        }

    # x0... => block decrypt => QCLZ => PE.
    x0 = located.get("embedded_assembly_encrypted")
    if x0:
        raw = x0.read_bytes()
        block = block_decrypt(X0_FINAL_KEY, raw)
        block_path = decdir / f"{RESOURCES['embedded_assembly_encrypted']}.block_decrypted_qclz.bin"
        block_path.write_bytes(block)
        pe = qclz_decompress(block)
        pe_path = decdir / "embedded_assembly_from_x0.dll"
        pe_path.write_bytes(pe)
        manifest["decryption"]["embedded_assembly_encrypted"] = {
            "routine": "CoreUtils.method_1-style block decrypt, then QCLZ-like decompression",
            "key_hex": X0_FINAL_KEY.hex(),
            "block_decrypted": {
                "path": str(block_path.relative_to(outdir)),
                "size": len(block),
                "sha256": sha256(block),
                "magic": block[:4].decode("ascii", errors="replace"),
            },
            "decompressed_payload": {
                "path": str(pe_path.relative_to(outdir)),
                "size": len(pe),
                "sha256": sha256(pe),
                "first16_hex": pe[:16].hex(),
                "starts_with_MZ": pe.startswith(b"MZ"),
            },
        }

    # r4... => AES-256-CBC no-pad => PKCS#7-stripped RSA XML.
    r4 = located.get("rsa_xml_encrypted")
    if r4:
        raw = r4.read_bytes()
        dec, err = openssl_aes256_cbc_nopad(raw, R4_AES_KEY, R4_AES_IV)
        r4_info = {
            "routine": "AES-256-CBC with recovered VM key/IV; ciphertext is decrypted with -nopad, then PKCS#7 stripped if valid",
            "key_hex": R4_AES_KEY.hex(),
            "iv_hex": R4_AES_IV.hex(),
            "error": err,
        }
        if dec is not None:
            nopad_path = decdir / f"{RESOURCES['rsa_xml_encrypted']}.aes256cbc_decrypted.bin"
            nopad_path.write_bytes(dec)
            stripped = pkcs7_strip(dec)
            xml_path = decdir / f"{RESOURCES['rsa_xml_encrypted']}.rsa_key.xml"
            xml_path.write_bytes(stripped)
            r4_info.update({
                "aes_decrypted": {
                    "path": str(nopad_path.relative_to(outdir)),
                    "size": len(dec),
                    "sha256": sha256(dec),
                    "first16_hex": dec[:16].hex(),
                },
                "pkcs7_stripped": {
                    "path": str(xml_path.relative_to(outdir)),
                    "size": len(stripped),
                    "sha256": sha256(stripped),
                    "starts_with_rsa_xml": stripped.startswith(b"<RSAKeyValue>"),
                },
            })
        manifest["decryption"]["rsa_xml_encrypted"] = r4_info


    # pj... => CoreUtils.method_1-style block decrypt => UTF-16LE string table.
    pj = located.get("string_table_encrypted")
    parsed_pj_strings = None
    if pj:
        raw = pj.read_bytes()
        pj_dec = block_decrypt(PJ_BLOCK_KEY, raw)
        pj_path = decdir / f"{RESOURCES['string_table_encrypted']}.decrypted_string_table.bin"
        pj_path.write_bytes(pj_dec)
        parsed_pj_strings = parse_all_known_strings(pj_dec, KNOWN_STRING_OFFSETS)
        strings_path = decdir / "strings_from_pj.json"
        strings_path.write_text(json.dumps(parsed_pj_strings, indent=2, ensure_ascii=False), encoding="utf-8")
        manifest["decryption"]["string_table_encrypted"] = {
            "resource": RESOURCES["string_table_encrypted"],
            "routine": "VM method 0 final CoreUtils.method_1-style block decrypt; second byte[] arg is unused by the routine",
            "key_hex": PJ_BLOCK_KEY.hex(),
            "unused_second_arg_hex": PJ_UNUSED_ARG.hex(),
            "decrypted_table": {
                "path": str(pj_path.relative_to(outdir)),
                "size": len(pj_dec),
                "sha256": sha256(pj_dec),
                "first16_hex": pj_dec[:16].hex(),
            },
            "parsed_strings": {
                "path": str(strings_path.relative_to(outdir)),
                "candidate_offsets": len(KNOWN_STRING_OFFSETS),
                "parsed_strings": len(parsed_pj_strings),
                "format": "int32 byte_length followed by UTF-16LE bytes at each resolved offset",
            },
        }

    # VM/string metadata.
    exprs = resolve_string_offset_expressions(root)
    expr_path = vmdir / "string_offset_expressions_signed.json"
    expr_path.write_text(json.dumps(exprs, indent=2, ensure_ascii=False), encoding="utf-8")
    offsets = sorted({int(r["resolved_offset"]) for r in exprs if r.get("resolved_offset") is not None}) or KNOWN_STRING_OFFSETS
    off_path = vmdir / "string_offsets_unique.json"
    off_path.write_text(json.dumps(offsets, indent=2), encoding="utf-8")
    fields_path = vmdir / "method1_fields_signed.json"
    fields_path.write_text(json.dumps(FIELD_VALUES, indent=2, ensure_ascii=False), encoding="utf-8")

    if parsed_pj_strings is not None:
        valued_exprs = []
        for r in exprs:
            rr = dict(r)
            off = rr.get("resolved_offset")
            rr["string"] = parsed_pj_strings.get(str(off)) if off is not None else None
            valued_exprs.append(rr)
        valued_expr_path = decdir / "string_calls_resolved_with_values.json"
        valued_expr_path.write_text(json.dumps(valued_exprs, indent=2, ensure_ascii=False), encoding="utf-8")
        manifest.setdefault("decryption", {}).setdefault("string_table_encrypted", {}).setdefault("source_call_values", {
            "path": str(valued_expr_path.relative_to(outdir)),
            "calls": len(valued_exprs),
        })

    manifest["vm"] = {
        "method1_fields_signed": str(fields_path.relative_to(outdir)),
        "string_offset_expressions_signed": str(expr_path.relative_to(outdir)),
        "string_offsets_unique": str(off_path.relative_to(outdir)),
        "resolved_decryptstring_calls": len(exprs),
        "unique_resolved_offsets": len(offsets),
    }

    if args.decrypted_string_table:
        buf = args.decrypted_string_table.read_bytes()
        strings = parse_all_known_strings(buf, offsets)
        strings_path = decdir / "strings_from_pj.json"
        strings_path.write_text(json.dumps(strings, indent=2, ensure_ascii=False), encoding="utf-8")
        manifest["decryption"]["parsed_strings_from_pj"] = {
            "source": str(args.decrypted_string_table),
            "path": str(strings_path.relative_to(outdir)),
            "candidate_offsets": len(offsets),
            "parsed_strings": len(strings),
        }

    notes = f"""Offline resource dump notes
===========================

Resources copied into raw/:
  - {RESOURCES['string_table_encrypted']}      encrypted string table used by CoreUtils.DecryptString
  - {RESOURCES['vm_bytecode']}      virtualized loader bytecode
  - {RESOURCES['rsa_xml_encrypted']}      AES-encrypted RSA XML key
  - {RESOURCES['embedded_assembly_encrypted']}      encrypted embedded assembly payload

Fully dumped/decrypted by this script:
  1. {RESOURCES['embedded_assembly_encrypted']}
     raw -> CoreUtils.method_1-style block decrypt -> QCLZ-like decompress -> decrypted/embedded_assembly_from_x0.dll

  2. {RESOURCES['rsa_xml_encrypted']}
     raw -> AES-256-CBC using recovered VM key/IV -> decrypted/*.rsa_key.xml

String table pj...:
  - Fully decrypted by this script with the recovered VM method 0 block key.
  - Outputs:
        decrypted/{RESOURCES['string_table_encrypted']}.decrypted_string_table.bin
        decrypted/strings_from_pj.json
        decrypted/string_calls_resolved_with_values.json
  - Source calls to CoreUtils.DecryptString(NUM ^ w_w_init.FIELD) are resolved into vm/string_offsets_unique.json.
  - String entry format:
        int32 byte_length; UTF-16LE bytes

Safety:
  - This script does not execute the target code.
  - If you instrument/run the target to get CoreUtils.byte_1, use a disposable VM with networking disabled.
"""
    (outdir / "notes.txt").write_text(notes, encoding="utf-8")
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Wrote dump to: {outdir}")
    print(f"Resolved DecryptString calls: {len(exprs)}; unique offsets: {len(offsets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
