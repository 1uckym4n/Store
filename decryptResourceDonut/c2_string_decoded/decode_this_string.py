#!/usr/bin/env python3
import base64, gzip, json, struct, sys

S = sys.argv[1] if len(sys.argv) > 1 else """H4sIAAAAAAAACn2Ntw7k1gEADV0hw8ABV7t0S+CWYUku1T2mZc65Y87kMocv0PcYuF7hxwS1LlxMNcDMf3/67eu/viL4dxTDvyM49f2Ffvv9x5dvf/z48u3PH1/+/etXVRS5Z8MwYJlKcIg0KEUT6Blo3gbpuutrq8Zhl8UmuoFGl+1UtfWbOmAamDAPWGCrFjjYMmQ902RZkKnRO1qiwepVBgSsIyIqK14ayx2qY96qN4bs3eK6055qo/4Nojsu7jf/pyOKjNj875vjAdAZUL7A354pZQaUHCjljVAsS4u8ulquIWCFKfNhSj78ztZkquVw1CQmu0FbNOkYWgpDIILQqNRoq9VAvDeC5j+th02tgSG8Z59ocvOvAuoDMYcJQOz4muhERaC97y8QbEl++twTgFrRYK78ThOGNhNIuHAnCThaFd76fefbjT7vVDKzAnb155Bqp/nWA3pr3RdXpaftNvuD3GXaDhJWjPiGjWn4cHVWKR4BQ+twg8sQYNtZLQQ/DTFMHj+XLBuz3niZoU4l55HRXvhnPEnzdMaSIuNXUY+YyWFY0dH8wSccMkIH0ptM3dN8dzvqnMCkVMONsIxL1ei9yVhQF8RXhXY3I3TDVcY3xXfnQ1xQpvA1g3ntTxtMqJPMe0mCibUD3/iUsCZWbsTkonKgk8VjwdJysDEsrNI8EtTnQuWhzz28758IDhseUJDc9smsQTkqtbZjN+rg4Ec2rhwJU8c9SIa0ccGnPPtUG9UID6YomSXliedFoQWICAKn1HWNlFTkhN7l9MxqT3znajAtqaNvAb7iWbXaC37XqmfeAha/lbHtiyylKRJaRnJTdlO++Xs2bPgejULn5YgqOPgxSYO040D+LPBRwxufV31ECJxArdTDBiLcSjwyJ0Oh31bt727bdHnddKTAmZYtQy8YokhJVgK2vedDiclGq/UB4wWeTN6uQHnBUjOdU6d77hUhXGcvBhwcALF6qSw4BDNkPQvWaTrkeJ2a8kBbHu0lrS0p7WVC1AnbOkOTquD1BoibcQdHPw6TV4FKg+J1sGYoyWMkVnuqAZPTaBOwZSnSgGU79o3WJg1/1tQrXs6tuN5KSEYPgobwo/D+WI95XU1asVI+Nzu/QxYi5PYSadclyQmDckb6NFQG16Dl1ZOYEFitRHFyqsWYj6lZ4evOx2NYc+czqXWLRccm1f3EnBjvp8z0MdlObsm3WXwFpQzxz7420T48ZhxCXX7hUqGvInjsszl5xR3bktJJX/vrjgsabxCiL2DgjQ5BItYxlvyC4A6fHg3lzFDHDld006uidmvSKPbjyI9PPOwTshm+4GBj96x1ehx0ttDe/V5VSOo35QPj6aSitmxxLloJeTFu3pwlnuKL0Hi/zZ2CpUYiI+OHGR6jigbzzNZ9acj68MzHrpGETo52iOrRMIY+Y3Okm0K9cymesShpVix814suTOV1C8cUVBh/KwxfvXorr0Ky388P3aR3WdgthJB4uuXatukT6Qya4+l9AcM4hF6NAuW7l5m7eA7rMV7tQ7VLDF5nbIiwQd+YswhjsuzZeBmEBSiJxcw6bVXJ9ZliRm8vTg784JDFGS0zMJrt9eicIxIr+In6pKITFB+UUms+P8a7NDPzBBi3YBKFrv3wbswAFm2t7uULjEKp2kdHFrL9wTFYBUdXcEeP5HCOm/7SwqYrryj8xmeE3KX2Vo6CRIKqcKnI0nMoAfO6R15g5jZKiokAQGLR6LIc6O1+er9eyqSU9myOBjOV/vPF4dZf/kH/DAyDBQ6Q/qnHedym2/YX5s02VcQGAAA="""

def read_varint(buf, pos=0):
    val = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        val |= (b & 0x7f) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7

def parse(buf):
    pos = 0
    out = []
    while pos < len(buf):
        tag, pos = read_varint(buf, pos)
        f, wt = tag >> 3, tag & 7
        if wt == 0:
            val, pos = read_varint(buf, pos)
            out.append((f, "varint", val))
        elif wt == 2:
            n, pos = read_varint(buf, pos)
            val = buf[pos:pos+n]
            pos += n
            try:
                v = val.decode("utf-8")
            except UnicodeDecodeError:
                v = val.hex()
            out.append((f, "bytes/string", v))
        else:
            raise SystemExit(f"unsupported wire type {wt} at field {f}")
    return out

gz = base64.b64decode(S)
plain = gzip.decompress(gz)
outer_tag, pos = read_varint(plain, 0)
outer_len, pos = read_varint(plain, pos)
nested = plain[pos:pos+outer_len]
print("gzip_size:", len(gz))
print("plain_size:", len(plain))
print("outer_field:", outer_tag >> 3, "wire:", outer_tag & 7, "length:", outer_len)
for f, typ, val in parse(nested):
    if isinstance(val, str) and len(val) > 120:
        val = val[:120] + "...<truncated>"
    print(f"field {f} ({typ}): {val}")
