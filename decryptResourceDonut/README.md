# ToolDecryptResource - Hướng dẫn cấu trúc thư mục

Tài liệu này giúp bạn hiểu nhanh toàn bộ workspace, ý nghĩa từng thư mục và luồng xử lý dữ liệu từ file mã hóa sang file đã giải mã.

## 1) Tổng quan

Workspace này có 2 cụm kết quả phân tích chính:

- `resource_dump/`: pipeline dump và giải mã tài nguyên embedded (string table, RSA XML, embedded DLL, VM metadata).
- `c2_string_decoded/`: kết quả giải mã một C2 config string (base64 + gzip + protobuf-like) và trích xuất certificate/public key.

Ngoài ra có script gốc `dump_resources.py` để tạo lại bộ kết quả dump/giải mã từ source tree.

## 2) Sơ đồ cây thư mục (rút gọn)

```text
ToolDecryptResource/
|- dump_resources.py
|- c2_string_decoded/
|  |- decode_this_string.py
|  |- decoded_config.json
|  |- certificate.der
|  |- certificate.pem
|  |- public_key.pem
|  |- decompressed_protobuf_like.bin
|  |- nested_message.bin
|  `- raw_base64_gzip.bin
|- resource_dump/
|  |- dump_resources.py
|  `- resource_dump/
|     |- manifest.json
|     |- notes.txt
|     |- raw/
|     |- decrypted/
|     `- vm/
|- c2_string_decoded.zip
`- resource_dump.zip
```

## 3) Giải thích từng nhóm thư mục

### 3.1) `dump_resources.py` (gốc)

Script chính để:

- tìm 4 embedded resources trong source root,
- copy vào `raw/`,
- giải mã theo routine đã reverse,
- parse string table,
- ghi metadata vào `manifest.json`, `notes.txt`, và nhóm `vm/*.json`.

4 resources được xử lý:

- `pjCvA5e88oGlCYclfo.iTkRnou2uybvuMxWn8`: encrypted string table.
- `QweDNjNWrkMuFjhOOY.7PhYAwGiHKPtcJlEoL`: VM bytecode.
- `r4JutVgxFonyP9i9Tx.MG7FmYrAOfQK2prLU1`: AES-encrypted RSA XML.
- `x0y6b3U8enEOD9FDxN.teZHJmdV98NX3nlK2L`: encrypted embedded assembly.

### 3.2) `resource_dump/resource_dump/raw/`

Chứa các file resource nguyên gốc đã copy từ source tree (chưa giải mã).

### 3.3) `resource_dump/resource_dump/decrypted/`

Chứa output đã giải mã/chuyển đổi:

- `embedded_assembly_from_x0.dll`: payload PE sau block decrypt + QCLZ decompress.
- `*.rsa_key.xml`: RSA XML sau AES-256-CBC decrypt (+ bỏ PKCS#7 nếu hợp lệ).
- `*.decrypted_string_table.bin`: string table đã decrypt.
- `strings_from_pj.json`: map offset -> string (UTF-16LE).
- `string_calls_resolved_with_values.json`: gắn kết call site `DecryptString(...)` với giá trị string.

### 3.4) `resource_dump/resource_dump/vm/`

Metadata phục vụ giải offset string:

- `method1_fields_signed.json`: field values đã ký (signed emulation).
- `string_offset_expressions_signed.json`: danh sách call expressions trích từ source C#.
- `string_offsets_unique.json`: tập offset unique đã resolve.

### 3.5) `resource_dump/resource_dump/manifest.json`

File quan trọng nhất để audit kết quả:

- thông tin tìm thấy resource,
- size, sha256,
- key/iv/routine decrypt,
- đường dẫn output,
- thống kê số call/số offset resolve.

### 3.6) `resource_dump/resource_dump/notes.txt`

Ghi chú tóm tắt pipeline, safety note, và ý nghĩa output theo dạng dễ đọc.

### 3.7) `c2_string_decoded/`

Cụm này mô tả việc decode một C2 config string:

- `decode_this_string.py`: script demo chuỗi decode (base64 -> gzip -> parse protobuf-like).
- `decoded_config.json`: kết quả đã parse (host, ports, cert, các field khác).
- `certificate.der` / `certificate.pem`: certificate trích xuất.
- `public_key.pem`: public key trích xuất.
- `raw_base64_gzip.bin`, `decompressed_protobuf_like.bin`, `nested_message.bin`: artifact trung gian.

## 4) Luồng dữ liệu (tương ứng `resource_dump`)

```text
source tree
  -> tìm resource theo tên
  -> copy sang raw/
  -> decrypt/decompress theo từng routine
  -> ghi vào decrypted/
  -> resolve DecryptString call expressions
  -> ghi vm/*.json + manifest.json + notes.txt
```

Chi tiết routine:

- x0 resource: block decrypt (CoreUtils.method_1-style) -> QCLZ-like decompress -> DLL (`MZ`).
- r4 resource: AES-256-CBC (`openssl enc -d -nopad`) -> strip PKCS#7 -> RSA XML.
- pj resource: block decrypt -> parse UTF-16LE strings theo danh sách offset.

## 5) Cách chạy lại nhanh

Từ thư mục gốc:

```bash
python dump_resources.py <source_root> <output_dir>
```

Ví dụ:

```bash
python dump_resources.py D:/src_extracted/Zhgcllfd ./resource_dump/resource_dump
```

Tùy chọn thêm:

```bash
python dump_resources.py <source_root> <output_dir> --decrypted-string-table <path_to_CoreUtils.byte_1_dump>
```

## 6) File nén (`*.zip`)

- `resource_dump.zip` và `c2_string_decoded.zip` là bản đóng gói của các thư mục kết quả để chia sẻ/lưu trữ.

## 7) Ghi chú an toàn

Script được thiết kế offline: chỉ đọc/ghi file, không execute target application.

Nếu cần instrument target để lấy thêm dữ liệu runtime, nên dùng VM disposable và tắt mạng.