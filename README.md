# `jwksctl` — Công cụ CLI Quản lý Vòng đời JWKS (File JSON & Database)

`jwksctl` là công cụ dòng lệnh (CLI) xây dựng trên **Bun + TypeScript** giúp quản lý bộ khóa **JWKS (JSON Web Key Set)** lưu trữ trên **File JSON (`jwks.json`)** hoặc **Database (`SQLite`, `PostgreSQL`, `MySQL/MariaDB`, `MongoDB`)**.

## Điểm nổi bật về Bảo mật & Toàn vẹn Dữ liệu

1. **Tách biệt tuyệt đối Public JWK & Private Key (`.pem`)**:
   - Trong `jwks.json` hoặc bảng Database **chỉ lưu Public JWK** kèm đường dẫn `privateKeyPath` trỏ tới file `.pem` (PKCS#8) trên ổ đĩa.
   - Tuyệt đối không bao giờ lưu các tham số khóa bí mật (`d`, `p`, `q`, `dp`, `dq`, `qi`) trong `jwks.json`.
   - Hỗ trợ mã hóa file `.pem` trên đĩa bằng **AES-256-GCM** (dẫn xuất khóa PBKDF2-SHA256 100.000 vòng từ `--passphrase` hoặc biến môi trường `JWKS_PASSPHRASE`).
2. **Chống mất hoặc xóa nhầm Key (`SafeMutationGuard`)**:
   - Kiểm tra bất biến danh sách `kid` trước và sau mọi thao tác **Create / Update / Delete** (đảm bảo thêm hoặc cập nhật khóa không bao giờ làm rơi bất kỳ khóa cũ nào).
   - Tự động tạo bản sao lưu **`jwks.json.bak`** và ghi nguyên tử (**Atomic Write** qua file tạm `.tmp` rồi `rename`).
   - Chặn xóa nhầm khóa đang ở trạng thái `active` (trừ khi xác nhận cưỡng bức hoặc truyền `--force`).
   - Hỗ trợ **xóa từng khóa hoặc xóa nhiều khóa cùng lúc** (tích chọn bằng phím `Space` trong chế độ tương tác hoặc truyền nhiều `kid`), kèm bảng xem trước **Diff Preview**.

---

## Cài đặt & Đóng gói

```bash
# Cài đặt dependencies
bun install

# Chạy trực tiếp ở chế độ Interactive Wizard
bun run index.ts

# Chạy bộ kiểm thử tự động
bun test

# Đóng gói thành 1 file thực thi độc lập (dist/jwksctl.exe hoặc dist/jwksctl)
bun run build
```

---

## Hướng dẫn Sử dụng Các Lệnh Chính

### 1. Khởi tạo Store & Quản lý Profile (`.jwksctl.json`)

```bash
# Khởi tạo file jwks.json và thư mục ./keys, đồng thời lưu thành profile "local"
bun run index.ts init --store ./jwks.json --keys-dir ./keys --save-profile local

# Cấu hình thêm profile SQLite hoặc PostgreSQL
bun run index.ts config set dev-sqlite --store ./jwks.sqlite --default
bun run index.ts config set prod-pg --store postgres://user:pass@localhost:5432/mydb --table jwks_keys
bun run index.ts config list
```

### 2. Tạo khóa mới (`generate`) & Xoay vòng khóa (`rotate`)

```bash
# Tạo khóa EdDSA (Ed25519) hoặc ES256 / RS256 (có thể kèm --passphrase để mã hóa file .pem)
bun run index.ts generate --alg EdDSA
bun run index.ts generate --alg RS256 --bits 2048 --passphrase "my-secret"

# Xoay vòng khóa: Tạo khóa active mới, chuyển khóa active cũ sang passive với thời gian ân hạn 7 ngày
bun run index.ts rotate --alg ES256 --grace-period 7d
```

### 3. Liệt kê (`list`), Xem chi tiết (`inspect`) & Kiểm tra toàn vẹn (`check`)

```bash
bun run index.ts list
bun run index.ts inspect <kid>
bun run index.ts check
```

### 4. Xóa an toàn (`remove`), Thùng rác (`trash`), Dọn dẹp (`prune`) & Khôi phục (`restore`)

Mặc định khi xóa khóa (`remove` hoặc `prune`), cả bản ghi JWK lẫn file Private Key (`.pem`) sẽ được chuyển vào **Thùng rác (`./keys/.trash/`)** để bạn có thể khôi phục lại nguyên vẹn cả khóa lẫn file `.pem` trên mọi Store (File JSON, SQLite, MongoDB, PostgreSQL, MySQL).

```bash
# Mở menu Checkbox tương tác để tích chọn 1 hoặc nhiều khóa cần xóa
bun run index.ts remove

# Xóa khóa trên dòng lệnh (mặc định đưa vào ./keys/.trash; thêm --permanent nếu muốn xóa vĩnh viễn)
bun run index.ts remove <kid1> <kid2>
bun run index.ts remove <kid1> --permanent

# Khôi phục khóa & trả lại file .pem từ Thùng rác (mở Checkbox tương tác hoặc truyền kid / --all)
bun run index.ts restore
bun run index.ts restore <kid1>
bun run index.ts restore --from-bak

# Xem danh sách khóa trong Thùng rác hoặc dọn sạch vĩnh viễn Thùng rác
bun run index.ts trash list
bun run index.ts trash empty

# Tự động dọn dẹp các khóa đã bị thu hồi (revoked) hoặc passive đã hết hạn
bun run index.ts prune
```

### 5. Xuất Public JWKS chuẩn RFC 7517 (`export`), Ký/Xác thực JWT (`sign`/`verify`) & Server (`serve`)

```bash
# Xuất bộ Public JWKS tinh khiết (đã lọc sạch metadata nội bộ) ra file hoặc màn hình
bun run index.ts export --output ./public-jwks.json

# Ký thử và xác thực thử JWT
TOKEN=$(bun run index.ts sign --data '{"sub":"user-1","role":"admin"}' --expires-in 1h)
bun run index.ts verify "$TOKEN"

# Đồng bộ khóa từ File JSON sang SQLite / Postgres
bun run index.ts --store ./jwks.json sync --to ./jwks.sqlite

# Mở nhanh HTTP server phục vụ /.well-known/jwks.json và /health tại cổng 8080
bun run index.ts serve --port 8080
```
