# Quy tắc Dự án `jwksctl` (Workspace Rules)

1. Ngôn ngữ mặc định cho việc trả lời, tạo plan, tạo git commit: Việt Nam (Vietnamese).
2. Luôn sử dụng `@mcp:context7` khi thực hiện các tác vụ liên quan đến thư viện thứ 3.
3. Luôn tạo plan khi thực hiện các tác vụ trừ những tác vụ nhỏ.
4. Khi sử dụng skill hãy đưa ra tên skill đã sử dụng.
5. **Quy tắc Quản lý Nhánh (Git Branching)**:
   - Mỗi task thực hiện bắt buộc phải tách 1 nhánh Git mới (ví dụ: `feat/<ten-task>`, `fix/<ten-task>`, `chore/<ten-task>`).
   - Nếu trong quá trình thực hiện task có sử dụng **subagent**, subagent đó bắt buộc phải tách nhánh mới xuất phát từ nhánh của task vừa tạo đó (sử dụng `Workspace: "branch"` từ nhánh hiện tại hoặc checkout nhánh con `feat/<ten-task>-<subagent>`).
6. **Quy tắc Khởi tạo & Quản lý Gói**:
   - Luôn sử dụng CLI chính thức (`bun init`, `bun add`...) để khởi tạo dự án và cài đặt thư viện; tuyệt đối không viết tay `package.json` hay tự điền version thủ công để tránh dùng phải version cũ.
