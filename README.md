# TeaserPaste - API Backend

Đây là mã nguồn cho dịch vụ API backend của nền tảng dán/chia sẻ mã TeaserPaste. API này được thiết kế để hoạt động không trạng thái và tối ưu cho việc triển khai trên các nền tảng Serverless như Vercel.

## ⚙️ Cấu trúc và Công nghệ

| Mục | Chi tiết |
| :--- | :--- |
| **Ngôn ngữ** | JavaScript (Node.js) / CommonJS |
| **Framework** | Express |
| **Database** | Google Cloud Firestore **và Realtime Database (RTDB)** (Thông qua Firebase Admin SDK) |
| **Tìm kiếm** | OpenSearch |
| **Caching/Queue** | Redis (Thông qua ioredis) |
| **Triển khai** | Vercel Serverless Function |

## 🛡️ Vấn đề Bảo mật và Cấu hình

Dự án này tuân thủ nguyên tắc bảo mật bằng cách sử dụng **Biến Môi Trường (Environment Variables)** để quản lý tất cả các thông tin nhạy cảm và khóa truy cập (secrets).

### Các biến môi trường chính:

* **Firebase Admin SDK:** `FIREBASE_PROJECT_ID`, `FIREBASE_PRIVATE_KEY`, v.v.
* **OpenSearch:** `OPENSEARCH_HOST`, `OPENSEARCH_USER`, `OPENSEARCH_PASSWORD`, v.v.
* **Redis:** `REDIS_URL`

**Lưu ý:** Các file chứa giá trị bí mật như `.env` đã được liệt kê trong `.gitignore` và sẽ không được công khai trong repository này.

## 📝 Tài liệu API

Để biết chi tiết về các endpoint API (`/getSnippet`, `/createSnippet`, `/searchSnippets`, `/starSnippet`, `/copySnippet`, `/restoreSnippet`, v.v.) và cách xác thực bằng Public/Private Key, vui lòng tham khảo tài liệu kỹ thuật chính thức.

**Tài liệu Chi tiết:** [https://docs.teaserverse.online/triple-tool/teaserpaste/api](https://docs.teaserverse.online/triple-tool/teaserpaste/api)
