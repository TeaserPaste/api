# TeaserPaste - API Backend

This is the source code for the API backend service of the TeaserPaste code-pasting/sharing platform. This API is designed to be stateless and optimized for deployment on Serverless platforms like Vercel.

## Architecture and Technology

| Item | Details |
| :--- | :--- |
| **Language** | JavaScript (Node.js) / CommonJS |
| **Framework** | Express |
| **Database** | Google Cloud Firestore **and Realtime Database (RTDB)** (Via Firebase Admin SDK) |
| **Search** | OpenSearch |
| **Caching/Queue** | Redis (via `ioredis`) |
| **Deployment** | Vercel Serverless Function |

## Security and Configuration

This project adheres to security principles by using **Environment Variables** to manage all sensitive information and access keys (secrets).

### Main environment variables:

* **Firebase Admin SDK:** `FIREBASE_PROJECT_ID`, `FIREBASE_PRIVATE_KEY`, etc.
* **OpenSearch:** `OPENSEARCH_HOST`, `OPENSEARCH_USER`, `OPENSEARCH_PASSWORD`, etc.
* **Redis:** `REDIS_URL`

**Note:** Files containing secret values, such as `.env`, are listed in `.gitignore` and will not be made public in this repository.

## 📝 API Documentation

For details on API endpoints (`/getSnippet`, `/createSnippet`, `/searchSnippets`, `/starSnippet`, `/copySnippet`, `/restoreSnippet`, etc.) and how to authenticate using Public/Private Keys, please refer to the official technical documentation.

**Detailed Documentation:** [https://docs.teaserverse.online/triple-tool/teaserpaste/api](https://docs.teaserverse.online/triple-tool/teaserpaste/api)
