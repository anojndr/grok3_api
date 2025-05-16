# Grok 3 Web API Wrapper

A Go-based OpenAI-compatible API wrapper for the Grok 3 Web API, providing `/v1/chat/completions` and `/v1/models` endpoints. This tool enables chat, vision, and image generation with advanced features such as Imgur integration, flexible cookie management, deep search, and more.

---

## Features

- **OpenAI-Compatible Endpoints**:  
  - `/v1/chat/completions` (POST): Chat completions, streaming and non-streaming.
  - `/v1/models` (GET): Lists available models.

- **Streaming & Non-Streaming Support**:  
  Real-time streaming or full-response modes, matching OpenAI's API.

- **Model Selection**:  
  - `grok-3`: Standard model.
  - `grok-3-reasoning`: Reasoning model.

- **Image Handling (Vision & Generation)**:
  - **Vision Input**: Accepts images in OpenAI-compatible message format:
    - Supports both `input_image` (standard) and `image_url` (legacy/compat) part types.
    - Accepts images as data URIs or HTTP/S URLs.
    - Handles both string and object for `image_url` (e.g., `{ "url": "..." }`).
  - **Image Generation**: Generates images from prompts.
  - **Imgur Integration**:
    - If an Imgur Client ID is provided (globally or per-request), generated images are downloaded from Grok, uploaded to Imgur, and Imgur URLs are appended to the response.
    - If not set, a warning is logged and Imgur upload is skipped.
    - Per-request Imgur Client ID override supported.

- **Advanced Search Capabilities**:
  - **Standard Web Search**: Toggle via request body (`enableSearch`).
  - **DeepSearch / DeeperSearch**:
    - Triggered by including `deepsearch` or `deepersearch` (case-insensitive, whole word) in the last user message.
    - Keyword is stripped from the message before sending to Grok.
    - Disables image generation for that request.
    - Not available if images are attached.

- **Flexible Cookie Management**:
  - Accepts cookies via:
    - `-cookie` flag (single string or JSON array).
    - `-cookieFile` flag (one per line, `#` for comments).
    - `GROK3_COOKIE` environment variable (single string or JSON array).
    - Per-request override in request body (`grokCookies`).
  - Supports round-robin rotation or index-based selection (`cookieIndex`).
  - Deduplicates cookies.

- **Text Message Handling**:
  - Automatically uploads long text as a file if it exceeds a configurable limit (`-charsLimit`).
  - Can be forced per-request (`uploadMessage`).
  - Uploaded text is referenced in the prompt and attached as a file.

- **Proxy Support**:
  - HTTP and SOCKS5 proxies supported via flag or standard environment variables.

- **Configurable Options**:
  - Flags and request body options for:
    - Chat retention (`keepChat`)
    - Thinking token filtering (`ignoreThinking`)
    - Prompt customization (`textBeforePrompt`, `textAfterPrompt`)
    - Imgur Client ID (`imgurClientID`)
    - Character limit for text upload (`charsLimit`)
    - Proxy (`httpProxy`)
    - Server port (`port`)

- **Error Handling & Logging**:
  - Detailed error messages for authentication, cookies, Imgur, proxy, and more.
  - Logs warnings for unsupported/invalid input, missing configuration, and Imgur upload failures.
  - HTTP error codes and messages are descriptive.

- **Other**:
  - Handles both global and per-request Imgur Client ID.
  - Handles both string and array for cookies in request body.
  - Handles both string and object for image_url in vision input.
  - Handles both standard and non-standard part types for images.
  - Handles before/after prompt customization globally and per-request.

---

## Prerequisites

- **Grok Cookie**: Obtain from [grok.com](https://grok.com) (e.g., `auth_token=...; other_cookie=...`).
- **API Authentication Token**: Required for securing the API endpoints.
- **(Optional) Imgur Client ID**: For uploading generated images to Imgur.

---

## Basic Usage

**Run with required token and cookie:**
```bash
grok3_api -token your_secret_token -cookie "your_grok_cookie_string"
```

**With Imgur Client ID:**
```bash
grok3_api -token your_secret_token -cookie "your_grok_cookie_string" -imgurClientID "your_imgur_client_id"
```

**With a cookie file:**
```bash
grok3_api -token your_secret_token -cookieFile cookies.txt
```

API endpoints will be available at `http://localhost:8180/v1`.

---

## Configuration

### Command-Line Flags

- `-token string`: API authentication token (**required**).
- `-cookie string`: Grok cookie(s) (single string or JSON array).
- `-cookieFile string`: File with one cookie per line (`#` for comments).
- `-textBeforePrompt string`: Text before the prompt (default: see below).
- `-textAfterPrompt string`: Text after the prompt (default: empty).
- `-keepChat`: Retain chat conversations (default: `false`).
- `-ignoreThinking`: Exclude thinking tokens (default: `false`).
- `-charsLimit uint`: Character limit for uploading text as a file (default: 50000).
- `-httpProxy string`: HTTP/SOCKS5 proxy URL.
- `-imgurClientID string`: Imgur Client ID for uploading generated images.
- `-port uint`: Server port (default: 8180).
- `-help`: Print help.

### Environment Variables

- `GROK3_AUTH_TOKEN`: Alternative to `-token`.
- `GROK3_COOKIE`: Alternative to `-cookie`.
- `IMGUR_CLIENT_ID`: Alternative to `-imgurClientID`.
- `http_proxy` / `https_proxy` / `HTTP_PROXY` / `HTTPS_PROXY`: Proxy.

### Request Body Options (`/v1/chat/completions`)

```json
{
  "messages": [
    {
      "role": "user",
      "content": "Tell me a joke."
    }
    // See "Image Handling" for vision input example
  ],
  "model": "grok-3", // or "grok-3-reasoning"
  "stream": false, // true for streaming, false for full response
  "grokCookies": "your_single_cookie_string", // or ["cookie1", "cookie2"]
  "cookieIndex": 1, // 1-based index, 0 or unset for round-robin
  "enableSearch": 1, // 1 to enable web search, 0 to disable
  "uploadMessage": 1, // 1 to force upload text as file, 0 or unset for auto
  "textBeforePrompt": "Custom system prompt...",
  "textAfterPrompt": "Custom suffix...",
  "keepChat": 1, // 1 to retain chat, 0 to not retain
  "ignoreThinking": 1, // 1 to exclude thinking tokens, 0 to include
  "imgurClientID": "override_imgur_client_id" // (optional) per-request Imgur Client ID
}
```

---

## Image Handling

### Vision Input

Send images for vision tasks using OpenAI-compatible message format:

- `content` is an array of parts.
- Text part: `{ "type": "text", "text": "Describe this image" }`
- Image part:  
  - `{ "type": "input_image", "image_url": { "url": "..." } }` (standard)  
  - `{ "type": "image_url", "image_url": "..." }` (legacy/compat, also accepted)
- `image_url` can be a data URI or HTTP/S URL.
- Both string and object forms for `image_url` are supported.

**Example:**
```json
{
  "model": "grok-3",
  "messages": [
    {
      "role": "user",
      "content": [
        { "type": "text", "text": "What's in this image?" },
        { "type": "input_image", "image_url": { "url": "https://example.com/image.jpg" } }
      ]
    }
  ]
}
```

### Image Generation & Imgur Upload

- Prompts can trigger image generation (e.g., "generate an image of a cat").
- Generated images are downloaded from Grok, then uploaded to Imgur if an Imgur Client ID is set (globally or per-request).
- Imgur URLs are appended to the response in a section like:

  ```
  --- Generated Images ---
  https://i.imgur.com/abc123.jpg
  ```

- If Imgur Client ID is not set, a warning is logged and Imgur upload is skipped.

---

## Search Functionality

### Standard Web Search

- Enable with `"enableSearch": 1` in the request body.

### DeepSearch / DeeperSearch

- Trigger by including `deepsearch` or `deepersearch` (case-insensitive, whole word) in the last user message.
- The keyword is stripped from the message before sending to Grok.
- DeepSearch disables image generation for that request.
- Not available if images are attached.

---

## Cookie Management

- Provide cookies via:
  - `-cookie` flag (single string or JSON array)
  - `-cookieFile` flag (one per line, `#` for comments)
  - `GROK3_COOKIE` environment variable
  - Per-request override in request body (`grokCookies`)
- Supports round-robin rotation or index-based selection (`cookieIndex`).
- Deduplicates cookies.

---

## Error Handling & Logging

- Descriptive error messages for authentication, cookies, Imgur, proxy, and more.
- Logs warnings for:
  - Missing or invalid configuration (e.g., no cookies, no Imgur Client ID)
  - Unsupported or invalid input (e.g., bad image part types)
  - Imgur upload failures
- HTTP error codes and messages are clear and actionable.

---

## Usage Examples

### 1. Vision Input (data URI)

```json
{
  "model": "grok-3",
  "messages": [
    {
      "role": "user",
      "content": [
        { "type": "text", "text": "What is in this image?" },
        { "type": "input_image", "image_url": { "url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg..." } }
      ]
    }
  ]
}
```

### 2. Vision Input (HTTP/S URL, legacy part type)

```json
{
  "model": "grok-3",
  "messages": [
    {
      "role": "user",
      "content": [
        { "type": "text", "text": "Describe this." },
        { "type": "image_url", "image_url": "https://example.com/image.jpg" }
      ]
    }
  ]
}
```

### 3. Forcing Long Text Upload

```json
{
  "model": "grok-3",
  "messages": [
    { "role": "user", "content": "A very long message..." }
  ],
  "uploadMessage": 1
}
```

### 4. DeepSearch/DeeperSearch

```json
{
  "model": "grok-3",
  "messages": [
    { "role": "user", "content": "deepsearch What is the latest news about AI?" }
  ]
}
```

### 5. Per-Request Imgur Client ID

```json
{
  "model": "grok-3",
  "messages": [
    { "role": "user", "content": "Generate an image of a futuristic city." }
  ],
  "imgurClientID": "your_imgur_client_id"
}
```

### 6. Per-Request Cookie and Index

```json
{
  "model": "grok-3",
  "messages": [
    { "role": "user", "content": "Tell me a joke." }
  ],
  "grokCookies": ["cookie1", "cookie2"],
  "cookieIndex": 2
}
```

---

## Warnings

- This is an **unofficial** OpenAI-compatible API for Grok 3.  
- Your account may be **banned** by xAI for using this tool.
- Do **not** use for commercial purposes. Use at your own risk.

---

## Special Thanks

- [mem0ai/grok3-api](https://github.com/mem0ai/grok3-api)
- [RoCry/grok3-api-cf](https://github.com/RoCry/grok3-api-cf/tree/master)
- Most code was written by Grok 3, thanks to Grok 3.

---

## License

Licensed under the `AGPL-3.0` License.
