package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart" // Added for Imgur upload
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/google/uuid"
)

// GrokClient defines a client for interacting with the Grok 3 Web API.
// It encapsulates the API endpoints, HTTP headers, and configuration flags.
type GrokClient struct {
	headers        map[string]string // HTTP headers for API requests
	isReasoning    bool              // Flag for using reasoning model
	enableSearch   bool              // Flag for searching in the Web
	uploadMessage  bool              // Flag for uploading the message as a file
	keepChat       bool              // Flag to preserve chat history
	ignoreThinking bool              // Flag to exclude thinking tokens in responses
	// Added imgurClientID to the client struct
	imgurClientID string // Imgur Client ID for uploads
}

// NewGrokClient creates a new instance of GrokClient with the provided cookies and configuration flags.
// Now includes imgurClientID.
func NewGrokClient(cookie string, isReasoning bool, enableSearch bool, uploadMessage bool, keepChat bool, ignoreThinking bool, imgurClientID string) *GrokClient {
	// Generate a unique x-xai-request-id for each client instance or request if needed
	// For simplicity here, we'll keep the headers mostly static but add dynamic ones in doRequest if needed
	return &GrokClient{
		headers: map[string]string{
			"accept":             "*/*",
			"accept-encoding":    "gzip, deflate, br, zstd",
			"accept-language":    "en-US,en;q=0.7",
			"content-type":       "application/json",
			"host":               "grok.com",
			"origin":             "https://grok.com",
			"dnt":                "1",
			"priority":           "u=1, i",
			"referer":            "https://grok.com/",
			"sec-ch-ua":          `"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"Windows"`,
			"sec-fetch-dest":     "empty",
			"sec-fetch-mode":     "cors",
			"sec-fetch-site":     "same-origin",
			"user-agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
			"cookie":             cookie, // IMPORTANT: This should be the full browser cookie string, including cf_clearance, sso, etc.
			"baggage":            "sentry-environment=production,sentry-release=D9QPVzlFugK3Uli28VnEL,sentry-public_key=b311e0f2690c81f25e2c4cf6d4f7ce1c,sentry-trace_id=2760d02ae158a5ebbcff60f5cf35a125,sentry-sampled=false",
			"sentry-trace":       "2760d02ae158a5ebbcff60f5cf35a125-a2a77ceba0092030-0",
			"x-statsig-id":       "8WC+GJpuMzzUT6O10eOv/jHpbw+1sLIBNothX/2Y3QedYcAp5VMaFLbnpNaDuXmof9TaJvINtIZWrxegHLnojmPGgRJ78g",
			"sec-gpc":            "1",
			"cache-control":      "no-cache",
			"pragma":             "no-cache",
			// Dynamic headers like x-xai-request-id will be added per request in doRequest
		},
		isReasoning:    isReasoning,
		enableSearch:   enableSearch,
		uploadMessage:  uploadMessage,
		keepChat:       keepChat,
		ignoreThinking: ignoreThinking,
		imgurClientID:  imgurClientID, // Store the Imgur Client ID
	}
}

// ToolOverrides struct definition remains unchanged.
type ToolOverrides struct {
	ImageGen     bool `json:"imageGen"`
	TrendsSearch bool `json:"trendsSearch"`
	WebSearch    bool `json:"webSearch"`
	XMediaSearch bool `json:"xMediaSearch"`
	XPostAnalyze bool `json:"xPostAnalyze"`
	XSearch      bool `json:"xSearch"`
}

// preparePayload constructs the request payload for the Grok 3 Web API.
// It now accepts fileIDs to include in fileAttachments for vision support.
func (c *GrokClient) preparePayload(message string, fileIDs []string, searchType string) map[string]any {
	// Default enableImageGeneration to true, assuming users might ask for images.
	// Specific logic could be added to disable it based on keywords if needed.
	enableImageGen := true

	if searchType == "default" || searchType == "deeper" {
		// --- DeepSearch Payload ---
		preset := "default"
		if searchType == "deeper" {
			preset = "deeper"
		}
		log.Printf("Using %s Search payload preset ('%s').", strings.Title(searchType), preset)
		// Note: DeepSearch payload example did not include fileAttachments. Assuming images are not used with DeepSearch keyword.
		// If they are, this payload needs fileAttachments added.
		// Disable image generation during deep search
		enableImageGen = false
		return map[string]any{
			"temporary":                 false,
			"modelName":                 grok3ModelName, // DeepSearch uses the standard model
			"message":                   message,
			"fileAttachments":           []string{}, // Assuming DeepSearch doesn't use file uploads triggered this way
			"imageAttachments":          []string{},
			"disableSearch":             false, // Explicitly false for DeepSearch
			"enableImageGeneration":     enableImageGen,
			"returnImageBytes":          false,
			"returnRawGrokInXaiRequest": false,
			"enableImageStreaming":      true,
			"imageGenerationCount":      2, // Still include, though generation is disabled by enableImageGeneration=false
			"forceConcise":              false,
			"toolOverrides": map[string]bool{ // Specific overrides for DeepSearch
				"imageGen":     false,
				"webSearch":    false,
				"xSearch":      false,
				"xMediaSearch": false,
				"trendsSearch": false,
				"xPostAnalyze": false,
			},
			"enableSideBySide":          true,
			"sendFinalMetadata":         true,
			"deepsearchPreset":          preset,
			"isReasoning":               false, // DeepSearch uses the standard model
			"webpageUrls":               []string{},
			"disableTextFollowUps":      true,
		}
	} else {
		// --- Standard/Vision Payload ---
		payload := map[string]any{
			"temporary":                 !c.keepChat,
			"modelName":                 c.getModelName(),
			"message":                   message,
			"fileAttachments":           fileIDs, // Use the provided fileIDs
			"imageAttachments":          []string{}, // Keep empty as per example
			"disableSearch":             !c.enableSearch,
			"enableImageGeneration":     enableImageGen, // Use determined value
			"returnImageBytes":          false,
			"returnRawGrokInXaiRequest": false,
			"enableImageStreaming":      true,
			"imageGenerationCount":      2, // Default number of images to request
			"forceConcise":              false,
			"toolOverrides":             map[string]bool{}, // Standard defaults, adjust if needed
			"enableSideBySide":          true,
			"sendFinalMetadata":         true,
			"isReasoning":               c.isReasoning,
			"webpageUrls":               []string{},
			"disableTextFollowUps":      true,
		}
		// Ensure fileAttachments is always an array, even if empty
		if payload["fileAttachments"] == nil {
			payload["fileAttachments"] = []string{}
		}
		return payload
	}
}

// getModelName returns the appropriate model name based on the isReasoning flag.
func (c *GrokClient) getModelName() string {
	if c.isReasoning {
		return grok3ReasoningModelName // "grok-3-reasoning"
	} else {
		return grok3ModelName // "grok-3"
	}
}

// RequestBody represents the structure of the JSON body expected in POST requests to the /v1/chat/completions endpoint.
type RequestBody struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content any    `json:"content"` // Can be string or array of parts for vision
	} `json:"messages"`
	Stream           bool   `json:"stream"`
	GrokCookies      any    `json:"grokCookies,omitempty"`   // A single cookie(string), or a list of cookie([]string)
	CookieIndex      uint   `json:"cookieIndex,omitempty"`   // Start from 1, 0 means auto-select cookies in turn
	EnableSearch     int    `json:"enableSearch,omitempty"`  // > 0 is true, == 0 is false
	UploadMessage    int    `json:"uploadMessage,omitempty"` // > 0 is true, == 0 is false (Now mainly for large text)
	TextBeforePrompt string `json:"textBeforePrompt,omitempty"`
	TextAfterPrompt  string `json:"textAfterPrompt,omitempty"`
	KeepChat         int    `json:"keepChat,omitempty"`       // > 0 is true, == 0 is false
	IgnoreThinking   int    `json:"ignoreThinking,omitempty"` // > 0 is true, == 0 is false
	// Added Imgur Client ID override
	ImgurClientID string `json:"imgurClientID,omitempty"` // Allow overriding Imgur Client ID per request
}

// --- Enhanced Response Parsing Structures ---

// GrokStreamingImageResponse represents the structure for streaming image generation updates.
type GrokStreamingImageResponse struct {
	ImageID  string `json:"imageId"`
	ImageURL string `json:"imageUrl"` // The partial URL
	Seq      int    `json:"seq"`
	Progress int    `json:"progress"`
}

// GrokModelResponse represents the structure of the final model response message.
type GrokModelResponse struct {
	ResponseID         string   `json:"responseId"`
	Message            string   `json:"message"` // Text message
	GeneratedImageUrls []string `json:"generatedImageUrls"` // List of final partial image URLs
	// Add other fields from ModelResponse if needed
}

// GrokResultResponse represents the 'response' part within the 'result' object.
type GrokResultResponse struct {
	Token                        string                      `json:"token"`
	IsThinking                   bool                        `json:"isThinking"`
	MessageTag                   string                      `json:"messageTag,omitempty"`
	StreamingImageGenerationResp *GrokStreamingImageResponse `json:"streamingImageGenerationResponse,omitempty"` // Pointer to handle absence
	ModelResp                    *GrokModelResponse          `json:"modelResponse,omitempty"`                    // Pointer to handle absence
}

// GrokResult represents the 'result' object in the streaming JSON.
type GrokResult struct {
	Response GrokResultResponse `json:"response"`
	// Add other fields from 'result' if needed (like 'conversation', 'title')
}

// GrokStreamChunk represents a single line (chunk) in the Grok streaming response.
type GrokStreamChunk struct {
	Result GrokResult `json:"result"`
	// Add top-level fields like 'error' if they exist in the stream
}

// --- End Enhanced Response Parsing Structures ---

// ModelData represents model metadata for OpenAI-compatible response.
type ModelData struct {
	Id       string `json:"id"`
	Object   string `json:"object"`
	Owned_by string `json:"owned_by"`
}

// ModelList contains available models for OpenAI-compatible endpoint.
type ModelList struct {
	Object string      `json:"object"`
	Data   []ModelData `json:"data"`
}

// UploadFileRequest represents the request payload for uploading a file to Grok.
type UploadFileRequest struct {
	Content      string `json:"content"` // Base64 encoded content
	FileMimeType string `json:"fileMimeType"`
	FileName     string `json:"fileName"`
}

// UploadFileResponse represents the response payload after uploading a file to Grok.
type UploadFileResponse struct {
	FileMetadataId string `json:"fileMetadataId"` // The crucial ID needed for chat request
	// Add other fields if present in the actual response and needed
}

// ImgurUploadResponse represents the structure of the response from Imgur API.
type ImgurUploadResponse struct {
	Data struct {
		Link string `json:"link"` // The direct link to the uploaded image
		// Include other fields like 'id', 'deletehash' if needed
	} `json:"data"`
	Success bool `json:"success"`
	Status  int  `json:"status"`
}

// Constants
const (
	newChatUrl    = "https://grok.com/rest/app-chat/conversations/new" // Endpoint for creating new conversations
	uploadFileUrl = "https://grok.com/rest/app-chat/upload-file"       // Endpoint for uploading files (for vision)
	grokAssetBase = "https://assets.grok.com"                          // Base URL for downloading generated images
	imgurUploadUrl = "https://api.imgur.com/3/image"                   // Imgur API endpoint for image upload

	grok3ModelName          = "grok-3"
	grok3ReasoningModelName = "grok-3-reasoning"

	completionsPath = "/v1/chat/completions"
	listModelsPath  = "/v1/models"

	messageCharsLimit = 50000 // Default limit for *text* message upload

	defaultBeforePromptText    = "For the data below, entries with '[[system]]' are system information, entries with '[[assistant]]' are messages you have previously sent, entries with '[[user]]' are messages sent by the user. You need to respond to the user's last message accordingly based on the corresponding data."
	defaultUploadMessagePrompt = "Follow the instructions in the attached file to respond." // Used if *text* message is uploaded
)

// Global configuration variables set.
var (
	apiToken         *string
	grokCookies      []string
	textBeforePrompt *string
	textAfterPrompt  *string
	keepChat         *bool
	ignoreThinking   *bool
	charsLimit       *uint // Limit for uploading *text* message
	httpProxy        *string
	imgurClientID    *string // Added global Imgur Client ID
	httpClient       = &http.Client{Timeout: 30 * time.Minute}
	nextCookieIndex  = struct { // Thread-safe cookie rotation
		sync.Mutex
		index uint // Start from 0
	}{}
)

// decompressBody decompresses the response body based on Content-Encoding header.
func decompressBody(resp *http.Response) (io.ReadCloser, error) {
	switch resp.Header.Get("content-encoding") {
	case "br":
		return io.NopCloser(brotli.NewReader(resp.Body)), nil
	case "gzip":
		return gzip.NewReader(resp.Body)
	case "": // No compression
		return resp.Body, nil
	default:
		// Log the unsupported encoding but return the raw body anyway,
		// hoping it might be readable text (e.g., an error message).
		log.Printf("Warning: Unsupported response encoding '%s', attempting to read raw body.", resp.Header.Get("content-encoding"))
		return resp.Body, nil
		// Original stricter approach:
		// return nil, fmt.Errorf("unknown response encoding: %s", resp.Header.Get("content-encoding"))
	}
}

// doRequest sends an HTTP request with the specified method, URL, and payload.
// It handles JSON marshaling, setting headers (including dynamic ones), and sending the request.
// Added optional custom headers parameter.
func (c *GrokClient) doRequest(method string, url string, payload any, customHeaders map[string]string) (*http.Response, error) {
	var reqBody io.Reader
	if payload != nil {
		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload for %s: %v", url, err)
		}
		// Debugging: Print payload for specific endpoints if needed
		// if url == uploadFileUrl || url == newChatUrl {
		// 	log.Printf("Sending Payload to %s:\n%s\n", url, string(jsonPayload))
		// }
		reqBody = bytes.NewBuffer(jsonPayload)
	} else {
		reqBody = nil // For requests without a body (e.g., GET)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %v", url, err)
	}

	// Set base headers from GrokClient (if not overridden by custom headers)
	for key, value := range c.headers {
		if _, exists := customHeaders[key]; !exists { // Only set if not in custom headers
			req.Header.Set(key, value)
		}
	}

	// Apply custom headers (these will override base headers if keys match)
	if customHeaders != nil {
		for key, value := range customHeaders {
			req.Header.Set(key, value)
		}
	}

	// Add dynamic headers required by Grok API (based on captured request)
	// Only add these if not already set by custom headers
	if req.Header.Get("x-xai-request-id") == "" {
		req.Header.Set("x-xai-request-id", uuid.New().String())
	}
	// Add other dynamic headers like sentry-trace, baggage if needed and stable
	// req.Header.Set("sentry-trace", generateSentryTrace()) // Requires implementation
	// req.Header.Set("baggage", generateBaggage()) // Requires implementation

	resp, err := httpClient.Do(req)
	if err != nil {
		// Network-level error
		return nil, fmt.Errorf("failed to send request to %s: %v", url, err)
	}

	// Check for non-200 status codes AFTER potentially attempting decompression
	if resp.StatusCode != http.StatusOK {
		// Try to read the error body, handling potential decompression issues
		respBodyStream, decompErr := decompressBody(resp)
		bodyBytes := []byte("Could not read error body") // Default error message
		if decompErr == nil && respBodyStream != nil {
			bodyBytes, _ = io.ReadAll(respBodyStream) // Read the decompressed body
			respBodyStream.Close()                    // Close the stream
		} else {
			// If decompression failed, try reading the raw body
			rawBodyBytes, readErr := io.ReadAll(resp.Body)
			if readErr == nil {
				bodyBytes = rawBodyBytes
			} else {
				log.Printf("Failed to read raw error body after decompression error (%v): %v", decompErr, readErr)
			}
		}
		resp.Body.Close() // Ensure original body is closed

		// Log and return a formatted error
		errMsg := fmt.Sprintf("API error for %s: %s (Status Code: %d)", url, resp.Status, resp.StatusCode)
		if len(bodyBytes) > 0 {
			errMsg += fmt.Sprintf(", Response Body: %s", string(bodyBytes)[:min(len(bodyBytes), 256)]) // Limit body length in log
		}
		return nil, fmt.Errorf(errMsg)
	}

	// Return the successful response (body will be decompressed by caller using decompressBody again)
	return resp, nil
}

// uploadGrokFile uploads content (text or image) as a file to Grok and returns the fileMetadataId.
// Handles Base64 encoding internally.
func (c *GrokClient) uploadGrokFile(content []byte, mimeType string, fileName string) (*UploadFileResponse, error) {
	if content == nil {
		return nil, fmt.Errorf("cannot upload nil content")
	}
	base64Content := base64.StdEncoding.EncodeToString(content)
	payload := UploadFileRequest{
		Content:      base64Content,
		FileMimeType: mimeType,
		FileName:     fileName,
	}
	log.Printf("Uploading file '%s' (%s, %d bytes) to Grok...", fileName, mimeType, len(content))

	// Use nil for customHeaders as this request uses standard Grok headers
	resp, err := c.doRequest(http.MethodPost, uploadFileUrl, payload, nil)
	if err != nil {
		// Error already formatted by doRequest
		return nil, fmt.Errorf("upload file request failed: %w", err)
	}
	defer resp.Body.Close() // Ensure body is closed

	respBody, err := decompressBody(resp)
	if err != nil {
		// Read raw body for potential error message
		rawBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decompress upload response: %v. Raw body: %s", err, string(rawBody)[:min(len(rawBody), 128)])
	}
	defer respBody.Close() // Ensure decompressed body is closed

	body, err := io.ReadAll(respBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read decompressed upload response body: %v", err)
	}

	var response UploadFileResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse upload response JSON: %v. Body: %s", err, string(body)[:min(len(body), 128)])
	}

	if response.FileMetadataId == "" {
		return nil, fmt.Errorf("upload response missing 'fileMetadataId'. Body: %s", string(body)[:min(len(body), 128)])
	}

	log.Printf("Successfully uploaded file '%s', got fileMetadataId: %s", fileName, response.FileMetadataId)
	return &response, nil
}

// downloadGrokImage fetches the image bytes from Grok's asset server.
func (c *GrokClient) downloadGrokImage(partialUrl string) ([]byte, error) {
	if partialUrl == "" {
		return nil, fmt.Errorf("cannot download image from empty URL")
	}
	fullUrl := grokAssetBase + "/" + strings.TrimPrefix(partialUrl, "/")
	log.Printf("Downloading generated image from: %s", fullUrl)

	// Use doRequest for GET, passing nil payload and nil custom headers
	// This ensures the client's cookies are used for authentication.
	resp, err := c.doRequest(http.MethodGet, fullUrl, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to start image download request for %s: %w", fullUrl, err)
	}
	defer resp.Body.Close()

	// Decompress if necessary
	respBody, err := decompressBody(resp)
	if err != nil {
		rawBody, _ := io.ReadAll(resp.Body) // Try reading raw body on decompression error
		return nil, fmt.Errorf("failed to decompress image response from %s: %v. Raw body: %s", fullUrl, err, string(rawBody)[:min(len(rawBody), 128)])
	}
	defer respBody.Close()

	imageData, err := io.ReadAll(respBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read image data from %s: %w", fullUrl, err)
	}

	log.Printf("Successfully downloaded image (%d bytes) from %s", len(imageData), fullUrl)
	return imageData, nil
}

// uploadToImgur uploads image data to Imgur anonymously.
func (c *GrokClient) uploadToImgur(imageData []byte) (string, error) {
	if c.imgurClientID == "" {
		return "", fmt.Errorf("Imgur Client ID is not configured. Cannot upload image.")
	}
	if len(imageData) == 0 {
		return "", fmt.Errorf("cannot upload empty image data to Imgur")
	}

	log.Printf("Uploading image (%d bytes) to Imgur...", len(imageData))

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add image data as a form field named "image"
	part, err := writer.CreateFormFile("image", "grok_generated_image."+guessExtension(http.DetectContentType(imageData)))
	if err != nil {
		return "", fmt.Errorf("failed to create form file for Imgur upload: %w", err)
	}
	_, err = io.Copy(part, bytes.NewReader(imageData))
	if err != nil {
		return "", fmt.Errorf("failed to copy image data to form for Imgur upload: %w", err)
	}

	// Add other fields if needed (e.g., title, description - check Imgur API docs)
	// writer.WriteField("title", "Generated by Grok")

	err = writer.Close() // Close writer to finalize the multipart body
	if err != nil {
		return "", fmt.Errorf("failed to close multipart writer for Imgur upload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, imgurUploadUrl, body)
	if err != nil {
		return "", fmt.Errorf("failed to create Imgur upload request: %w", err)
	}

	// Set Imgur required headers
	req.Header.Set("Authorization", "Client-ID "+c.imgurClientID)
	req.Header.Set("Content-Type", writer.FormDataContentType()) // Set correct multipart content type

	// Use the global httpClient which respects proxy settings
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send Imgur upload request: %w", err)
	}
	defer resp.Body.Close()

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read Imgur upload response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Imgur API error: %s (Status: %d), Body: %s", resp.Status, resp.StatusCode, string(respBodyBytes)[:min(len(respBodyBytes), 256)])
	}

	var imgurResp ImgurUploadResponse
	err = json.Unmarshal(respBodyBytes, &imgurResp)
	if err != nil {
		return "", fmt.Errorf("failed to parse Imgur upload response JSON: %w. Body: %s", err, string(respBodyBytes)[:min(len(respBodyBytes), 256)])
	}

	if !imgurResp.Success || imgurResp.Data.Link == "" {
		return "", fmt.Errorf("Imgur upload failed according to response. Status: %d, Success: %v, Body: %s", imgurResp.Status, imgurResp.Success, string(respBodyBytes)[:min(len(respBodyBytes), 256)])
	}

	log.Printf("Successfully uploaded image to Imgur: %s", imgurResp.Data.Link)
	return imgurResp.Data.Link, nil
}

// sendMessage sends a message (potentially with file attachments) to the Grok 3 Web API.
func (c *GrokClient) sendMessage(message string, fileIDs []string, searchType string) (*http.Response, error) {
	var effectiveMessage = message
	var effectiveFileIDs = fileIDs

	// Check if *text* message should be uploaded due to length
	// This does NOT upload images, only large text content.
	// Images are handled separately before calling sendMessage.
	shouldUploadText := c.uploadMessage || (len(message) > int(*charsLimit) && utf8.RuneCountInString(message) > int(*charsLimit))

	if shouldUploadText && searchType == "none" { // Only upload text if not in search mode
		log.Printf("Text message length (%d chars) exceeds limit (%d), uploading as file.", utf8.RuneCountInString(message), *charsLimit)
		textFileName := uuid.New().String() + ".txt"
		uploadResp, err := c.uploadGrokFile([]byte(message), "text/plain", textFileName)
		if err != nil {
			// Log the error but maybe try sending truncated message? Or just fail?
			// For now, fail the request if text upload fails.
			return nil, fmt.Errorf("failed to upload long text message: %w", err)
		}
		// Replace message with prompt and add file ID
		effectiveMessage = defaultUploadMessagePrompt
		effectiveFileIDs = append(effectiveFileIDs, uploadResp.FileMetadataId) // Add text file ID
		log.Printf("Replaced long text message with prompt and file attachment ID: %s", uploadResp.FileMetadataId)
	}

	// Prepare payload using the potentially modified message and fileIDs
	payload := c.preparePayload(effectiveMessage, effectiveFileIDs, searchType)

	// Debug log to confirm the payload being sent
	// jsonPayloadBytes, _ := json.MarshalIndent(payload, "", "  ")
	// log.Printf("DEBUG: Sending Payload to %s:\n%s", newChatUrl, string(jsonPayloadBytes))

	// Use nil for customHeaders as this request uses standard Grok headers
	resp, err := c.doRequest(http.MethodPost, newChatUrl, payload, nil)
	if err != nil {
		// Error already formatted by doRequest
		return nil, fmt.Errorf("send message request failed: %w", err)
	}

	return resp, nil
}

// --- OpenAI Response Structures (Unchanged) ---
type OpenAIChatCompletionMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIChatCompletionChunkChoice struct {
	Index        int                         `json:"index"`
	Delta        OpenAIChatCompletionMessage `json:"delta"`
	FinishReason *string                     `json:"finish_reason"` // Use pointer for null
}

type OpenAIChatCompletionChunk struct {
	ID      string                            `json:"id"`
	Object  string                            `json:"object"`
	Created int64                             `json:"created"`
	Model   string                            `json:"model"`
	Choices []OpenAIChatCompletionChunkChoice `json:"choices"`
}

type OpenAIChatCompletionChoice struct {
	Index        int                         `json:"index"`
	Message      OpenAIChatCompletionMessage `json:"message"`
	FinishReason string                      `json:"finish_reason"`
}

type OpenAIChatCompletionUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type OpenAIChatCompletion struct {
	ID      string                       `json:"id"`
	Object  string                       `json:"object"`
	Created int64                        `json:"created"`
	Model   string                       `json:"model"`
	Choices []OpenAIChatCompletionChoice `json:"choices"`
	Usage   OpenAIChatCompletionUsage    `json:"usage"`
}

// parseGrok3StreamingJson parses the streaming response from Grok 3.
// It now also extracts final generated image URLs.
func (c *GrokClient) parseGrok3StreamingJson(stream io.Reader, handler func(respToken string), isSearchMode bool) (finalText string, generatedImageUrls []string) {
	isThinking := false
	var textBuilder strings.Builder // Accumulate text tokens
	reader := bufio.NewReader(stream)

	for {
		line, err := reader.ReadBytes('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			log.Printf("Error reading stream line: %v", err)
			break
		}

		trimmedLine := bytes.TrimSpace(line)
		if len(trimmedLine) == 0 {
			continue
		}

		// Use the more detailed GrokStreamChunk structure
		var chunk GrokStreamChunk
		err = json.Unmarshal(trimmedLine, &chunk)
		if err != nil {
			log.Printf("Parsing json error during stream for line '%s': %v", string(trimmedLine), err)
			continue
		}

		// --- Extract relevant data from the chunk ---
		respData := chunk.Result.Response
		respToken := respData.Token // <--- Get the base token for this chunk

		// Handle image generation progress (optional logging)
		if respData.StreamingImageGenerationResp != nil {
			imgResp := respData.StreamingImageGenerationResp
			log.Printf("Image Generation Progress: ID=%s, Seq=%d, Progress=%d%%, URL=%s",
				imgResp.ImageID, imgResp.Seq, imgResp.Progress, imgResp.ImageURL)
			// We don't act on intermediate URLs, wait for the final modelResponse
		}

		// Handle final model response (extract image URLs only, DO NOT add message to respToken)
		if respData.ModelResp != nil {
			modelResp := respData.ModelResp
			// --- FIX START: Remove the addition of modelResp.Message to respToken ---
			// // Check if images were generated in this specific chunk
			// hasImagesInThisChunk := len(modelResp.GeneratedImageUrls) > 0
			//
			// if !hasImagesInThisChunk && modelResp.Message != "" {
			//  // This message often summarizes the action, like "I generated images..."
			//  // Only append the message if it's *not* just the image generation summary,
			//  // as the image URLs will be handled separately later.
			//  // REMOVED: respToken += modelResp.Message // <<< THIS LINE CAUSED DUPLICATION
			// }
			// --- FIX END ---
			if len(modelResp.GeneratedImageUrls) > 0 {
				generatedImageUrls = append(generatedImageUrls, modelResp.GeneratedImageUrls...)
				log.Printf("Extracted %d final generated image URLs from modelResponse.", len(modelResp.GeneratedImageUrls))
			}
		}

		// --- Standard token processing ---
		if isSearchMode && respData.MessageTag != "final" {
			continue // Skip non-final chunks in DeepSearch mode
		}

		// Apply thinking tags (modifies respToken before handler/builder use)
		if c.ignoreThinking && respData.IsThinking {
			continue // Skip the whole chunk if ignoring thinking
		} else if respData.IsThinking {
			if !isThinking {
				respToken = "<think>\n" + respToken
			}
			isThinking = true
		} else if isThinking {
			respToken = respToken + "\n</think>\n\n"
			isThinking = false
		}

		// Use the (potentially modified by thinking tags) token for both handler and builder
		if respToken != "" {
			handler(respToken)                 // Send token to the streaming handler
			textBuilder.WriteString(respToken) // Accumulate text using the token (without the extra modelResponse.message)
		}
	}
	finalText = textBuilder.String()
	return // Return accumulated text and image URLs
}

// createOpenAIStreamingResponse returns an HTTP handler for streaming OpenAI format responses.
// Now handles appending Imgur URLs at the end.
func (c *GrokClient) createOpenAIStreamingResponse(grokStream io.Reader, isSearchMode bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		// w.Header().Set("Access-Control-Allow-Origin", "*") // Optional: For browser clients

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, logPrintf("Streaming unsupported!"), http.StatusInternalServerError)
			return
		}

		completionID := "chatcmpl-" + uuid.New().String()
		modelName := c.getModelName() // Get model name from client state
		startTime := time.Now().Unix()

		// Send initial chunk (optional, mimics OpenAI structure)
		startChunk := OpenAIChatCompletionChunk{
			ID:      completionID,
			Object:  "chat.completion.chunk",
			Created: startTime,
			Model:   modelName,
			Choices: []OpenAIChatCompletionChunkChoice{
				{
					Index: 0,
					Delta: OpenAIChatCompletionMessage{
						Role: "assistant", // Indicate assistant is starting
					},
					FinishReason: nil, // Explicitly null
				},
			},
		}
		fmt.Fprintf(w, "data: %s\n\n", mustMarshal(startChunk))
		flusher.Flush()

		// Process the Grok stream and send delta chunks
		// Collect final image URLs (ignore final text in streaming)
		_, grokImageUrls := c.parseGrok3StreamingJson(grokStream, func(respToken string) { // Corrected: Ignore finalText
			chunk := OpenAIChatCompletionChunk{
				ID:      completionID,
				Object:  "chat.completion.chunk",
				Created: startTime, // Use consistent creation time
				Model:   modelName,
				Choices: []OpenAIChatCompletionChunkChoice{
					{
						Index: 0,
						Delta: OpenAIChatCompletionMessage{
							Content: respToken, // Send the actual token delta
						},
						FinishReason: nil, // Explicitly null
					},
				},
			}
			fmt.Fprintf(w, "data: %s\n\n", mustMarshal(chunk))
			flusher.Flush()
		}, isSearchMode) // Pass search mode flag

		// --- Image Handling ---
		var imgurUrls []string
		if len(grokImageUrls) > 0 && c.imgurClientID != "" {
			log.Printf("Processing %d generated Grok image URLs for Imgur upload...", len(grokImageUrls))
			for _, partialUrl := range grokImageUrls {
				imageData, err := c.downloadGrokImage(partialUrl)
				if err != nil {
					log.Printf("Error downloading Grok image (%s): %v. Skipping upload.", partialUrl, err)
					continue
				}
				imgurUrl, err := c.uploadToImgur(imageData)
				if err != nil {
					log.Printf("Error uploading image (from %s) to Imgur: %v. Skipping URL.", partialUrl, err)
					continue
				}
				imgurUrls = append(imgurUrls, imgurUrl)
			}
		} else if len(grokImageUrls) > 0 && c.imgurClientID == "" {
			log.Printf("Warning: Grok generated %d images, but Imgur Client ID is not configured. Cannot upload.", len(grokImageUrls))
		}

		// Append Imgur URLs to the final response chunk if any were successfully uploaded
		if len(imgurUrls) > 0 {
			imgurSection := "\n\n--- Generated Images ---\n" + strings.Join(imgurUrls, "\n")
			finalImgChunk := OpenAIChatCompletionChunk{
				ID:      completionID,
				Object:  "chat.completion.chunk",
				Created: startTime,
				Model:   modelName,
				Choices: []OpenAIChatCompletionChunkChoice{
					{
						Index: 0,
						Delta: OpenAIChatCompletionMessage{
							Content: imgurSection, // Send the Imgur URLs
						},
						FinishReason: nil,
					},
				},
			}
			fmt.Fprintf(w, "data: %s\n\n", mustMarshal(finalImgChunk))
			flusher.Flush()
		}
		// --- End Image Handling ---

		// Send the final chunk with finish reason
		finishReason := "stop"
		finalChunk := OpenAIChatCompletionChunk{
			ID:      completionID,
			Object:  "chat.completion.chunk",
			Created: startTime, // Use consistent creation time
			Model:   modelName,
			Choices: []OpenAIChatCompletionChunkChoice{
				{
					Index:        0,
					Delta:        OpenAIChatCompletionMessage{}, // Empty delta
					FinishReason: &finishReason,               // Set finish reason
				},
			},
		}
		fmt.Fprintf(w, "data: %s\n\n", mustMarshal(finalChunk))
		flusher.Flush()

		// Finish the stream
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	}
}

// createOpenAIFullResponse returns an HTTP handler for non-streaming OpenAI format responses.
// Now handles appending Imgur URLs at the end.
func (c *GrokClient) createOpenAIFullResponse(grokFull io.Reader, isSearchMode bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Collect final text and image URLs
		finalText, grokImageUrls := c.parseGrok3StreamingJson(grokFull, func(respToken string) {
			// Don't need to do anything with tokens here for non-streaming
		}, isSearchMode) // Pass search mode flag

		// --- Image Handling ---
		var imgurUrls []string
		if len(grokImageUrls) > 0 && c.imgurClientID != "" {
			log.Printf("Processing %d generated Grok image URLs for Imgur upload...", len(grokImageUrls))
			for _, partialUrl := range grokImageUrls {
				imageData, err := c.downloadGrokImage(partialUrl)
				if err != nil {
					log.Printf("Error downloading Grok image (%s): %v. Skipping upload.", partialUrl, err)
					continue
				}
				imgurUrl, err := c.uploadToImgur(imageData)
				if err != nil {
					log.Printf("Error uploading image (from %s) to Imgur: %v. Skipping URL.", partialUrl, err)
					continue
				}
				imgurUrls = append(imgurUrls, imgurUrl)
			}
		} else if len(grokImageUrls) > 0 && c.imgurClientID == "" {
			log.Printf("Warning: Grok generated %d images, but Imgur Client ID is not configured. Cannot upload.", len(grokImageUrls))
		}

		// Append Imgur URLs to the final response text if any were successfully uploaded
		if len(imgurUrls) > 0 {
			imgurSection := "\n\n--- Generated Images ---\n" + strings.Join(imgurUrls, "\n")
			finalText += imgurSection
		}
		// --- End Image Handling ---

		openAIResponse := c.createOpenAIFullResponseBody(finalText) // Use the potentially modified final text
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(openAIResponse); err != nil {
			http.Error(w, logPrintf("Encoding response error: %v", err), http.StatusInternalServerError)
		}
	}
}

// createOpenAIFullResponseBody creates the OpenAI response body for non-streaming requests.
func (c *GrokClient) createOpenAIFullResponseBody(content string) OpenAIChatCompletion {
	modelName := c.getModelName()
	return OpenAIChatCompletion{
		ID:      "chatcmpl-" + uuid.New().String(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   modelName,
		Choices: []OpenAIChatCompletionChoice{
			{
				Index: 0,
				Message: OpenAIChatCompletionMessage{
					Role:    "assistant",
					Content: content,
				},
				FinishReason: "stop",
			},
		},
		Usage: OpenAIChatCompletionUsage{
			PromptTokens:     -1, // Placeholder
			CompletionTokens: -1, // Placeholder
			TotalTokens:      -1, // Placeholder
		},
	}
}

// mustMarshal serializes the given value to a JSON string, panicking on error.
func mustMarshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		log.Panicf("Failed to marshal JSON: %v", err) // More informative panic
	}
	return string(b)
}

// logPrintf prints the message to the standard logger and returns the string.
func logPrintf(format string, a ...any) string {
	msg := fmt.Sprintf(format, a...)
	log.Print(msg) // Log message prefixed with timestamp and source file:line
	return msg
}

// getCookieIndex selects the next cookie index in a round-robin fashion.
func getCookieIndex(numCookies int, requestedIndex uint) uint {
	if numCookies <= 0 {
		return 0 // Should not happen if cookies are loaded, but safe guard
	}
	if requestedIndex == 0 || requestedIndex > uint(numCookies) {
		// Auto-select mode or invalid index
		nextCookieIndex.Lock()
		defer nextCookieIndex.Unlock()
		indexToUse := nextCookieIndex.index
		nextCookieIndex.index = (nextCookieIndex.index + 1) % uint(numCookies) // Rotate
		return indexToUse
	} else {
		// User-provided 1-based index
		return requestedIndex - 1
	}
}

// Regexes for DeepSearch keywords
var (
	deepSearchRegex   = regexp.MustCompile(`(?i)\bdeepsearch\b`)
	deeperSearchRegex = regexp.MustCompile(`(?i)\bdeepersearch\b`)
)

// Helper to get image data from URL (http/https or data URI)
func getImageDataFromURL(urlString string) ([]byte, string, error) {
	if strings.HasPrefix(urlString, "data:") {
		// Decode Base64 data URL
		parts := strings.SplitN(urlString, ",", 2)
		if len(parts) != 2 {
			return nil, "", fmt.Errorf("invalid data URL format")
		}
		meta := parts[0] // e.g., data:image/png;base64
		data := parts[1]
		mimeType := "application/octet-stream" // Default
		if strings.HasPrefix(meta, "data:") && strings.Contains(meta, ";base64") {
			mimeType = strings.TrimSuffix(strings.TrimPrefix(meta, "data:"), ";base64")
		}
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decode base64 data: %w", err)
		}
		log.Printf("Decoded image from data URL, MIME: %s, Size: %d bytes", mimeType, len(decoded))
		return decoded, mimeType, nil
	} else if strings.HasPrefix(urlString, "http://") || strings.HasPrefix(urlString, "https://") {
		// Fetch image from URL
		log.Printf("Fetching image from URL: %s", urlString)
		resp, err := httpClient.Get(urlString) // Use the global client which respects proxy settings
		if err != nil {
			return nil, "", fmt.Errorf("failed to fetch image URL %s: %w", urlString, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return nil, "", fmt.Errorf("failed to fetch image URL %s: status %s, body: %s", urlString, resp.Status, string(bodyBytes)[:min(len(bodyBytes), 128)])
		}

		imageData, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read image data from URL %s: %w", urlString, err)
		}

		// Determine MIME type from Content-Type header, fallback if missing
		mimeType := resp.Header.Get("Content-Type")
		if mimeType == "" || mimeType == "application/octet-stream" {
			// Attempt to detect from content if header is generic/missing
			detectedMime := http.DetectContentType(imageData)
			log.Printf("Detected MIME type for URL %s: %s (Header was: '%s')", urlString, detectedMime, mimeType)
			mimeType = detectedMime
		} else {
			// Sanitize potentially complex Content-Type headers (e.g., "image/jpeg; charset=utf-8")
			parsedMime, _, err := mime.ParseMediaType(mimeType)
			if err == nil {
				mimeType = parsedMime // Use the base MIME type
			} else {
				log.Printf("Warning: Could not parse Content-Type header '%s': %v. Using original value.", mimeType, err)
			}
		}

		log.Printf("Fetched image from URL %s, MIME: %s, Size: %d bytes", urlString, mimeType, len(imageData))
		return imageData, mimeType, nil
	} else {
		return nil, "", fmt.Errorf("unsupported image URL scheme in: %s", urlString)
	}
}

// guessExtension attempts to guess a file extension based on MIME type.
func guessExtension(mimeType string) string {
	// Normalize MIME type (e.g., remove parameters like charset)
	baseMime, _, err := mime.ParseMediaType(mimeType)
	if err == nil {
		mimeType = baseMime
	}

	extensions, err := mime.ExtensionsByType(mimeType)
	if err != nil || len(extensions) == 0 {
		// Fallback based on common types if standard library fails or returns nothing
		switch strings.ToLower(mimeType) { // Use lowercase for comparison
		case "image/jpeg":
			return "jpg"
		case "image/png":
			return "png"
		case "image/gif":
			return "gif"
		case "image/webp":
			return "webp"
		case "text/plain":
			return "txt" // For text uploads
		default:
			log.Printf("Warning: Could not determine standard extension for MIME type '%s'. Using default 'bin'.", mimeType)
			return "bin" // Generic binary extension
		}
	}
	// Return the first extension (often the most common, e.g., ".jpg" for image/jpeg)
	// Remove the leading dot
	return strings.TrimPrefix(extensions[0], ".")
}

// handleChatCompletion handles incoming POST requests to /v1/chat/completions.
func handleChatCompletion(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request from %s for %s", r.RemoteAddr, completionsPath)

	if r.Method != http.MethodPost {
		http.Error(w, logPrintf("Method %s Not Allowed", r.Method), http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, logPrintf("Unauthorized: Bearer token required"), http.StatusUnauthorized)
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if token != *apiToken {
		http.Error(w, logPrintf("Unauthorized: Invalid token"), http.StatusUnauthorized)
		return
	}

	body := RequestBody{EnableSearch: -1, KeepChat: -1, IgnoreThinking: -1}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, logPrintf("Bad Request: Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// --- Cookie Selection ---
	var cookie string
	var selectedCookies []string
	cookieSource := "global config" // Default source

	if body.GrokCookies != nil {
		cookieSource = "request body"
		if ck, ok := body.GrokCookies.(string); ok && strings.TrimSpace(ck) != "" {
			selectedCookies = []string{ck}
		} else if list, ok := body.GrokCookies.([]any); ok {
			strList := make([]string, 0, len(list))
			validCookieFound := false
			for i, item := range list {
				if ck, ok := item.(string); ok && strings.TrimSpace(ck) != "" {
					strList = append(strList, strings.TrimSpace(ck))
					validCookieFound = true
				} else {
					log.Printf("Warning: Invalid Grok 3 cookie type or empty string in request list at index %d", i)
					// Don't fail the request, just ignore invalid entry
				}
			}
			if validCookieFound {
				selectedCookies = strList
			} else {
				cookieSource = "global config" // Fallback if request cookies were invalid/empty
			}
		} else {
			log.Printf("Warning: Invalid type for 'grokCookies' field in request, falling back to global cookies.")
			cookieSource = "global config" // Fallback
		}
	}

	// Fallback to global cookies if needed
	if len(selectedCookies) == 0 {
		if len(grokCookies) > 0 {
			selectedCookies = grokCookies
			cookieSource = "global config"
		} else {
			http.Error(w, logPrintf("Error: No Grok 3 cookie available (checked request body and global config)"), http.StatusBadRequest)
			return
		}
	}

	cookieIndex := getCookieIndex(len(selectedCookies), body.CookieIndex)
	cookie = selectedCookies[cookieIndex]
	log.Printf("Using cookie index %d (0-based) from %s (%d available cookies)", cookieIndex, cookieSource, len(selectedCookies))

	// --- Configuration Override ---
	isReasoning := false
	if strings.TrimSpace(body.Model) == grok3ReasoningModelName {
		isReasoning = true
	}
	enableSearch := true
	if body.EnableSearch == 0 {
		enableSearch = false
	}
	uploadLongText := false // Renamed from uploadMessage for clarity
	if body.UploadMessage > 0 {
		uploadLongText = true // Now specifically controls long text upload
	}
	keepConversation := *keepChat // Start with global default
	if body.KeepChat == 0 {       // 0 means false override
		keepConversation = false
	} else if body.KeepChat > 0 { // >0 means true override
		keepConversation = true
	}
	ignoreThink := *ignoreThinking // Start with global default
	if body.IgnoreThinking == 0 {
		ignoreThink = false
	} else if body.IgnoreThinking > 0 {
		ignoreThink = true
	}
	beforePrompt := *textBeforePrompt
	if body.TextBeforePrompt != "" {
		beforePrompt = body.TextBeforePrompt
	}
	afterPrompt := *textAfterPrompt
	if body.TextAfterPrompt != "" {
		afterPrompt = body.TextAfterPrompt
	}
	// Resolve Imgur Client ID (request overrides global)
	resolvedImgurClientID := *imgurClientID // Start with global default
	if body.ImgurClientID != "" {
		resolvedImgurClientID = body.ImgurClientID
		log.Printf("Using Imgur Client ID provided in request.")
	} else if resolvedImgurClientID == "" {
		log.Printf("Warning: Imgur Client ID not configured globally or in request. Image uploads will be skipped.")
	}

	// --- Initialize Grok Client with resolved settings ---
	// Use resolved settings, not just global defaults
	grokClient := NewGrokClient(cookie, isReasoning, enableSearch, uploadLongText, keepConversation, ignoreThink, resolvedImgurClientID)

	// --- Message Processing: Extract Text, Handle Images, Detect Keywords ---
	var textParts []string
	var imageFileIDs []string // Store IDs of successfully uploaded images
	searchType := "none"      // Default: no search keyword detected
	var finalUserContentForSearch string // Store user text content if search is detected

	if len(body.Messages) == 0 {
		http.Error(w, logPrintf("Bad Request: No messages provided"), http.StatusBadRequest)
		return
	}

	// Process messages to build final text and upload images
	lastUserMessageIndex := -1 // Find the index of the last user message
	for i := len(body.Messages) - 1; i >= 0; i-- {
		if body.Messages[i].Role == "user" {
			lastUserMessageIndex = i
			break
		}
	}

	for i, msg := range body.Messages {
		rolePrefix := fmt.Sprintf("\n[[%s]]\n", msg.Role)
		textParts = append(textParts, rolePrefix)

		if contentStr, ok := msg.Content.(string); ok {
			textParts = append(textParts, contentStr)
			// Check for search keywords only in the *last* user message string content
			if msg.Role == "user" && i == lastUserMessageIndex {
				finalUserContentForSearch = contentStr // Store for potential modification
			}
		} else if contentArr, ok := msg.Content.([]any); ok {
			// Handle OpenAI vision format (array of parts)
			partTexts := []string{} // Collect text parts within this message
			isThisTheLastUserMsg := (msg.Role == "user" && i == lastUserMessageIndex)

			for _, partAny := range contentArr {
				partMap, ok := partAny.(map[string]any)
				if !ok {
					log.Printf("Warning: Skipping invalid content part format in message for role %s: %T", msg.Role, partAny)
					continue
				}
				partType, _ := partMap["type"].(string)

				if partType == "text" {
					text, _ := partMap["text"].(string)
					partTexts = append(partTexts, text)
					// --- MODIFICATION START ---
					// Accept both "input_image" (standard) and "image_url" (potentially from older clients/mistakes)
				} else if partType == "input_image" || partType == "image_url" {
					if partType == "image_url" { // Log if the non-standard type is used
						log.Printf("Warning: Received non-standard image part type 'image_url', processing anyway. Standard is 'input_image'.")
					}

					// Robustly extract image URL (string or object)
					var imageUrl string
					imageUrlAny, urlExists := partMap["image_url"]
					if !urlExists {
						log.Printf("Warning: Skipping '%s' part with missing 'image_url' field for role %s", partType, msg.Role)
						continue
					}

					// Check if image_url is a string
					if urlStr, ok := imageUrlAny.(string); ok {
						imageUrl = urlStr
						// Check if image_url is a map (object) like { "url": "...", "detail": "..." }
					} else if urlMap, ok := imageUrlAny.(map[string]any); ok {
						imageUrl, _ = urlMap["url"].(string)
						detail, _ := urlMap["detail"].(string) // Optional: Read detail
						if detail != "" {
							log.Printf("Image detail level specified: %s (currently not used by Grok upload)", detail)
						}
					} else {
						log.Printf("Warning: Skipping '%s' part with unexpected 'image_url' type (%T) for role %s", partType, imageUrlAny, msg.Role)
						continue
					}
					// --- END MODIFICATION (URL extraction) ---

					if imageUrl == "" {
						log.Printf("Warning: Skipping image part with empty or invalid image_url content for role %s", msg.Role)
						continue
					}

					// Fetch image data
					imageData, mimeType, err := getImageDataFromURL(imageUrl)
					if err != nil {
						log.Printf("Error processing image URL for role %s (%s): %v. Skipping image.", msg.Role, imageUrl, err)
						continue // Skip this image
					}

					// Generate filename and upload
					fileName := uuid.New().String() + "." + guessExtension(mimeType)
					uploadResp, err := grokClient.uploadGrokFile(imageData, mimeType, fileName)
					if err != nil {
						log.Printf("Error uploading image file %s (%s) for role %s: %v. Skipping image.", fileName, mimeType, msg.Role, err)
						continue // Skip this image
					}
					imageFileIDs = append(imageFileIDs, uploadResp.FileMetadataId)
					// --- MODIFICATION END (Type check) ---
				} else {
					log.Printf("Warning: Skipping unsupported message part type '%s' for role %s", partType, msg.Role)
				}
			}
			// Combine collected text parts for this message
			combinedPartText := strings.Join(partTexts, "\n")
			textParts = append(textParts, combinedPartText)
			if isThisTheLastUserMsg {
				finalUserContentForSearch = combinedPartText // Store combined text for search check
			}

		} else {
			// Handle unexpected content types (e.g., log, error, or try to serialize)
			log.Printf("Warning: Unsupported message content type for role %s: %T. Attempting to serialize.", msg.Role, msg.Content)
			contentBytes, err := json.Marshal(msg.Content)
			if err == nil {
				textParts = append(textParts, string(contentBytes))
			} else {
				textParts = append(textParts, fmt.Sprintf("[Unsupported Content: %v]", err))
			}
		}
	}

	// --- Keyword Detection & Message Modification (after processing all messages) ---
	// Only check keywords if no images were uploaded, as search might not work with images.
	if len(imageFileIDs) == 0 && finalUserContentForSearch != "" {
		modifiedContent := finalUserContentForSearch
		if deeperSearchRegex.MatchString(finalUserContentForSearch) {
			searchType = "deeper"
			modifiedContent = deeperSearchRegex.ReplaceAllString(finalUserContentForSearch, "")
			modifiedContent = strings.Join(strings.Fields(modifiedContent), " ") // Clean spaces
			log.Println("Detected 'deepersearch' keyword in last user message. Modifying message and enabling DeeperSearch mode.")
		} else if deepSearchRegex.MatchString(finalUserContentForSearch) {
			searchType = "default"
			modifiedContent = deepSearchRegex.ReplaceAllString(finalUserContentForSearch, "")
			modifiedContent = strings.Join(strings.Fields(modifiedContent), " ") // Clean spaces
			log.Println("Detected 'deepsearch' keyword in last user message. Modifying message and enabling DeepSearch mode.")
		}

		// If content was modified, update the last user text part in the textParts slice
		if searchType != "none" {
			// Find the last user message text block and replace it
			// Iterate backwards through textParts to find the content associated with the last [[user]] role marker
			foundAndModified := false
			for i := len(textParts) - 1; i > 0; i-- { // Stop at index 1 (need i-1)
				// Check if the previous part was the user role marker
				if textParts[i-1] == fmt.Sprintf("\n[[%s]]\n", "user") {
					// Check if the current part matches the original content
					if textParts[i] == finalUserContentForSearch {
						textParts[i] = modifiedContent // Replace the content part
						foundAndModified = true
						break
					} else {
						// If the content doesn't match exactly (e.g., multi-part text already joined),
						// we might have trouble replacing. Log a warning.
						// This scenario is less likely now that we join parts first.
						log.Printf("Warning: Could not find exact last user message content block to modify for search keyword removal. Proceeding with original text structure but search mode enabled.")
						break // Stop searching
					}
				}
			}
			if !foundAndModified {
				log.Printf("Warning: Could not find '[[user]]' marker preceding the last user message content for search keyword modification.")
				// Reset searchType if modification failed? Or proceed?
				// searchType = "none" // Option: Disable search if modification fails
			}
		}
	} else if len(imageFileIDs) > 0 {
		log.Printf("Image attachments detected (%d). Skipping DeepSearch keyword check.", len(imageFileIDs))
	}

	// --- Construct Final Message String ---
	var messageBuilder strings.Builder
	fmt.Fprintln(&messageBuilder, beforePrompt)
	messageBuilder.WriteString(strings.Join(textParts, "")) // Join processed parts
	fmt.Fprintf(&messageBuilder, "\n%s", afterPrompt)
	constructedMessage := messageBuilder.String()

	// --- Send to Grok ---
	// Note: sendMessage now handles uploading *long text* if needed and configured.
	// Images were already uploaded above.
	resp, err := grokClient.sendMessage(constructedMessage, imageFileIDs, searchType)
	if err != nil {
		// Check if the error is potentially related to invalid cookies
		if strings.Contains(err.Error(), "Status Code: 401") || strings.Contains(err.Error(), "Unauthorized") {
			http.Error(w, logPrintf("Error sending request to Grok API (potentially invalid cookie): %v", err), http.StatusUnauthorized) // Send 401 back
		} else {
			http.Error(w, logPrintf("Error sending request to Grok API: %v", err), http.StatusInternalServerError)
		}
		return
	}
	defer resp.Body.Close()

	respBody, err := decompressBody(resp)
	if err != nil {
		http.Error(w, logPrintf("Error decompressing Grok API response: %v", err), http.StatusInternalServerError)
		return
	}
	defer respBody.Close()

	isSearchMode := searchType != "none"
	if body.Stream {
		grokClient.createOpenAIStreamingResponse(respBody, isSearchMode)(w, r)
	} else {
		grokClient.createOpenAIFullResponse(respBody, isSearchMode)(w, r)
	}
	_, _ = io.Copy(io.Discard, respBody) // Ensure body is fully read/closed
}

// listModels handles GET requests to /v1/models.
func listModels(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request from %s for %s", r.RemoteAddr, listModelsPath)

	if r.Method != http.MethodGet {
		http.Error(w, logPrintf("Method %s Not Allowed", r.Method), http.StatusMethodNotAllowed)
		return
	}

	list := ModelList{
		Object: "list",
		Data: []ModelData{
			{Id: grok3ModelName, Object: "model", Owned_by: "xAI"},
			{Id: grok3ReasoningModelName, Object: "model", Owned_by: "xAI"},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(list); err != nil {
		http.Error(w, logPrintf("Encoding response error: %v", err), http.StatusInternalServerError)
	}
}

// main parses flags, loads config, sets up proxy, and starts the server.
func main() {
	// --- Flag Definitions ---
	apiToken = flag.String("token", "", "Authentication token (env: GROK3_AUTH_TOKEN)")
	cookie := flag.String("cookie", "", "Grok cookie(s) as JSON string or single string (env: GROK3_COOKIE)")
	cookieFile := flag.String("cookieFile", "", "A text file which contains Grok cookies line by line")
	textBeforePrompt = flag.String("textBeforePrompt", defaultBeforePromptText, "Default text before the prompt (overridable in request)")
	textAfterPrompt = flag.String("textAfterPrompt", "", "Default text after the prompt (overridable in request)")
	keepChat = flag.Bool("keepChat", false, "Default setting to retain chat conversations (overridable in request)")
	ignoreThinking = flag.Bool("ignoreThinking", false, "Default setting to ignore thinking tokens (overridable in request)")
	charsLimit = flag.Uint("charsLimit", messageCharsLimit, "Default character limit to trigger *text* message upload (overridable in request via uploadMessage)")
	httpProxy = flag.String("httpProxy", "", "HTTP/SOCKS5 proxy URL (env: http_proxy, https_proxy, HTTP_PROXY, HTTPS_PROXY)")
	imgurClientID = flag.String("imgurClientID", "", "Imgur Client ID for uploading generated images (env: IMGUR_CLIENT_ID)") // Added Imgur flag
	port := flag.Uint("port", 8180, "Server port")
	flag.Parse()

	// --- Port Validation ---
	if *port > 65535 {
		log.Fatalf("Server port %d is invalid (must be 0-65535)", *port)
	}

	// --- Token Configuration ---
	*apiToken = strings.TrimSpace(*apiToken)
	if *apiToken == "" {
		*apiToken = strings.TrimSpace(os.Getenv("GROK3_AUTH_TOKEN"))
	}
	if *apiToken == "" {
		log.Fatal("Authentication token is required. Set via -token flag or GROK3_AUTH_TOKEN environment variable.")
	}
	log.Println("API Authentication token configured.") // Don't log the token itself

	// --- Imgur Client ID Configuration ---
	*imgurClientID = strings.TrimSpace(*imgurClientID)
	if *imgurClientID == "" {
		*imgurClientID = strings.TrimSpace(os.Getenv("IMGUR_CLIENT_ID"))
	}
	if *imgurClientID == "" {
		log.Println("Warning: Imgur Client ID is not set. Image generation responses will not be uploaded to Imgur. Set via -imgurClientID flag or IMGUR_CLIENT_ID environment variable.")
	} else {
		log.Println("Imgur Client ID configured. Generated images will be uploaded.")
	}

	// --- Cookie Loading ---
	loadedCookies := []string{}
	// 1. From -cookie flag or GROK3_COOKIE env var
	cookieStr := strings.TrimSpace(*cookie)
	if cookieStr == "" {
		cookieStr = strings.TrimSpace(os.Getenv("GROK3_COOKIE"))
	}
	if cookieStr != "" {
		var parsedCookies []string
		err := json.Unmarshal([]byte(cookieStr), &parsedCookies)
		if err == nil {
			loadedCookies = append(loadedCookies, parsedCookies...)
			log.Printf("Loaded %d cookie(s) from -cookie flag / GROK3_COOKIE env var (parsed as JSON).", len(parsedCookies))
		} else {
			loadedCookies = append(loadedCookies, cookieStr) // Treat as single string
			log.Println("Loaded 1 cookie from -cookie flag / GROK3_COOKIE env var (treated as single string).")
		}
	}
	// 2. From -cookieFile flag
	if *cookieFile != "" {
		file, err := os.Open(*cookieFile)
		if err != nil {
			log.Printf("Warning: Could not open cookie file %s: %v. Continuing without it.", *cookieFile, err)
		} else {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			linesRead := 0
			cookiesFromFile := 0
			for scanner.Scan() {
				linesRead++
				c := strings.TrimSpace(scanner.Text())
				if c != "" && !strings.HasPrefix(c, "#") {
					loadedCookies = append(loadedCookies, c)
					cookiesFromFile++
				}
			}
			if err = scanner.Err(); err != nil {
				log.Printf("Warning: Error reading cookie file %s: %v. Cookies read so far will be used.", *cookieFile, err)
			}
			log.Printf("Read %d lines and loaded %d cookies from %s", linesRead, cookiesFromFile, *cookieFile)
		}
	}
	// 3. Deduplicate and store globally
	seen := make(map[string]struct{})
	uniqueCookies := make([]string, 0, len(loadedCookies))
	for _, c := range loadedCookies {
		trimmed := strings.TrimSpace(c)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; !exists {
			seen[trimmed] = struct{}{}
			uniqueCookies = append(uniqueCookies, trimmed)
		}
	}
	grokCookies = uniqueCookies // Assign to global variable
	if len(grokCookies) == 0 {
		log.Println("Warning: No global Grok cookies loaded. Cookies must be provided in each request via 'grokCookies'.")
	} else {
		log.Printf("Initialized with %d unique global Grok cookie(s).", len(grokCookies))
	}

	// --- Proxy Configuration ---
	proxyURLStr := strings.TrimSpace(*httpProxy)
	if proxyURLStr == "" {
		proxyURLStr = strings.TrimSpace(os.Getenv("https_proxy")) // Prefer HTTPS proxy
	}
	if proxyURLStr == "" {
		proxyURLStr = strings.TrimSpace(os.Getenv("HTTPS_PROXY"))
	}
	if proxyURLStr == "" {
		proxyURLStr = strings.TrimSpace(os.Getenv("http_proxy")) // Fallback to HTTP proxy
	}
	if proxyURLStr == "" {
		proxyURLStr = strings.TrimSpace(os.Getenv("HTTP_PROXY"))
	}

	// Configure HTTP client transport (default or with proxy)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 10 // Increased from default
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = 1 * time.Second
	transport.ForceAttemptHTTP2 = true
	transport.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second, // Connection timeout
		KeepAlive: 30 * time.Second,
	}).DialContext

	if proxyURLStr != "" {
		proxyURL, err := url.Parse(proxyURLStr)
		if err == nil {
			log.Printf("Using proxy: %s", proxyURL.Host) // Log host, not full URL with potential creds
			transport.Proxy = http.ProxyURL(proxyURL)
		} else {
			log.Fatalf("Error parsing proxy URL '%s': %v", proxyURLStr, err) // Fatal error if proxy is invalid
		}
	} else {
		log.Println("No proxy configured.")
	}
	httpClient.Transport = transport // Assign configured transport to global client

	// --- HTTP Server Setup ---
	http.HandleFunc(completionsPath, handleChatCompletion)
	http.HandleFunc(listModelsPath, listModels)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "Grok 3 API Wrapper (OpenAI Compatible) is running.\nEndpoints:\n  %s (POST)\n  %s (GET)\n", completionsPath, listModelsPath)
	})

	addr := fmt.Sprintf(":%d", *port)
	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 30 * time.Minute, // Long timeout for streaming
		IdleTimeout:  2 * time.Minute,  // Increased idle timeout
	}

	log.Printf("Server starting on port %d...", *port)
	log.Printf("OpenAI-compatible endpoints available at http://localhost:%d/v1", *port)
	log.Printf("See README.md for usage details and image input format.")
	if *imgurClientID != "" {
		log.Printf("Imgur uploads enabled. Ensure your Client ID (%s...) is valid.", (*imgurClientID)[:min(len(*imgurClientID), 4)])
	} else {
		log.Printf("Imgur uploads disabled (no Client ID provided).")
	}

	// --- Start Server ---
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// min function for integer comparison.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
