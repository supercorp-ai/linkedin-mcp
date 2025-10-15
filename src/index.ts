#!/usr/bin/env node

import { hideBin } from 'yargs/helpers'
import yargs from 'yargs'
import express, { Request, Response } from 'express'
import cors from 'cors'
import type { CorsOptionsDelegate } from 'cors'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { InMemoryEventStore } from '@modelcontextprotocol/sdk/examples/shared/inMemoryEventStore.js'
import { z } from 'zod'
import { Redis } from '@upstash/redis'
import { randomUUID } from 'node:crypto'

// --------------------------------------------------------------------
// Logging Helpers
// --------------------------------------------------------------------
function log(...args: any[]) {
  console.log('[linkedin-mcp]', ...args);
}

function logErr(...args: any[]) {
  console.error('[linkedin-mcp]', ...args);
}

// --------------------------------------------------------------------
// Helper: JSON Response Formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}

// --------------------------------------------------------------------
// Configuration & Storage Interface
// --------------------------------------------------------------------
interface Config {
  port: number;
  transport: 'sse' | 'stdio' | 'http';
  httpMode: 'stateful' | 'stateless';
  storage: 'memory-single' | 'memory' | 'upstash-redis-rest';
  linkedinClientId: string;
  linkedinClientSecret: string;
  linkedinRedirectUri: string;
  storageHeaderKey?: string;
  upstashRedisRestUrl?: string;
  upstashRedisRestToken?: string;
}

interface ILinkedInAuthStorage {
  get(memoryKey: string): Promise<{ accessToken: string; userId: string } | undefined>;
  set(memoryKey: string, accessToken: string, linkedinUserId: string): Promise<void>;
}

// --------------------------------------------------------------------
// In-Memory Storage Implementation
// --------------------------------------------------------------------
class MemoryLinkedInAuthStorage implements ILinkedInAuthStorage {
  private storage: Record<string, { accessToken?: string; userId?: string }> = {};

  async get(memoryKey: string): Promise<{ accessToken: string; userId: string } | undefined> {
    const data = this.storage[memoryKey];
    if (data && data.accessToken && data.userId) {
      return { accessToken: data.accessToken, userId: data.userId };
    }
    return undefined;
  }

  async set(memoryKey: string, accessToken: string, linkedinUserId: string): Promise<void> {
    this.storage[memoryKey] = { accessToken, userId: linkedinUserId };
  }
}

// --------------------------------------------------------------------
// Upstash Redis Storage Implementation
// --------------------------------------------------------------------
class RedisLinkedInAuthStorage implements ILinkedInAuthStorage {
  private redis: Redis;
  private keyPrefix: string;

  constructor(redisUrl: string, redisToken: string, keyPrefix: string) {
    this.redis = new Redis({ url: redisUrl, token: redisToken });
    this.keyPrefix = keyPrefix;
  }

  async get(memoryKey: string): Promise<{ accessToken: string; userId: string } | undefined> {
    const data = await this.redis.get<{ accessToken?: string; userId?: string }>(`${this.keyPrefix}:${memoryKey}`);
    if (data && (data as any).accessToken && (data as any).userId) {
      const obj = data as any;
      return { accessToken: obj.accessToken, userId: obj.userId };
    }
    return undefined;
  }

  async set(memoryKey: string, accessToken: string, linkedinUserId: string): Promise<void> {
    const obj = { accessToken, userId: linkedinUserId };
    await this.redis.set(`${this.keyPrefix}:${memoryKey}`, JSON.stringify(obj));
  }
}

// --------------------------------------------------------------------
// LinkedIn OAuth Helper Functions
// --------------------------------------------------------------------
function generateLinkedinAuthUrl(config: Config): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.linkedinClientId,
    redirect_uri: config.linkedinRedirectUri,
    scope: 'openid profile w_member_social'
  });
  return `https://www.linkedin.com/oauth/v2/authorization?${params.toString()}`;
}

async function exchangeLinkedinAuthCode(code: string, config: Config): Promise<string> {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code.trim(),
    client_id: config.linkedinClientId,
    client_secret: config.linkedinClientSecret,
    redirect_uri: config.linkedinRedirectUri
  });
  const response = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  });
  const data = await response.json();
  if (!data.access_token) {
    throw new Error('Failed to obtain LinkedIn access token.');
  }
  return data.access_token;
}

async function fetchLinkedinUser(accessToken: string): Promise<any> {
  const response = await fetch('https://api.linkedin.com/v2/userinfo', {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
  const data = await response.json();
  if (!data.sub) throw new Error('Failed to fetch LinkedIn user id.');
  return data;
}

async function authLinkedin(args: { code: string; memoryKey: string; config: Config; storage: ILinkedInAuthStorage }): Promise<any> {
  const { code, memoryKey, config, storage } = args;
  const accessToken = await exchangeLinkedinAuthCode(code, config);
  const userInfo = await fetchLinkedinUser(accessToken);
  await storage.set(memoryKey, accessToken, userInfo.sub);
  return { success: true, provider: "linkedin", user: userInfo };
}

// --------------------------------------------------------------------
// LinkedIn Image Upload Helper
// --------------------------------------------------------------------
/**
 * Uploads an image to LinkedIn via the Assets API.
 * Downloads the image from mediaUrl, registers the upload, uploads the binary file, and returns the asset URN.
 */
async function uploadLinkedinImage(mediaUrl: string, accessToken: string, ownerUrn: string): Promise<string> {
  log("Downloading image for LinkedIn upload:", mediaUrl);
  const mediaResponse = await fetch(mediaUrl);
  if (!mediaResponse.ok) {
    const errText = await mediaResponse.text();
    logErr("Error downloading image:", errText);
    throw new Error("Failed to download image for LinkedIn post.");
  }

  // Use ArrayBuffer/Uint8Array to satisfy Node 24 typings (Buffer is not BodyInit in TS)
  const mediaArrayBuffer = await mediaResponse.arrayBuffer();
  const imageBytes = new Uint8Array(mediaArrayBuffer);

  // Register upload
  const registerUrl = "https://api.linkedin.com/v2/assets?action=registerUpload";
  const registerBody = {
    registerUploadRequest: {
      recipes: ["urn:li:digitalmediaRecipe:feedshare-image"],
      owner: ownerUrn,
      serviceRelationships: [
        { relationshipType: "OWNER", identifier: "urn:li:userGeneratedContent" }
      ]
    }
  };
  log("Registering image upload with body:", JSON.stringify(registerBody));
  const registerResponse = await fetch(registerUrl, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      "X-Restli-Protocol-Version": "2.0.0"
    },
    body: JSON.stringify(registerBody)
  });
  if (!registerResponse.ok) {
    const errorText = await registerResponse.text();
    logErr("Error in image register upload:", errorText);
    throw new Error(`Image register upload failed: ${errorText}`);
  }
  const registerData = await registerResponse.json();
  const uploadUrl = registerData.value.uploadMechanism["com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest"].uploadUrl;
  const asset = registerData.value.asset;
  log("Image upload registered. Upload URL:", uploadUrl, "Asset:", asset);

  // Upload the image binary using PUT (Uint8Array is accepted BodyInit)
  const putResponse = await fetch(uploadUrl, {
    method: "PUT",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/octet-stream"
    },
    body: imageBytes
  });
  if (!putResponse.ok) {
    const putError = await putResponse.text();
    logErr("Error uploading image:", putError);
    throw new Error(`Image upload failed: ${putError}`);
  }
  log("Image upload successful. Asset URN:", asset);
  return asset;
}

// --------------------------------------------------------------------
// LinkedIn Post Creation Tool (with optional image or article share)
// --------------------------------------------------------------------
interface LinkedInPostArgs {
  postContent: string;
  mediaType?: "none" | "image" | "article";
  mediaUrl?: string;
  articleUrl?: string;
  title?: string;
  description?: string;
  memoryKey: string;
  config: Config;
  storage: ILinkedInAuthStorage;
}

async function createLinkedinPostTool(args: LinkedInPostArgs): Promise<any> {
  const { postContent, mediaType = "none", mediaUrl, articleUrl, title, description, memoryKey, config, storage } = args;
  const creds = await storage.get(memoryKey);
  if (!creds) {
    throw new Error(`No LinkedIn authentication configured for key "${memoryKey}". Run linkedin_exchange_auth_code first.`);
  }
  const author = `urn:li:person:${creds.userId}`;
  let shareContent: any = {
    shareCommentary: { text: postContent },
    shareMediaCategory: "NONE"
  };
  if (mediaType === "image" && mediaUrl) {
    const assetUrn = await uploadLinkedinImage(mediaUrl, creds.accessToken, author);
    shareContent = {
      shareCommentary: { text: postContent },
      shareMediaCategory: "IMAGE",
      media: [
        {
          status: "READY",
          description: { text: description || "Image share" },
          media: assetUrn,
          title: { text: title || "Image" }
        }
      ]
    };
  } else if (mediaType === "article" && articleUrl) {
    // For articles, LinkedIn will automatically extract metadata from the URL.
    shareContent = {
      shareCommentary: { text: postContent },
      shareMediaCategory: "ARTICLE",
      media: [
        {
          status: "READY",
          originalUrl: articleUrl
        }
      ]
    };
  }
  const postData = {
    author,
    lifecycleState: "PUBLISHED",
    specificContent: {
      "com.linkedin.ugc.ShareContent": shareContent
    },
    visibility: {
      "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
    }
  };
  const response = await fetch('https://api.linkedin.com/v2/ugcPosts', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${creds.accessToken}`,
      'Content-Type': 'application/json',
      'X-Restli-Protocol-Version': '2.0.0'
    },
    body: JSON.stringify(postData)
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`LinkedIn post creation failed: ${errorText}`);
  }
  return { success: true, message: 'Post created successfully.' };
}

// --------------------------------------------------------------------
// MCP Server Creation: Register LinkedIn Tools
// --------------------------------------------------------------------
function createLinkedinServer(memoryKey: string, config: Config): McpServer {
  let storage: ILinkedInAuthStorage;
  if (config.storage === 'upstash-redis-rest') {
    storage = new RedisLinkedInAuthStorage(
      config.upstashRedisRestUrl!,
      config.upstashRedisRestToken!,
      config.storageHeaderKey!
    );
  } else {
    storage = new MemoryLinkedInAuthStorage();
  }
  const server = new McpServer({
    name: `LinkedIn MCP Server (Memory Key: ${memoryKey})`,
    version: '1.0.0'
  });

  server.tool(
    'linkedin_auth_url',
    'Return an OAuth URL for LinkedIn login. (Grants openid, profile, and w_member_social scopes.)',
    {
      // TODO: MCP SDK bug patch - remove when fixed
      comment: z.string().optional(),
    },
    async () => {
      try {
        const authUrl = generateLinkedinAuthUrl(config);
        return toTextJson({ authUrl });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'linkedin_exchange_auth_code',
    'Exchange an auth code for a LinkedIn access token and set up authentication.',
    { code: z.string().describe("Authorization code obtained from LinkedIn OAuth flow") },
    async (args: { code: string }) => {
      try {
        const result = await authLinkedin({ code: args.code, memoryKey, config, storage });
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'linkedin_create_post',
    'Create a new LinkedIn post.\nArguments:\n  - postContent: The text content of the post.\n  - mediaType (optional): "none", "image", or "article". Use "image" to upload an image or "article" to share a URL.\n  - mediaUrl (optional): URL of the image to upload (required if mediaType is "image").\n  - articleUrl (optional): URL of the article to share (required if mediaType is "article").\n  - title (optional): Title for the media share (only used if mediaType is "image").\n  - description (optional): A short description for the media share (only used if mediaType is "image").',
    {
      postContent: z.string().describe("The text content of the post"),
      mediaType: z.enum(["none", "image", "article"]).optional().describe("Specifies the type of media attached: 'image' for image upload, 'article' for URL share, 'none' for text only"),
      mediaUrl: z.string().optional().describe("The URL of the image to upload (required if mediaType is 'image')"),
      articleUrl: z.string().optional().describe("The URL of the article to share (required if mediaType is 'article')"),
      title: z.string().optional().describe("Title for the image share"),
      description: z.string().optional().describe("A short description for the image share")
    },
    async (args: { postContent: string; mediaType?: "none" | "image" | "article"; mediaUrl?: string; articleUrl?: string; title?: string; description?: string }) => {
      try {
        const result = await createLinkedinPostTool({ ...args, memoryKey, config, storage });
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  return server;
}

// --------------------------------------------------------------------
// Main: Start the Server (HTTP / SSE / stdio)
// --------------------------------------------------------------------
async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio', 'http'], default: 'sse' })
    .option('httpMode', {
      type: 'string',
      choices: ['stateful', 'stateless'] as const,
      default: 'stateful',
      describe:
        'Choose HTTP session mode when --transport=http. "stateful" uses MCP session IDs; "stateless" treats each request separately.'
    })
    .option('storage', {
      type: 'string',
      choices: ['memory-single', 'memory', 'upstash-redis-rest'],
      default: 'memory-single',
      describe:
        'Choose storage backend: "memory-single" uses fixed single-user storage; "memory" uses multi-user in-memory storage (requires --storageHeaderKey); "upstash-redis-rest" uses Upstash Redis (requires --storageHeaderKey, --upstashRedisRestUrl, and --upstashRedisRestToken).'
    })
    .option('linkedinClientId', { type: 'string', demandOption: true, describe: "LinkedIn Client ID" })
    .option('linkedinClientSecret', { type: 'string', demandOption: true, describe: "LinkedIn Client Secret" })
    .option('linkedinRedirectUri', { type: 'string', demandOption: true, describe: "LinkedIn Redirect URI" })
    .option('storageHeaderKey', { type: 'string', describe: 'For storage "memory" or "upstash-redis-rest": the header name (or key prefix) to use.' })
    .option('upstashRedisRestUrl', { type: 'string', describe: 'Upstash Redis REST URL (if --storage=upstash-redis-rest)' })
    .option('upstashRedisRestToken', { type: 'string', describe: 'Upstash Redis REST token (if --storage=upstash-redis-rest)' })
    .option('toolsPrefix', { type: 'string', default: 'linkedin_', describe: 'Prefix to add to all tool names.' })
    .help()
    .parseSync();

  const config: Config = {
    port: argv.port,
    transport: argv.transport as 'sse' | 'stdio' | 'http',
    httpMode: argv.httpMode as 'stateful' | 'stateless',
    storage: argv.storage as 'memory-single' | 'memory' | 'upstash-redis-rest',
    linkedinClientId: argv.linkedinClientId,
    linkedinClientSecret: argv.linkedinClientSecret,
    linkedinRedirectUri: argv.linkedinRedirectUri,
    storageHeaderKey:
      (argv.storage === 'memory-single')
        ? undefined
        : (argv.storageHeaderKey && argv.storageHeaderKey.trim()
          ? argv.storageHeaderKey.trim()
          : (() => { logErr('Error: --storageHeaderKey is required for storage modes "memory" or "upstash-redis-rest".'); process.exit(1); return ''; })()),
    upstashRedisRestUrl: argv.upstashRedisRestUrl,
    upstashRedisRestToken: argv.upstashRedisRestToken,
  };

  if (config.storage === 'upstash-redis-rest') {
    if (!config.upstashRedisRestUrl || !config.upstashRedisRestUrl.trim()) {
      logErr("Error: --upstashRedisRestUrl is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
    if (!config.upstashRedisRestToken || !config.upstashRedisRestToken.trim()) {
      logErr("Error: --upstashRedisRestToken is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
  }

  const storageHeaderKeyLower = config.storageHeaderKey?.toLowerCase();
  const storageHeaderLabel = config.storageHeaderKey ?? 'memory-key';
  const corsBaseHeaders = [
    'Content-Type',
    'Accept',
    'Mcp-Session-Id',
    'mcp-session-id',
    config.storageHeaderKey,
    storageHeaderKeyLower
  ].filter((header): header is string => typeof header === 'string' && header.length > 0);

  const corsOptionsDelegate: CorsOptionsDelegate<Request> = (req, callback) => {
    const headers = new Set<string>(corsBaseHeaders);
    const requestHeaders = req.header('Access-Control-Request-Headers');
    if (requestHeaders) {
      for (const header of requestHeaders.split(',')) {
        const trimmed = header.trim();
        if (trimmed) headers.add(trimmed);
      }
    }
    callback(null, {
      origin: true,
      allowedHeaders: Array.from(headers),
      exposedHeaders: ['Mcp-Session-Id']
    });
  };

  const corsMiddleware = cors(corsOptionsDelegate);

  const resolveMemoryKeyFromHeaders = (headers: Request['headers']): string | undefined => {
    if (config.storage === 'memory-single') {
      return 'single';
    }
    if (!storageHeaderKeyLower) return undefined;
    const raw = headers[storageHeaderKeyLower];
    if (typeof raw === 'string') {
      const trimmed = raw.trim();
      return trimmed.length > 0 ? trimmed : undefined;
    }
    if (Array.isArray(raw)) {
      for (const value of raw) {
        if (typeof value === 'string') {
          const trimmed = value.trim();
          if (trimmed.length > 0) {
            return trimmed;
          }
        }
      }
    }
    return undefined;
  };

  // stdio
  if (config.transport === 'stdio') {
    const memoryKey = "single";
    const server = createLinkedinServer(memoryKey, config);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    log('Listening on stdio');
    return;
  }

  // Streamable HTTP (root "/")
  if (config.transport === 'http') {
    const port = config.port;
    const app = express();
    const isStatefulHttp = config.httpMode === 'stateful';

    app.use(corsMiddleware);
    app.options('*', corsMiddleware);

    const createServerFor = (memoryKey: string) => createLinkedinServer(memoryKey, config);

    if (isStatefulHttp) {
      // Do not JSON-parse "/" — the transport needs the raw body/stream.
      app.use((req, res, next) => {
        if (req.path === '/') return next();
        return express.json()(req, res, next);
      });

      interface HttpSession {
        memoryKey: string;
        server: McpServer;
        transport: StreamableHTTPServerTransport;
      }
      const sessions = new Map<string, HttpSession>();
      const eventStore = new InMemoryEventStore();

      app.post('/', async (req: Request, res: Response) => {
        try {
          const sessionId = req.headers['mcp-session-id'] as string | undefined;
          if (sessionId && sessions.has(sessionId)) {
            const { transport } = sessions.get(sessionId)!;
            await transport.handleRequest(req, res);
            return;
          }

          const memoryKey = resolveMemoryKeyFromHeaders(req.headers);
          if (!memoryKey) {
            res.status(400).json({
              jsonrpc: '2.0',
              error: {
                code: -32000,
                message: `Bad Request: Missing or invalid "${storageHeaderLabel}" header`
              },
              id: (req as any)?.body?.id
            });
            return;
          }

          const server = createServerFor(memoryKey);

          let transport!: StreamableHTTPServerTransport;
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            eventStore,
            onsessioninitialized: (newSessionId: string) => {
              sessions.set(newSessionId, { memoryKey, server, transport });
              log(`[${newSessionId}] HTTP session initialized for key "${memoryKey}"`);
            }
          });

          transport.onclose = async () => {
            const sid = transport.sessionId;
            if (sid && sessions.has(sid)) {
              sessions.delete(sid);
              log(`[${sid}] Transport closed; removed session`);
            }
            try {
              await server.close();
            } catch {
              // best-effort cleanup; ignore if already closed
            }
          };

          await server.connect(transport);
          await transport.handleRequest(req, res);
        } catch (err) {
          logErr('Error handling HTTP POST /:', err);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal server error' },
              id: (req as any)?.body?.id
            });
          }
        }
      });

      app.get('/', async (req: Request, res: Response) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        if (!sessionId || !sessions.has(sessionId)) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
            id: (req as any)?.body?.id
          });
          return;
        }
        try {
          const { transport } = sessions.get(sessionId)!;
          await transport.handleRequest(req, res);
        } catch (err) {
          logErr(`[${sessionId}] Error handling HTTP GET /:`, err);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal server error' },
              id: (req as any)?.body?.id
            });
          }
        }
      });

      app.delete('/', async (req: Request, res: Response) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        if (!sessionId || !sessions.has(sessionId)) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
            id: (req as any)?.body?.id
          });
          return;
        }
        try {
          const { transport } = sessions.get(sessionId)!;
          await transport.handleRequest(req, res);
        } catch (err) {
          logErr(`[${sessionId}] Error handling HTTP DELETE /:`, err);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Error handling session termination' },
              id: (req as any)?.body?.id
            });
          }
        }
      });
    } else {
      app.use(express.json());

      interface StatelessSession {
        server: McpServer;
        transport: StreamableHTTPServerTransport;
        memoryKey: string;
      }

      const statelessSessions = new Map<string, StatelessSession>();
      const statelessSessionPromises = new Map<string, Promise<StatelessSession>>();

      const destroyStatelessSession = async (memoryKey: string) => {
        const session = statelessSessions.get(memoryKey);
        if (!session) return;
        statelessSessions.delete(memoryKey);
        statelessSessionPromises.delete(memoryKey);
        try {
          await session.transport.close();
        } catch (err) {
          logErr(`[stateless:${memoryKey}] Error closing transport:`, err);
        }
        try {
          await session.server.close();
        } catch (err) {
          logErr(`[stateless:${memoryKey}] Error closing server:`, err);
        }
      };

      const getOrCreateStatelessSession = async (memoryKey: string): Promise<StatelessSession> => {
        const existing = statelessSessions.get(memoryKey);
        if (existing) {
          return existing;
        }

        const pending = statelessSessionPromises.get(memoryKey);
        if (pending) {
          return pending;
        }

        const creation = (async () => {
          const server = createServerFor(memoryKey);
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined
          });
          transport.onerror = error => {
            logErr(`[stateless:${memoryKey}] Streamable HTTP transport error:`, error);
          };
          transport.onclose = async () => {
            statelessSessions.delete(memoryKey);
            statelessSessionPromises.delete(memoryKey);
            try {
              await server.close();
            } catch (err) {
              logErr(`[stateless:${memoryKey}] Error closing server on transport close:`, err);
            }
          };
          await server.connect(transport);
          const session: StatelessSession = { server, transport, memoryKey };
          statelessSessions.set(memoryKey, session);
          return session;
        })()
          .catch(err => {
            statelessSessionPromises.delete(memoryKey);
            throw err;
          })
          .finally(() => {
            statelessSessionPromises.delete(memoryKey);
          });

        statelessSessionPromises.set(memoryKey, creation);
        return creation;
      };

      const handleStatelessRequest = async (
        req: Request,
        res: Response,
        handler: (session: StatelessSession, memoryKey: string) => Promise<void>
      ) => {
        const memoryKey = resolveMemoryKeyFromHeaders(req.headers);
        if (!memoryKey) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: {
              code: -32000,
              message: `Bad Request: Missing or invalid "${storageHeaderLabel}" header`
            },
            id: (req as any)?.body?.id ?? null
          });
          return;
        }

        try {
          const session = await getOrCreateStatelessSession(memoryKey);
          await handler(session, memoryKey);
        } catch (err) {
          logErr('Error handling MCP request (stateless):', err);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal server error' },
              id: (req as any)?.body?.id ?? null
            });
          }
        }
      };

      app.post('/', async (req: Request, res: Response) => {
        await handleStatelessRequest(req, res, async ({ transport }, memoryKey) => {
          res.on('close', () => {
            if (!res.writableEnded) {
              logErr(`[stateless:${memoryKey}] POST connection closed prematurely; destroying session`);
              void destroyStatelessSession(memoryKey);
            }
          });

          await transport.handleRequest(req, res, req.body);
        });
      });

      app.get('/', async (req: Request, res: Response) => {
        await handleStatelessRequest(req, res, async ({ transport }) => {
          await transport.handleRequest(req, res);
        });
      });

      app.delete('/', async (req: Request, res: Response) => {
        await handleStatelessRequest(req, res, async ({ transport }, memoryKey) => {
          try {
            await transport.handleRequest(req, res);
          } finally {
            void destroyStatelessSession(memoryKey);
          }
        });
      });
    }

    app.listen(port, () => {
      log(
        `Listening for Streamable HTTP on port ${port} [storage=${config.storage}, httpMode=${config.httpMode}]`
      );
    });

    return;
  }

  // SSE
  const app = express();
  app.use(corsMiddleware);
  app.options('*', corsMiddleware);
  interface ServerSession {
    memoryKey: string;
    server: McpServer;
    transport: SSEServerTransport;
    sessionId: string;
  }
  let sessions: ServerSession[] = [];

  app.use((req, res, next) => {
    if (req.path === '/message') return next();
    express.json()(req, res, next);
  });

  app.get('/', async (req: Request, res: Response) => {
    const memoryKey = resolveMemoryKeyFromHeaders(req.headers);
    if (!memoryKey) {
      res.status(400).json({ error: `Missing or invalid "${storageHeaderLabel}" header` });
      return;
    }
    const server = createLinkedinServer(memoryKey, config);
    const transport = new SSEServerTransport('/message', res);
    await server.connect(transport);
    const sessionId = transport.sessionId;
    sessions.push({ memoryKey, server, transport, sessionId });
    log(`[${sessionId}] SSE connected for key: "${memoryKey}"`);
    transport.onclose = () => {
      log(`[${sessionId}] SSE connection closed`);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    req.on('close', () => {
      log(`[${sessionId}] Client disconnected`);
      sessions = sessions.filter(s => s.transport !== transport);
    });
  });

  app.post('/message', async (req, res) => {
    const sessionId = req.query.sessionId as string;
    if (!sessionId) {
      logErr('Missing sessionId');
      res.status(400).send({ error: 'Missing sessionId' });
      return;
    }
    const target = sessions.find(s => s.sessionId === sessionId);
    if (!target) {
      logErr(`No active session for sessionId=${sessionId}`);
      res.status(404).send({ error: 'No active session' });
      return;
    }
    try {
      await target.transport.handlePostMessage(req, res);
    } catch (err: any) {
      logErr(`[${sessionId}] Error handling /message:`, err);
      res.status(500).send({ error: 'Internal error' });
    }
  });

  app.listen(config.port, () => {
    log(`Listening on port ${config.port} (sse) [storage=${config.storage}]`);
  });
}

main().catch((err: any) => {
  logErr('Fatal error:', err);
  process.exit(1);
});
