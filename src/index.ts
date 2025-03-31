#!/usr/bin/env node

import { hideBin } from 'yargs/helpers'
import yargs from 'yargs'
import express, { Request, Response } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import path from 'path'
import { Redis } from '@upstash/redis'

// --------------------------------------------------------------------
// Configuration & Storage Interface
// --------------------------------------------------------------------
interface Config {
  port: number;
  transport: 'sse' | 'stdio';
  // Storage modes: "memory-single", "memory", or "upstash-redis-rest"
  storage: 'memory-single' | 'memory' | 'upstash-redis-rest';
  linkedinClientId: string;
  linkedinClientSecret: string;
  linkedinRedirectUri: string;
  // For storage "memory" and "upstash-redis-rest": the header name (or key prefix) to use.
  storageHeaderKey?: string;
  // Upstash-specific options (if storage is "upstash-redis-rest")
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
  private storage: Record<string, { accessToken: string; userId: string }> = {};

  async get(memoryKey: string) {
    return this.storage[memoryKey];
  }

  async set(memoryKey: string, accessToken: string, linkedinUserId: string) {
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
    const data = await this.redis.get<{ accessToken: string; userId: string }>(`${this.keyPrefix}:${memoryKey}`);
    return data === null ? undefined : data;
  }

  async set(memoryKey: string, accessToken: string, linkedinUserId: string): Promise<void> {
    const obj = { accessToken, userId: linkedinUserId };
    await this.redis.set(`${this.keyPrefix}:${memoryKey}`, JSON.stringify(obj));
  }
}

// --------------------------------------------------------------------
// LinkedIn OAuth Helper Functions (using config)
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

async function createLinkedinPostTool(args: { postContent: string; memoryKey: string; storage: ILinkedInAuthStorage }): Promise<any> {
  const { postContent, memoryKey, storage } = args;
  const creds = await storage.get(memoryKey);
  if (!creds) {
    throw new Error(`No LinkedIn authentication configured for key "${memoryKey}". Run linkedin_exchange_auth_code first.`);
  }
  const postData = {
    author: `urn:li:person:${creds.userId}`,
    lifecycleState: "PUBLISHED",
    specificContent: {
      "com.linkedin.ugc.ShareContent": {
        shareCommentary: { text: postContent },
        shareMediaCategory: "NONE"
      }
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
// Helper: JSON response formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

// --------------------------------------------------------------------
// Create a LinkedIn MCP server
// This function creates the storage instance internally based on the config
// and returns an MCP server that uses the provided memoryKey.
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
    'Return an OAuth URL for LinkedIn (visit this URL to grant access with openid, profile, and w_member_social scopes).',
    {},
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
    'Set up LinkedIn authentication by exchanging an auth code.',
    { code: z.string() },
    async (args) => {
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
    'Create a new post on LinkedIn on behalf of the authenticated member. Provide postContent as text.',
    { postContent: z.string() },
    async (args) => {
      try {
        const result = await createLinkedinPostTool({ postContent: args.postContent, memoryKey, storage });
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  return server;
}

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
// Main: Start the server
// --------------------------------------------------------------------
async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
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
    .help()
    .parseSync();

  const config: Config = {
    port: argv.port,
    transport: argv.transport as 'sse' | 'stdio',
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

  // Validate Upstash Redis options immediately if using upstash-redis-rest.
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

  if (config.transport === 'stdio') {
    // For stdio, always run in memory-single mode.
    const memoryKey = "single";
    const server = createLinkedinServer(memoryKey, config);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    log('Listening on stdio');
    return;
  }

  // For SSE transport:
  const app = express();

  interface ServerSession {
    memoryKey: string;
    server: McpServer;
    transport: SSEServerTransport;
    sessionId: string;
  }
  let sessions: ServerSession[] = [];

  // Parse JSON on all routes except /message.
  app.use((req, res, next) => {
    if (req.path === '/message') return next();
    express.json()(req, res, next);
  });

  app.get('/', async (req: Request, res: Response) => {
    let memoryKey: string;
    if (config.storage === 'memory-single') {
      memoryKey = "single";
    } else {
      // In "memory" or "upstash-redis-rest", use the header named by storageHeaderKey.
      const headerVal = req.headers[config.storageHeaderKey!.toLowerCase()];
      if (typeof headerVal !== 'string' || !headerVal.trim()) {
        res.status(400).json({ error: `Missing or invalid "${config.storageHeaderKey}" header` });
        return;
      }
      memoryKey = headerVal.trim();
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

  app.post('/message', async (req: Request, res: Response) => {
    const sessionId = req.query.sessionId as string;
    if (!sessionId) {
      res.status(400).send({ error: 'Missing sessionId' });
      return;
    }
    const target = sessions.find(s => s.sessionId === sessionId);
    if (!target) {
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
    log(`Listening on port ${config.port} [storage=${config.storage}]`);
  });
}

main().catch(err => {
  logErr('Fatal error:', err);
  process.exit(1);
});
