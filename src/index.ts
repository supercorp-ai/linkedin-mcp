#!/usr/bin/env node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import express, { Request, Response } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'

// --------------------------------------------------------------------
// 1) Parse CLI options (including LinkedIn credentials)
// --------------------------------------------------------------------
const argv = yargs(hideBin(process.argv))
  .option('port', { type: 'number', default: 8000 })
  .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
  .option('linkedinClientId', { type: 'string', demandOption: true, describe: "LinkedIn Client ID" })
  .option('linkedinClientSecret', { type: 'string', demandOption: true, describe: "LinkedIn Client Secret" })
  .option('linkedinRedirectUri', { type: 'string', demandOption: true, describe: "LinkedIn Redirect URI" })
  .option('linkedinState', { type: 'string', default: '', describe: "LinkedIn State (optional)" })
  .help()
  .parseSync()

const log = (...args: any[]) => console.log('[linkedin-mcp]', ...args)
const logErr = (...args: any[]) => console.error('[linkedin-mcp]', ...args)

// --------------------------------------------------------------------
// 2) Global LinkedIn Auth State
// --------------------------------------------------------------------
let linkedinAccessToken: string | null = null
let linkedinUserId: string | null = null

// --------------------------------------------------------------------
// 3) LinkedIn OAuth Setup
// --------------------------------------------------------------------
const LINKEDIN_CLIENT_ID = argv.linkedinClientId
const LINKEDIN_CLIENT_SECRET = argv.linkedinClientSecret
const LINKEDIN_REDIRECT_URI = argv.linkedinRedirectUri
const LINKEDIN_STATE = argv.linkedinState

// Generate the LinkedIn OAuth URL
function generateLinkedinAuthUrl(): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: LINKEDIN_CLIENT_ID,
    redirect_uri: LINKEDIN_REDIRECT_URI,
    state: LINKEDIN_STATE,
    scope: 'liteprofile w_member_social',
  })
  return `https://www.linkedin.com/oauth/v2/authorization?${params.toString()}`
}

// Exchange authorization code for access token
async function exchangeLinkedinAuthCode(code: string): Promise<string> {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code.trim(),
    client_id: LINKEDIN_CLIENT_ID,
    client_secret: LINKEDIN_CLIENT_SECRET,
    redirect_uri: LINKEDIN_REDIRECT_URI
  })
  const response = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  })
  const data = await response.json()
  if (!data.access_token) {
    throw new Error('Failed to obtain LinkedIn access token.')
  }
  linkedinAccessToken = data.access_token
  return data.access_token
}

// Fetch authenticated user's profile to retrieve the LinkedIn user ID
async function fetchLinkedinUser(): Promise<any> {
  if (!linkedinAccessToken) throw new Error('No LinkedIn access token available.')
  const response = await fetch('https://api.linkedin.com/v2/me', {
    headers: {
      'Authorization': `Bearer ${linkedinAccessToken}`
    }
  })
  const data = await response.json()
  if (!data.id) throw new Error('Failed to fetch LinkedIn user id.')
  linkedinUserId = data.id
  return data
}

// Authenticate with LinkedIn: exchange code and fetch user info
async function authLinkedin(args: { code: string }): Promise<any> {
  const { code } = args
  await exchangeLinkedinAuthCode(code)
  const user = await fetchLinkedinUser()
  return { success: true, provider: "linkedin", user }
}

// --------------------------------------------------------------------
// 4) Tool Functions: LinkedIn Post Creation
// --------------------------------------------------------------------
async function createLinkedinPostTool(args: { postContent: string }): Promise<any> {
  if (!linkedinAccessToken || !linkedinUserId) {
    throw new Error('No LinkedIn authentication configured. Run linkedin_exchange_auth_code first.')
  }
  const { postContent } = args
  const postData = {
    author: `urn:li:person:${linkedinUserId}`,
    lifecycleState: "PUBLISHED",
    specificContent: {
      "com.linkedin.ugc.ShareContent": {
        shareCommentary: {
          text: postContent
        },
        shareMediaCategory: "NONE"
      }
    },
    visibility: {
      "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
    }
  }
  const response = await fetch('https://api.linkedin.com/v2/ugcPosts', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${linkedinAccessToken}`,
      'Content-Type': 'application/json',
      'X-Restli-Protocol-Version': '2.0.0'
    },
    body: JSON.stringify(postData)
  })
  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`LinkedIn post creation failed: ${errorText}`)
  }
  return { success: true, message: 'Post created successfully.' }
}

// --------------------------------------------------------------------
// 5) Helper: JSON response formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(data, null, 2)
      }
    ]
  }
}

// --------------------------------------------------------------------
// 6) Create the MCP server, registering our tools
// --------------------------------------------------------------------
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: 'LinkedIn MCP Server',
    version: '1.0.0'
  })

  server.tool(
    'linkedin_auth_url',
    'Return an OAuth URL for LinkedIn (visit this URL to grant access with w_member_social scope).',
    {},
    async () => {
      try {
        const authUrl = generateLinkedinAuthUrl()
        return toTextJson({ authUrl })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'linkedin_exchange_auth_code',
    'Set up LinkedIn authentication by exchanging an auth code.',
    {
      code: z.string()
    },
    async (args) => {
      try {
        const result = await authLinkedin(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'linkedin_create_post',
    'Create a new post on LinkedIn on behalf of the authenticated member. Provide postContent as text.',
    {
      postContent: z.string()
    },
    async (args) => {
      try {
        const result = await createLinkedinPostTool(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  return server
}

// --------------------------------------------------------------------
// 7) Minimal Fly.io "replay" handling (optional)
// --------------------------------------------------------------------
function parseFlyReplaySrc(headerValue: string): Record<string, string> {
  const regex = /(.*?)=(.*?)($|;)/g
  const matches = headerValue.matchAll(regex)
  const result: Record<string, string> = {}
  for (const match of matches) {
    if (match.length >= 3) {
      const key = match[1].trim()
      const value = match[2].trim()
      result[key] = value
    }
  }
  return result
}
let machineId: string | null = null
function saveMachineId(req: Request) {
  if (machineId) return
  const headerKey = 'fly-replay-src'
  const raw = req.headers[headerKey.toLowerCase()]
  if (!raw || typeof raw !== 'string') return
  try {
    const parsed = parseFlyReplaySrc(raw)
    if (parsed.state) {
      const decoded = decodeURIComponent(parsed.state)
      const obj = JSON.parse(decoded)
      if (obj.machineId) machineId = obj.machineId
    }
  } catch {
    // ignore
  }
}

// --------------------------------------------------------------------
// 8) Main: Start either SSE or stdio server
// --------------------------------------------------------------------
function main() {
  const server = createMcpServer()

  if (argv.transport === 'stdio') {
    const transport = new StdioServerTransport()
    void server.connect(transport)
    log('Listening on stdio')
    return
  }

  const port = argv.port
  const app = express()
  let sessions: { server: McpServer; transport: SSEServerTransport }[] = []

  app.use((req, res, next) => {
    if (req.path === '/message') return next()
    express.json()(req, res, next)
  })

  app.get('/', async (req: Request, res: Response) => {
    saveMachineId(req)
    const transport = new SSEServerTransport('/message', res)
    const mcpInstance = createMcpServer()
    await mcpInstance.connect(transport)
    sessions.push({ server: mcpInstance, transport })

    const sessionId = transport.sessionId
    log(`[${sessionId}] SSE connection established`)

    transport.onclose = () => {
      log(`[${sessionId}] SSE closed`)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    req.on('close', () => {
      log(`[${sessionId}] SSE client disconnected`)
      sessions = sessions.filter(s => s.transport !== transport)
    })
  })

  app.post('/message', async (req: Request, res: Response) => {
    const sessionId = req.query.sessionId as string
    if (!sessionId) {
      logErr('Missing sessionId')
      res.status(400).send({ error: 'Missing sessionId' })
      return
    }
    const target = sessions.find(s => s.transport.sessionId === sessionId)
    if (!target) {
      logErr(`No active session for sessionId=${sessionId}`)
      res.status(404).send({ error: 'No active session' })
      return
    }
    try {
      await target.transport.handlePostMessage(req, res)
    } catch (err: any) {
      logErr(`[${sessionId}] Error handling /message:`, err)
      res.status(500).send({ error: 'Internal error' })
    }
  })

  app.listen(port, () => {
    log(`Listening on port ${port} (${argv.transport})`)
  })
}

main()
