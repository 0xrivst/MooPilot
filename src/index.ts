/*
MooPilot -- MCP server for Remember The Milk API
Copyright (C) 2025 rivst.

MooPilot is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

MooPilot is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import cors from "cors";
import crypto from "crypto";
import express, { Request, Response } from "express";
import { z } from "zod";
import { RememberTheMilkAPI } from "./RememberTheMilkAPI.js";
import wellKnown from "./routes/well-known.js";
import { getBaseUrl } from "./util.js";

interface StoredToken {
  token: string;
  rtmToken: string;
  rtmUser: any;
  scopes: string[];
  clientId: string;
  createdAt: Date;
  expiresAt: Date;
}

interface AuthObject {
  token: string;
  clientId: string;
  scopes: string[];
  rtmToken: string;
  rtmUser: any;
}

interface AuthenticatedRequest extends Request {
  auth?: AuthObject;
}

const authorizationCodes = new Map<string, any>();
const accessTokens = new Map<string, StoredToken>();
const pendingAuths = new Map<string, any>();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cors());

app.use("/.well-known", wellKnown);

app.get("/authorize", async (req: Request, res: Response) => {
  const {
    client_id,
    redirect_uri,
    response_type,
    state,
    code_challenge,
    code_challenge_method,
  } = req.query;

  if (response_type !== "code") {
    res.status(400).send("Only authorization code flow is supported");
    return;
  }

  try {
    const rtmApi = new RememberTheMilkAPI({
      apiKey: process.env.RTM_API_KEY!,
      sharedSecret: process.env.RTM_SHARED_SECRET!,
    });

    const frob = await rtmApi.getFrob();

    const authId = crypto.randomUUID();
    pendingAuths.set(authId, {
      frob,
      client_id,
      redirect_uri,
      state,
      code_challenge,
      code_challenge_method,
      createdAt: new Date(),
    });

    const rtmAuthUrl = rtmApi.getAuthUrl(frob, "delete");

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authorize Remember The Milk</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
          .button { 
            background-color: #4CAF50; 
            border: none; 
            color: white; 
            padding: 15px 32px; 
            text-align: center; 
            text-decoration: none; 
            display: inline-block; 
            font-size: 16px; 
            margin: 4px 2px; 
            cursor: pointer; 
            border-radius: 4px;
          }
        </style>
      </head>
      <body>
        <h1>Authorize Remember The Milk Access</h1>
        <p>This application needs access to your Remember The Milk account.</p>
        <a href="${rtmAuthUrl}" class="button">Authorize with Remember The Milk</a>
        <br><br>
        <p>After authorizing, click the button below:</p>
        <a href="/callback?auth_id=${authId}" class="button">I've Authorized the App</a>
      </body>
      </html>
    `);
  } catch (error) {
    console.error("Auth error:", error);
    res.status(500).send("Authorization error");
  }
});

app.get("/callback", async (req: Request, res: Response) => {
  const { auth_id } = req.query;

  if (!auth_id || typeof auth_id !== "string") {
    res.status(400).send("Missing auth_id");
    return;
  }

  const authData = pendingAuths.get(auth_id);
  if (!authData) {
    res.status(400).send("Invalid or expired auth_id");
    return;
  }

  try {
    const rtmApi = new RememberTheMilkAPI({
      apiKey: process.env.RTM_API_KEY!,
      sharedSecret: process.env.RTM_SHARED_SECRET!,
    });

    const { token: rtmToken, user: rtmUser } = await rtmApi.getToken(
      authData.frob
    );

    const authCode = crypto.randomUUID();

    authorizationCodes.set(authCode, {
      ...authData,
      rtmToken,
      rtmUser,
      authCode,
      expiresAt: new Date(Date.now() + 600000), // 10 minutes
    });

    pendingAuths.delete(auth_id);

    const redirectUrl = new URL(authData.redirect_uri);
    redirectUrl.searchParams.set("code", authCode);
    if (authData.state) {
      redirectUrl.searchParams.set("state", authData.state);
    }

    res.redirect(redirectUrl.toString());
  } catch (error) {
    console.error("Callback error:", error);
    res.status(500).send("Failed to complete authorization");
  }
});

app.post("/token", async (req: Request, res: Response) => {
  const { grant_type, code, redirect_uri, code_verifier, client_id } = req.body;

  if (grant_type !== "authorization_code") {
    res.status(400).json({ error: "unsupported_grant_type" });
    return;
  }

  const authData = authorizationCodes.get(code);
  if (!authData) {
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  if (new Date() > authData.expiresAt) {
    authorizationCodes.delete(code);
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  if (authData.code_challenge) {
    if (!code_verifier) {
      res.status(400).json({
        error: "invalid_request",
        error_description: "code_verifier required",
      });
      return;
    }

    let calculatedChallenge: string;
    if (authData.code_challenge_method === "S256") {
      const hash = crypto
        .createHash("sha256")
        .update(code_verifier)
        .digest("base64url");
      calculatedChallenge = hash;
    } else {
      calculatedChallenge = code_verifier;
    }

    if (calculatedChallenge !== authData.code_challenge) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }
  }

  const accessToken = crypto.randomUUID();

  const tokenData: StoredToken = {
    token: accessToken,
    rtmToken: authData.rtmToken,
    rtmUser: authData.rtmUser,
    scopes: ["tasks"],
    clientId: authData.client_id || client_id || "unknown",
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
  };

  accessTokens.set(accessToken, tokenData);

  authorizationCodes.delete(code);

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 2592000, // 30 days
    scope: "tasks",
  });
});

interface AuthResult {
  success: boolean;
  response?: Response;
  tokenData?: StoredToken;
  authObject?: AuthObject;
}

async function authenticateToken(
  req: AuthenticatedRequest,
  res: Response,
  rpcId: any = null
): Promise<AuthResult> {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.replace(/^Bearer\s+/i, "").trim();
  const baseUrl = getBaseUrl(req);

  if (!token) {
    const wwwAuthHeader = `Bearer realm="RTM MCP Server", resource_metadata_endpoint="${baseUrl}/.well-known/oauth-protected-resource"`;

    res
      .status(401)
      .header("WWW-Authenticate", wwwAuthHeader)
      .json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Missing Bearer token" },
        id: rpcId,
      });

    return { success: false };
  }

  const tokenData = accessTokens.get(token);
  if (!tokenData) {
    res.status(403).json({
      jsonrpc: "2.0",
      error: { code: -32001, message: "Invalid or expired token" },
      id: rpcId,
    });

    return { success: false };
  }

  if (new Date() > tokenData.expiresAt) {
    accessTokens.delete(token);
    res.status(403).json({
      jsonrpc: "2.0",
      error: { code: -32001, message: "Token expired" },
      id: rpcId,
    });

    return { success: false };
  }

  const authObject: AuthObject = {
    token: token,
    clientId: tokenData.clientId,
    scopes: tokenData.scopes,
    rtmToken: tokenData.rtmToken,
    rtmUser: tokenData.rtmUser,
  };

  return {
    success: true,
    tokenData,
    authObject,
  };
}

const mcpServer = new McpServer({
  name: "Remember The Milk MCP",
  version: "0.1.0",
});

const transports: { [key: string]: any } = {};
const pendingTransports: { [key: string]: any } = {};

async function createAndConnectTransport(
  sessionId: string,
  server: McpServer,
  transports: any,
  label: string
): Promise<any> {
  if (pendingTransports[sessionId] || transports[sessionId]) {
    return pendingTransports[sessionId] || transports[sessionId];
  }

  const transport = new StreamableHTTPServerTransport({
    enableJsonResponse: true,
    sessionIdGenerator: () => sessionId,
    onsessioninitialized: (actualId) => {
      delete pendingTransports[actualId];
    },
  });

  (transport as any).sessionId = sessionId;

  (transport as any).onclose = () => {
    if (transports[sessionId]) {
      delete transports[sessionId];
    }
  };

  pendingTransports[sessionId] = transport;
  transports[sessionId] = transport;

  try {
    await server.connect(transport);
  } catch (error) {
    delete pendingTransports[sessionId];
    delete transports[sessionId];
    throw error;
  }

  return transport;
}

const GetListsSchema = z.object({});

const GetTasksSchema = z.object({
  list_id: z.string().optional().describe("Optional list ID to filter tasks"),
  last_sync: z
    .string()
    .optional()
    .describe("Optional last sync timestamp for incremental updates"),
});

const AddTaskSchema = z.object({
  list_id: z.string().describe("List ID to add the task to"),
  name: z.string().describe("Name of the task"),
});

const DeleteTaskSchema = z.object({
  list_id: z.string().describe("List ID containing the task"),
  taskseries_id: z.string().describe("Task series ID"),
  task_id: z.string().describe("Task ID"),
});

const SetPrioritySchema = z.object({
  list_id: z.string().describe("List ID containing the task"),
  taskseries_id: z.string().describe("Task series ID"),
  task_id: z.string().describe("Task ID"),
  priority: z
    .enum(["1", "2", "3", "N"])
    .describe("Priority level (1=High, 2=Medium, 3=Low, N=None)"),
});

function registerRTMTools(server: McpServer) {
  server.registerTool(
    "rtm_get_lists",
    {
      description: "Get all lists from Remember The Milk",
      inputSchema: GetListsSchema.shape,
    },
    async (args: z.infer<typeof GetListsSchema>, context: any) => {
      const rtmToken = context?.rtmToken;
      if (!rtmToken) {
        throw new Error("Not authenticated with Remember The Milk");
      }

      const rtmApi = new RememberTheMilkAPI({
        apiKey: process.env.RTM_API_KEY!,
        sharedSecret: process.env.RTM_SHARED_SECRET!,
        authToken: rtmToken,
      });

      const lists = await rtmApi.getLists();
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(lists, null, 2),
          },
        ],
      };
    }
  );

  server.registerTool(
    "rtm_get_tasks",
    {
      description: "Get tasks from Remember The Milk",
      inputSchema: GetTasksSchema.shape,
    },
    async (args: z.infer<typeof GetTasksSchema>, context: any) => {
      const rtmToken = context?.rtmToken;
      if (!rtmToken) {
        throw new Error("Not authenticated with Remember The Milk");
      }

      const rtmApi = new RememberTheMilkAPI({
        apiKey: process.env.RTM_API_KEY!,
        sharedSecret: process.env.RTM_SHARED_SECRET!,
        authToken: rtmToken,
      });

      const tasks = await rtmApi.getTasks(args.list_id, args.last_sync);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(tasks, null, 2),
          },
        ],
      };
    }
  );

  server.registerTool(
    "rtm_add_task",
    {
      description: "Add a new task to Remember The Milk",
      inputSchema: AddTaskSchema.shape,
    },
    async (args: z.infer<typeof AddTaskSchema>, context: any) => {
      const rtmToken = context?.rtmToken;
      if (!rtmToken) {
        throw new Error("Not authenticated with Remember The Milk");
      }

      const rtmApi = new RememberTheMilkAPI({
        apiKey: process.env.RTM_API_KEY!,
        sharedSecret: process.env.RTM_SHARED_SECRET!,
        authToken: rtmToken,
      });

      const timeline = await rtmApi.createTimeline();
      const result = await rtmApi.addTask(args.list_id, args.name, timeline);

      return {
        content: [
          {
            type: "text",
            text: `Task added successfully!\n${JSON.stringify(
              result,
              null,
              2
            )}`,
          },
        ],
      };
    }
  );

  server.registerTool(
    "rtm_delete_task",
    {
      description: "Delete a task from Remember The Milk",
      inputSchema: DeleteTaskSchema.shape,
    },
    async (args: z.infer<typeof DeleteTaskSchema>, context: any) => {
      const rtmToken = context?.rtmToken;
      if (!rtmToken) {
        throw new Error("Not authenticated with Remember The Milk");
      }

      const rtmApi = new RememberTheMilkAPI({
        apiKey: process.env.RTM_API_KEY!,
        sharedSecret: process.env.RTM_SHARED_SECRET!,
        authToken: rtmToken,
      });

      const timeline = await rtmApi.createTimeline();
      const result = await rtmApi.deleteTask(
        args.list_id,
        args.taskseries_id,
        args.task_id,
        timeline
      );

      return {
        content: [
          {
            type: "text",
            text: `Task deleted successfully!\n${JSON.stringify(
              result,
              null,
              2
            )}`,
          },
        ],
      };
    }
  );

  server.registerTool(
    "rtm_set_priority",
    {
      description: "Set the priority of a task",
      inputSchema: SetPrioritySchema.shape,
    },
    async (args: z.infer<typeof SetPrioritySchema>, context: any) => {
      const rtmToken = context?.rtmToken;
      if (!rtmToken) {
        throw new Error("Not authenticated with Remember The Milk");
      }

      const rtmApi = new RememberTheMilkAPI({
        apiKey: process.env.RTM_API_KEY!,
        sharedSecret: process.env.RTM_SHARED_SECRET!,
        authToken: rtmToken,
      });

      const timeline = await rtmApi.createTimeline();
      const result = await rtmApi.setPriority(
        args.list_id,
        args.taskseries_id,
        args.task_id,
        args.priority,
        timeline
      );

      return {
        content: [
          {
            type: "text",
            text: `Priority updated successfully!\n${JSON.stringify(
              result,
              null,
              2
            )}`,
          },
        ],
      };
    }
  );
}

registerRTMTools(mcpServer);

app.post("/mcp", async (req: AuthenticatedRequest, res: Response) => {
  const body = req.body;
  const rpcId = body && body.id !== undefined ? body.id : null;

  const authResult = await authenticateToken(req, res, rpcId);
  if (!authResult.success) {
    return;
  }

  req.auth = authResult.authObject;

  const clientSessionIdHeader = req.headers["mcp-session-id"];
  const actualClientSessionId = Array.isArray(clientSessionIdHeader)
    ? clientSessionIdHeader[0]
    : clientSessionIdHeader;

  let transport;
  let effectiveSessionId: string;

  const isInitRequest = body && body.method === "initialize";

  if (isInitRequest) {
    effectiveSessionId = crypto.randomUUID();
    transport = await createAndConnectTransport(
      effectiveSessionId,
      mcpServer,
      transports,
      "Initialize: "
    );

    res.setHeader("Mcp-Session-Id", effectiveSessionId);
  } else if (actualClientSessionId && transports[actualClientSessionId]) {
    transport = transports[actualClientSessionId];
    effectiveSessionId = actualClientSessionId;
  } else {
    res.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32003, message: "Bad Request: No valid session ID" },
      id: rpcId,
    });
    return;
  }

  req.headers["mcp-session-id"] = effectiveSessionId;

  res.setHeader("Mcp-Session-Id", effectiveSessionId);

  try {
    await transport.handleRequest(req, res, body);
  } catch (handleError) {
    console.error(
      `MCP POST handleRequest error (session ${effectiveSessionId}):`,
      handleError
    );
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Internal server error during request handling",
        },
        id: rpcId,
      });
    }
  }
});

app.delete("/mcp", async (req: Request, res: Response) => {
  const sessionId = req.headers["mcp-session-id"];

  if (sessionId && transports[sessionId as string]) {
    delete transports[sessionId as string];
    res.status(204).end();
  } else {
    res.status(404).json({ error: "Session not found" });
  }
});

app.get("/mcp", async (req: AuthenticatedRequest, res: Response) => {
  const authResult = await authenticateToken(req, res, null);
  if (!authResult.success) {
    return;
  }

  req.auth = authResult.authObject;

  const transport = new SSEServerTransport("/messages", res);

  transports[(transport as any).sessionId] = transport;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.setHeader("Mcp-Session-Id", (transport as any).sessionId);

  try {
    await mcpServer.connect(transport);
  } catch (error) {
    console.error("SSE connection error:", error);
    if (!res.headersSent) {
      res.status(500).send("Internal server error during SSE setup.");
    } else {
      res.end();
    }

    if (transports[(transport as any).sessionId]) {
      delete transports[(transport as any).sessionId];
    }
  }
});

app.post(
  "/messages",
  express.json(),
  async (req: AuthenticatedRequest, res: Response) => {
    const sessionId = req.query.sessionId;
    const body = req.body;
    const rpcId = body && body.id !== undefined ? body.id : null;

    const authResult = await authenticateToken(req, res, rpcId);
    if (!authResult.success) {
      return;
    }

    req.auth = authResult.authObject;

    if (!sessionId) {
      res.status(400).json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Missing sessionId in query parameters",
        },
        id: rpcId,
      });
      return;
    }

    const transport = transports[sessionId as string];

    if (!transport || !(transport instanceof SSEServerTransport)) {
      res.status(404).json({
        jsonrpc: "2.0",
        error: {
          code: -32001,
          message: "Session not found or not an SSE session",
        },
        id: rpcId,
      });
      return;
    }

    try {
      await transport.handlePostMessage(req, res, body);
    } catch (error) {
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: {
            code: -32603,
            message: "Internal server error handling message",
          },
          id: rpcId,
        });
      }
    }
  }
);

app.listen(port, () => {
  console.log(`Remember The Milk MCP server running on port ${port}`);
  console.log(`MCP endpoint available at http://localhost:${port}/mcp`);
  console.log(`OAuth authorization at http://localhost:${port}/authorize`);
});

if (process.argv.includes("--stdio")) {
  const stdioServer = new McpServer({
    name: "remember-the-milk",
    version: "1.0.0",
  });

  registerRTMTools(stdioServer);

  const transport = new StdioServerTransport();
  stdioServer.connect(transport).catch(console.error);
}

module.exports = app;
