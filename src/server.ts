import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { getNavigationTools, DOMAINS } from './domains/navigation.js';
import { getDomainHandler } from './domains/index.js';
import { getCredentials } from './utils/client.js';
import { logger } from './utils/logger.js';
import { toolErrorResult } from './utils/tool-error.js';
import { setServerRef } from './utils/server-ref.js';
import type { DomainName } from './utils/types.js';

export function createMcpServer(): Server {
  const server = new Server(
    { name: 'threatlocker-mcp', version: '0.1.0' },
    {
      capabilities: {
        tools: {},
        logging: {},
      },
    }
  );

  // Set server reference for elicitation
  setServerRef(server);

  // Return ALL tools upfront — navigation is a stateless help/discovery tool
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const allTools = [...getNavigationTools()];
    for (const domain of DOMAINS) {
      const handler = await getDomainHandler(domain);
      allTools.push(...handler.getTools());
    }
    return { tools: allTools };
  });

  // Route tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const { name, arguments: args } = request.params;

    // Navigation: navigate (stateless discovery aid)
    if (name === 'threatlocker_navigate') {
      const domain = (args?.domain as string) as DomainName;
      if (!DOMAINS.includes(domain)) {
        return {
          content: [{ type: 'text' as const, text: `Invalid domain: ${domain}. Valid: ${DOMAINS.join(', ')}` }],
          isError: true,
        };
      }

      const handler = await getDomainHandler(domain);
      const tools = handler.getTools();

      const toolSummary = tools
        .map(t => `- ${t.name}: ${t.description}`)
        .join('\n');

      // Get domain description from navigation
      const navTools = getNavigationTools();
      const navTool = navTools.find(t => t.name === 'threatlocker_navigate');
      const domainProp = navTool?.inputSchema?.properties?.domain as { description?: string } | undefined;
      const domainDesc = domainProp?.description ?? '';
      const domainLine = domainDesc.split('\n').find((line: string) => line.includes(`- ${domain}:`));
      const description = domainLine ? domainLine.replace(`- ${domain}: `, '') : `${domain} domain`;

      return {
        content: [{
          type: 'text' as const,
          text: `${description}\n\nAvailable tools:\n${toolSummary}\n\nYou can call any of these tools directly.`,
        }],
      };
    }

    // Navigation: status
    if (name === 'threatlocker_status') {
      const creds = getCredentials();
      const credStatus = creds
        ? 'Configured (API connection available)'
        : 'NOT CONFIGURED - Please set environment variables';

      return {
        content: [{
          type: 'text' as const,
          text: `ThreatLocker MCP Server Status\n\nCredentials: ${credStatus}\nAvailable domains: ${DOMAINS.join(', ')}\n\nAll tools are available at all times. Use threatlocker_navigate to discover tools by domain.`,
        }],
      };
    }

    // Domain tool calls — try every domain handler
    for (const domain of DOMAINS) {
      const handler = await getDomainHandler(domain);
      const toolNames = handler.getTools().map(t => t.name);
      if (toolNames.includes(name)) {
        try {
          return await handler.handleCall(name, (args || {}) as Record<string, unknown>, extra);
        } catch (error) {
          logger.error('Tool call failed', { tool: name, error: (error as Error).message });
          // A 429 also carries retry_after_seconds (see utils/tool-error.ts).
          return toolErrorResult(error);
        }
      }
    }

    return {
      content: [{ type: 'text' as const, text: `Unknown tool: ${name}. Use threatlocker_navigate to discover available tools.` }],
      isError: true,
    };
  });

  return server;
}