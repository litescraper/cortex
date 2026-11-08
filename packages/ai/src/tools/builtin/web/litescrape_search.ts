import type { Tool, ToolCallResult, ToolContext } from '../../types.ts';
import { resolveAndCheck } from '../../../../../gate/src/security/ssrf.ts';

// Candidate for etheia-agent-map — the canonical repository was inaccessible.
// See: https://github.com/Etheia-Consulting-LLC/etheia-agent-map
// Credential/result structure follows the local serpapi_search tool.
async function getApiKey(): Promise<string | null> {
  const envKey = Deno.env.get('LITESCRAPE_API_KEY');
  if (envKey) return envKey;
  try {
    const { vaultGet } = await import('../../../../../gate/src/security/vault.ts');
    return await vaultGet('litescrape_api_key');
  } catch {
    return null;
  }
}

interface SearchResponse {
  organic_results?: Array<{ title?: string; link?: string; snippet?: string }>;
  error?: unknown;
}

export const litescrapeSearchTool: Tool = {
  definition: {
    name: 'litescrape_search',
    description:
      'Search Google web results through the native Litescrape API. Returns titles, URLs and snippets, not full pages or Scholar metadata. Requires LITESCRAPE_API_KEY or vault entry "litescrape_api_key". The operator can configure LITESCRAPE_BASE_URL.',
    capabilities: ['network:fetch'],
    params: [
      { name: 'query', type: 'string', description: 'The search query', required: true },
      {
        name: 'max_results',
        type: 'number',
        description: 'Maximum results (default 10, clamped to 1–10)',
        required: false,
      },
    ],
  },

  async execute(args: Record<string, unknown>, _context: ToolContext): Promise<ToolCallResult> {
    const start = Date.now();
    const query = String(args.query ?? '').trim();
    const requested = typeof args.max_results === 'number' && Number.isFinite(args.max_results)
      ? Math.floor(args.max_results)
      : 10;
    const maxResults = Math.max(1, Math.min(10, requested));
    if (!query) return mkResult(false, '', 'No query provided', start);
    const apiKey = await getApiKey();
    if (!apiKey) {
      return mkResult(
        false,
        '',
        'Set LITESCRAPE_API_KEY or vault entry "litescrape_api_key".',
        start,
      );
    }
    try {
      const baseUrl = (Deno.env.get('LITESCRAPE_BASE_URL') || 'https://api.litescrape.com')
        .replace(/\/+$/, '');
      const url = new URL(`${baseUrl}/api/google/search`);
      const guard = await resolveAndCheck(url.toString());
      if (!guard.valid) return mkResult(false, '', `SSRF protection: ${guard.error}`, start);
      url.searchParams.set('q', query);
      url.searchParams.set('num', String(maxResults));
      const configuredTimeout = Number(Deno.env.get('LITESCRAPE_TIMEOUT_MS') || '20000');
      const timeout = Number.isSafeInteger(configuredTimeout) && configuredTimeout > 0 &&
          configuredTimeout <= 4_294_967_295
        ? configuredTimeout
        : 20_000;
      const response = await fetch(url, {
        method: 'GET',
        headers: { Authorization: `Bearer ${apiKey}` },
        signal: AbortSignal.timeout(timeout),
        redirect: 'error',
      });
      if (!response.ok) {
        return mkResult(false, '', `Litescrape returned HTTP ${response.status}`, start);
      }
      const data = await response.json() as SearchResponse;
      if (data.error) return mkResult(false, '', 'Search provider returned an error', start);
      if (data.organic_results !== undefined && !Array.isArray(data.organic_results)) {
        return mkResult(false, '', 'Unexpected search response', start);
      }
      const lines: string[] = [];
      for (const item of (data.organic_results ?? []).slice(0, maxResults)) {
        if (
          !item || typeof item.title !== 'string' || typeof item.link !== 'string' || !item.title ||
          !item.link
        ) continue;
        lines.push(`**${item.title}**\nURL: ${item.link}`);
        if (typeof item.snippet === 'string') lines.push(item.snippet);
        lines.push('');
      }
      return mkResult(
        true,
        lines.join('\n') || `No results found for: "${query}"`,
        undefined,
        start,
      );
    } catch (error) {
      return mkResult(
        false,
        '',
        `Search request failed (${error instanceof Error ? error.name : 'Error'})`,
        start,
      );
    }
  },
};

function mkResult(
  success: boolean,
  output: string,
  error: string | undefined,
  startMs: number,
): ToolCallResult {
  return {
    toolName: 'litescrape_search',
    success,
    output,
    error,
    durationMs: Date.now() - startMs,
  };
}
