/**
 * GitHub REST API client
 *
 * Used by the Maintainer Health scorer to fetch repository signals:
 *   - Stars, forks, open issues
 *   - Last push date (proxy for active development)
 *   - Archived status
 *
 * Rate limits:
 *   - Unauthenticated: 60 requests/hour
 *   - With GITHUB_TOKEN:  5,000 requests/hour
 *
 * Set the GITHUB_TOKEN environment variable to raise the limit.
 * The token needs no special scopes — public repo access is sufficient.
 */

import { USER_AGENT } from '../utils/constants';

const GITHUB_API_BASE = 'https://api.github.com';
const TIMEOUT_MS      = 10_000;

export interface GitHubRepoInfo {
  owner:        string;
  repo:         string;
  stars:        number;
  forks:        number;
  openIssues:   number;
  pushedAt:     Date | null;   // last push to any branch
  isArchived:   boolean;
  htmlUrl:      string;
}

// ─── URL extraction ────────────────────────────────────────────────────────

/**
 * Extracts the GitHub owner + repo from a repository URL string.
 *
 * Handles:
 *   - https://github.com/owner/repo
 *   - https://github.com/owner/repo.git
 *   - git+https://github.com/owner/repo.git
 *   - git://github.com/owner/repo.git
 *   - github:owner/repo           (npm shorthand)
 *   - owner/repo                  (bare shorthand)
 */
export function extractGitHubRepo(
  url: string | null | undefined,
): { owner: string; repo: string } | null {
  if (!url) return null;

  const s = url.trim();

  // Full GitHub URL (https or git+https or git://)
  const httpMatch = s.match(
    /(?:https?|git\+https?|git):\/\/(?:www\.)?github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/i,
  );
  if (httpMatch) {
    return { owner: httpMatch[1], repo: httpMatch[2] };
  }

  // SSH: git@github.com:owner/repo.git
  const sshMatch = s.match(/git@github\.com:([^/]+)\/([^/]+?)(?:\.git)?$/i);
  if (sshMatch) {
    return { owner: sshMatch[1], repo: sshMatch[2] };
  }

  // npm shorthand: github:owner/repo  OR  owner/repo (no slashes in owner)
  const shortMatch = s.match(/^(?:github:)?([a-z0-9_-]+)\/([a-z0-9_.-]+)$/i);
  if (shortMatch) {
    return { owner: shortMatch[1], repo: shortMatch[2].replace(/\.git$/, '') };
  }

  return null;
}

// ─── API client ────────────────────────────────────────────────────────────

function _buildHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept:                 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent':           USER_AGENT,
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

/**
 * Fetches repository metadata from the GitHub REST API.
 *
 * @throws  if the network call fails or the API returns a non-200 status.
 *          Callers should catch and treat as "GitHub data unavailable".
 */
export async function fetchGitHubRepoInfo(
  owner: string,
  repo:  string,
): Promise<GitHubRepoInfo> {
  const url = `${GITHUB_API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(url, { headers: _buildHeaders(), signal: controller.signal });
  } catch (err) {
    clearTimeout(timer);
    if ((err as Error).name === 'AbortError') throw new Error(`GitHub API timed out for ${owner}/${repo}`);
    throw new Error(`GitHub API network error: ${(err as Error).message}`);
  }
  clearTimeout(timer);

  if (response.status === 404) throw new Error(`GitHub repo not found: ${owner}/${repo}`);

  // 403 / 429 = rate limited
  if (response.status === 403 || response.status === 429) {
    throw new Error(`GitHub API rate limit reached — set GITHUB_TOKEN for higher limits`);
  }

  if (!response.ok) throw new Error(`GitHub API returned HTTP ${response.status}`);

  const data = await response.json() as Record<string, unknown>;

  const pushedAtStr = data.pushed_at as string | undefined;
  const pushedAt = pushedAtStr ? (() => {
    const d = new Date(pushedAtStr);
    return isNaN(d.getTime()) ? null : d;
  })() : null;

  return {
    owner,
    repo,
    stars:       (data.stargazers_count as number) ?? 0,
    forks:       (data.forks_count      as number) ?? 0,
    openIssues:  (data.open_issues_count as number) ?? 0,
    pushedAt,
    isArchived:  (data.archived as boolean) ?? false,
    htmlUrl:     (data.html_url as string) ?? `https://github.com/${owner}/${repo}`,
  };
}
