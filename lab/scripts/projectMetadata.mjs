/**
 * Project metadata for bailey-forbes.com: Linguist language bytes, merged-PR
 * timeline, and repository/build identity. The Deploy KeyQuorum Lab workflow writes this JSON
 * into lab/public/ so Vite copies it next to the lab on GitHub Pages.
 */
export const SCHEMA_VERSION = 1;
export const PERCENTAGE_DECIMALS = 1;
export const GITHUB_API_VERSION = '2022-11-28';

const DEFAULT_API_BASE = 'https://api.github.com';
const EMAIL_PATTERN = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
const NOREPLY_GITHUB = /^(?:\d+\+)?([^@]+)@users\.noreply\.github\.com$/i;
const CO_AUTHOR_LINE = /^[ \t]*Co-authored-by:[ \t]+(.+?)[ \t]+<([^>\s]+)>[ \t]*$/gim;
const SHA_PATTERN = /^[0-9a-f]{7,40}$/i;
const ISO_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

const MAINTENANCE_BOTS = new Set([
  'dependabot',
  'dependabot[bot]',
  'renovate',
  'renovate[bot]',
  'imgbot',
  'imgbot[bot]',
  'snyk-bot',
  'github-actions[bot]',
]);

export const roundPercentage = (value) => {
  const factor = 10 ** PERCENTAGE_DECIMALS;
  return Math.round(value * factor) / factor;
};

export const languageBreakdown = (languageBytes) => {
  if (!languageBytes || typeof languageBytes !== 'object' || Array.isArray(languageBytes)) {
    throw new Error('GitHub Languages API must return an object of language name → byte count.');
  }

  const entries = Object.entries(languageBytes).map(([name, bytes]) => {
    if (typeof name !== 'string' || !name.trim()) {
      throw new Error('Language names from GitHub Linguist must be non-empty strings.');
    }
    if (!Number.isInteger(bytes) || bytes < 0) {
      throw new Error(`Language '${name}' has a non-integer byte count: ${bytes}`);
    }
    return { name, bytes };
  });

  const total = entries.reduce((sum, entry) => sum + entry.bytes, 0);
  const languages = entries.map((entry) => ({
    name: entry.name,
    bytes: entry.bytes,
    percentage: total === 0 ? 0 : roundPercentage((entry.bytes / total) * 100),
  }));

  languages.sort((left, right) => (
    right.percentage - left.percentage
    || right.bytes - left.bytes
    || left.name.localeCompare(right.name)
  ));
  return languages;
};

export const publicIdentityFromTrailer = (name, email) => {
  if (typeof email !== 'string' || typeof name !== 'string') return undefined;
  const trimmedEmail = email.trim();
  const trimmedName = name.trim();
  if (!trimmedEmail || EMAIL_PATTERN.test(trimmedName)) return undefined;

  const noreply = trimmedEmail.match(NOREPLY_GITHUB);
  if (noreply) return noreply[1];
  // Private inboxes stay off the public JSON; keep a display name when it is not an email.
  return trimmedName || undefined;
};

export const parseCoAuthorTrailers = (message) => {
  if (typeof message !== 'string' || !message) return [];
  const identities = [];
  const seen = new Set();
  for (const match of message.matchAll(CO_AUTHOR_LINE)) {
    const identity = publicIdentityFromTrailer(match[1], match[2]);
    if (!identity) continue;
    const key = identity.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    identities.push(identity);
  }
  return identities;
};

const AGENT_LOGINS = new Set([
  'cursoragent',
  'copilot-swe-agent',
  'chatgpt-codex-connector',
]);

export const isBotIdentity = (login, type) => {
  if (!login) return false;
  if (type === 'Bot') return true;
  const normalized = String(login).toLowerCase();
  return normalized.endsWith('[bot]') || MAINTENANCE_BOTS.has(normalized) || AGENT_LOGINS.has(normalized);
};

export const isRoutineMaintenancePullRequest = ({ author }) => (
  MAINTENANCE_BOTS.has(String(author ?? '').toLowerCase())
);

export const shouldIncludeMergedPullRequest = ({
  mergedAt,
  author,
  authorType,
  merger,
  mergerType,
  coAuthors = [],
}) => {
  if (!mergedAt) return false;
  const humanCoAuthors = coAuthors.filter((identity) => !isBotIdentity(identity));
  const humanAuthor = Boolean(author) && !isBotIdentity(author, authorType);
  const humanMerger = Boolean(merger) && !isBotIdentity(merger, mergerType);
  const hasHuman = humanAuthor || humanMerger || humanCoAuthors.length > 0;

  if (isRoutineMaintenancePullRequest({ author }) && humanCoAuthors.length === 0) {
    return false;
  }
  if (!hasHuman && isBotIdentity(author, authorType)) return false;
  return true;
};

const timelineTimestamp = (event) => event.mergedAt ?? event.publishedAt ?? '';

export const compareTimelineEvents = (left, right) => {
  const byDate = timelineTimestamp(right).localeCompare(timelineTimestamp(left));
  if (byDate) return byDate;
  if (left.type !== right.type) return left.type.localeCompare(right.type);
  return String(left.number ?? left.tag ?? '').localeCompare(String(right.number ?? right.tag ?? ''), undefined, { numeric: true });
};

const assertString = (value, label) => {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`Metadata field '${label}' must be a non-empty string.`);
  }
};

const assertNoEmail = (value, label) => {
  if (typeof value === 'string' && EMAIL_PATTERN.test(value)) {
    throw new Error(`Metadata field '${label}' must not include an email address.`);
  }
};

export const validateProjectMetadata = (data) => {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('project-metadata.json must be a JSON object.');
  }
  if (data.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`schemaVersion must be ${SCHEMA_VERSION}.`);
  }
  assertString(data.generatedAt, 'generatedAt');
  if (!ISO_PATTERN.test(data.generatedAt)) {
    throw new Error('generatedAt must be an ISO-8601 UTC timestamp.');
  }
  assertString(data.sourceCommit, 'sourceCommit');
  if (!SHA_PATTERN.test(data.sourceCommit)) {
    throw new Error('sourceCommit must be a git SHA.');
  }

  const repository = data.repository;
  if (!repository || typeof repository !== 'object') {
    throw new Error('repository metadata is required.');
  }
  ['owner', 'name', 'defaultBranch', 'url'].forEach((field) => assertString(repository[field], `repository.${field}`));

  if (!Array.isArray(data.languages)) throw new Error('languages must be an array.');
  data.languages.forEach((language, index) => {
    assertString(language?.name, `languages[${index}].name`);
    if (!Number.isInteger(language.bytes) || language.bytes < 0) {
      throw new Error(`languages[${index}].bytes must be a non-negative integer.`);
    }
    if (typeof language.percentage !== 'number' || Number.isNaN(language.percentage)) {
      throw new Error(`languages[${index}].percentage must be a number.`);
    }
  });
  const sorted = [...data.languages].sort((left, right) => (
    right.percentage - left.percentage || right.bytes - left.bytes || left.name.localeCompare(right.name)
  ));
  sorted.forEach((language, index) => {
    if (language.name !== data.languages[index].name || language.bytes !== data.languages[index].bytes) {
      throw new Error('languages must be sorted from largest percentage to smallest.');
    }
  });

  if (!Array.isArray(data.timeline)) throw new Error('timeline must be an array.');
  data.timeline.forEach((event, index) => {
    if (!event || typeof event !== 'object') throw new Error(`timeline[${index}] must be an object.`);
    if (event.type === 'pull_request') {
      if (!Number.isInteger(event.number) || event.number <= 0) {
        throw new Error(`timeline[${index}].number must be a positive integer.`);
      }
      assertString(event.title, `timeline[${index}].title`);
      assertString(event.mergedAt, `timeline[${index}].mergedAt`);
      assertString(event.url, `timeline[${index}].url`);
      assertString(event.author, `timeline[${index}].author`);
      assertNoEmail(event.author, `timeline[${index}].author`);
      if (!Array.isArray(event.coAuthors)) {
        throw new Error(`timeline[${index}].coAuthors must be an array.`);
      }
      event.coAuthors.forEach((author, coIndex) => {
        assertString(author, `timeline[${index}].coAuthors[${coIndex}]`);
        assertNoEmail(author, `timeline[${index}].coAuthors[${coIndex}]`);
      });
    } else if (event.type === 'release' || event.type === 'tag') {
      assertString(event.tag, `timeline[${index}].tag`);
      assertString(event.title, `timeline[${index}].title`);
      assertString(event.publishedAt, `timeline[${index}].publishedAt`);
      assertString(event.url, `timeline[${index}].url`);
    } else {
      throw new Error(`timeline[${index}].type '${event.type}' is not supported.`);
    }
  });

  const ordered = [...data.timeline].sort(compareTimelineEvents);
  ordered.forEach((event, index) => {
    const actual = data.timeline[index];
    if (actual.type !== event.type || (actual.number ?? actual.tag) !== (event.number ?? event.tag)) {
      throw new Error('timeline must be ordered newest-first.');
    }
  });

  const forbiddenKeys = ['token', 'authorization', 'GITHUB_TOKEN', 'email'];
  const serialized = JSON.stringify(data);
  forbiddenKeys.forEach((key) => {
    if (Object.hasOwn(data, key)) throw new Error(`Metadata must not include '${key}'.`);
  });
  if (/authorization\s*[:=]/i.test(serialized)) {
    throw new Error('Metadata must not include authorization values.');
  }

  if (data.build) {
    if (typeof data.build !== 'object' || Array.isArray(data.build)) {
      throw new Error('build must be an object when present.');
    }
    if (data.build.commit) assertString(data.build.commit, 'build.commit');
    if (data.build.workflow) assertString(data.build.workflow, 'build.workflow');
    if (data.build.generatedAt) assertString(data.build.generatedAt, 'build.generatedAt');
  }

  return data;
};

export const assembleProjectMetadata = ({
  repository,
  languages,
  timeline,
  sourceCommit,
  generatedAt,
  workflow,
}) => {
  const metadata = {
    schemaVersion: SCHEMA_VERSION,
    generatedAt,
    sourceCommit,
    repository: {
      owner: repository.owner,
      name: repository.name,
      defaultBranch: repository.defaultBranch,
      url: repository.url,
    },
    languages,
    timeline,
    build: {
      workflow,
      commit: sourceCommit,
      generatedAt,
    },
  };
  return validateProjectMetadata(metadata);
};

const parseLinkNext = (linkHeader) => {
  if (!linkHeader) return undefined;
  const next = linkHeader.split(',').map((part) => part.trim()).find((part) => part.endsWith('rel="next"'));
  const match = next?.match(/^<([^>]+)>/);
  return match?.[1];
};

const githubHeaders = (token) => {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
    'User-Agent': 'BPForbes-KeyQuorum-project-metadata',
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
};

export const githubGetJson = async (url, { token, fetchImpl = fetch } = {}) => {
  const response = await fetchImpl(url, { headers: githubHeaders(token) });
  const rateLimitRemaining = response.headers.get('x-ratelimit-remaining');
  const rateLimitReset = response.headers.get('x-ratelimit-reset');

  if (response.status === 403 || response.status === 429) {
    const resetAt = rateLimitReset
      ? new Date(Number(rateLimitReset) * 1000).toISOString()
      : 'unknown';
    throw new Error(`GitHub API rate limited (${response.status}) for ${url}. Remaining=${rateLimitRemaining ?? 'n/a'}; reset=${resetAt}.`);
  }
  if (!response.ok) {
    throw new Error(`GitHub API request failed: ${response.status} ${response.statusText} for ${url}`);
  }

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(`GitHub API returned non-JSON for ${url}`);
  }
  return { data, headers: response.headers };
};

export const githubGetAllPages = async (url, { token, fetchImpl = fetch } = {}) => {
  const items = [];
  let nextUrl = url;
  while (nextUrl) {
    const { data, headers } = await githubGetJson(nextUrl, { token, fetchImpl });
    if (!Array.isArray(data)) {
      throw new Error(`GitHub API page for ${nextUrl} must be a JSON array.`);
    }
    items.push(...data);
    nextUrl = parseLinkNext(headers.get?.('link') ?? headers.get?.('Link'));
  }
  return items;
};

const uniqueIdentities = (values) => {
  const seen = new Set();
  return values.filter((value) => {
    const key = value.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((left, right) => left.localeCompare(right));
};

export const collectPullRequestCoAuthors = (commits) => {
  if (!Array.isArray(commits)) {
    throw new Error('Pull request commits payload must be an array.');
  }
  return uniqueIdentities(commits.flatMap((commit) => (
    parseCoAuthorTrailers(commit?.commit?.message ?? '')
  )));
};

const pullRequestEvent = (pull, coAuthors) => ({
  type: 'pull_request',
  number: pull.number,
  title: pull.title,
  mergedAt: pull.merged_at,
  url: pull.html_url,
  author: pull.user?.login,
  coAuthors: uniqueIdentities(coAuthors.filter((identity) => identity.toLowerCase() !== String(pull.user?.login ?? '').toLowerCase())),
});

const releaseEvent = (release) => ({
  type: 'release',
  tag: release.tag_name,
  title: release.name?.trim() || release.tag_name,
  publishedAt: release.published_at,
  url: release.html_url,
});

const tagEvent = (tag, publishedAt, url) => ({
  type: 'tag',
  tag: tag.name,
  title: tag.name,
  publishedAt,
  url,
});

export const generateProjectMetadata = async ({
  token,
  repository,
  sourceCommit,
  workflow = 'Deploy KeyQuorum Lab',
  generatedAt = new Date().toISOString(),
  apiBase = DEFAULT_API_BASE,
  fetchImpl = fetch,
} = {}) => {
  if (!token) throw new Error('GITHUB_TOKEN is required to retrieve repository metadata.');
  if (!repository || !repository.includes('/')) {
    throw new Error('GITHUB_REPOSITORY must be set as owner/name.');
  }
  if (!sourceCommit) throw new Error('GITHUB_SHA is required so sourceCommit matches the deployed build.');

  const [owner, repo] = repository.split('/');
  const repoUrl = `${apiBase}/repos/${owner}/${repo}`;
  const { data: repoData } = await githubGetJson(repoUrl, { token, fetchImpl });
  if (!repoData || typeof repoData !== 'object' || Array.isArray(repoData)) {
    throw new Error('GitHub repository payload must be an object.');
  }

  const { data: languageBytes } = await githubGetJson(`${repoUrl}/languages`, { token, fetchImpl });
  const languages = languageBreakdown(languageBytes);

  const closedPulls = await githubGetAllPages(`${repoUrl}/pulls?state=closed&sort=updated&direction=desc&per_page=100`, {
    token,
    fetchImpl,
  });
  const mergedPulls = closedPulls.filter((pull) => typeof pull?.merged_at === 'string' && pull.merged_at);
  const timelinePulls = [];
  for (const pull of mergedPulls) {
    if (!pull?.user?.login || typeof pull.title !== 'string' || typeof pull.html_url !== 'string') {
      throw new Error(`Merged pull request #${pull?.number ?? '?'} is missing required fields.`);
    }
    const commits = await githubGetAllPages(`${repoUrl}/pulls/${pull.number}/commits?per_page=100`, { token, fetchImpl });
    const coAuthors = collectPullRequestCoAuthors(commits);
    let merger = pull.merged_by?.login;
    let mergerType = pull.merged_by?.type;
    if (isBotIdentity(pull.user.login, pull.user.type) && !merger) {
      const { data: detail } = await githubGetJson(`${repoUrl}/pulls/${pull.number}`, { token, fetchImpl });
      merger = detail?.merged_by?.login;
      mergerType = detail?.merged_by?.type;
    }
    const include = shouldIncludeMergedPullRequest({
      mergedAt: pull.merged_at,
      author: pull.user.login,
      authorType: pull.user.type,
      merger,
      mergerType,
      coAuthors,
    });
    if (include) timelinePulls.push(pullRequestEvent(pull, coAuthors));
  }

  const releases = await githubGetAllPages(`${repoUrl}/releases?per_page=100`, { token, fetchImpl });
  const publishedReleases = releases.filter((release) => (
    release && release.draft !== true && typeof release.published_at === 'string' && release.tag_name
  ));
  const releaseTags = new Set(publishedReleases.map((release) => release.tag_name));
  const timelineReleases = publishedReleases.map(releaseEvent);

  const tags = await githubGetAllPages(`${repoUrl}/tags?per_page=100`, { token, fetchImpl });
  const timelineTags = [];
  for (const tag of tags) {
    if (!tag?.name || releaseTags.has(tag.name)) continue;
    const sha = tag.commit?.sha;
    if (!sha) continue;
    const { data: commit } = await githubGetJson(`${apiBase}/repos/${owner}/${repo}/commits/${sha}`, { token, fetchImpl });
    const publishedAt = commit?.commit?.committer?.date ?? commit?.commit?.author?.date;
    if (typeof publishedAt !== 'string') continue;
    timelineTags.push(tagEvent(
      tag,
      publishedAt,
      `https://github.com/${owner}/${repo}/tree/${encodeURIComponent(tag.name)}`,
    ));
  }

  const timeline = [...timelineReleases, ...timelineTags, ...timelinePulls].sort(compareTimelineEvents);

  return assembleProjectMetadata({
    repository: {
      owner: repoData.owner?.login ?? owner,
      name: repoData.name ?? repo,
      defaultBranch: repoData.default_branch ?? 'main',
      url: repoData.html_url ?? `https://github.com/${owner}/${repo}`,
    },
    languages,
    timeline,
    sourceCommit,
    generatedAt,
    workflow,
  });
};
