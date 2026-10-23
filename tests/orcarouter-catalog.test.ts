// SPDX-License-Identifier: Apache-2.0
//
// Catalog fixtures for the OrcaRouter Cyber Inference selector. One mixed
// provider response is reused across every capability, because the failure this
// guards against is a model appearing under a capability it cannot serve — a
// free-text field or a name heuristic would happily offer all of them.

import { describe, it, expect, vi, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  ORCAROUTER_MAX_CATALOG_ITEMS,
  discoverOrcaRouterModels,
  resetOrcaRouterCatalogCache,
} from '../lib/providers/orcarouter.js';

const envWithKey = {
  apiKey: null,
  authBaseOverride: null,
  apiBaseOverride: null,
  sharedBaseOverride: null,
  modelOverride: null,
  stateDir: null,
  settingsSurfaceEnabled: false,
};

const credential = { key: 'sk-orca-catalogkey123456789', generation: 'test', source: 'api_key' as const };

const MIXED = [
  {
    id: 'acme/text-chat',
    name: 'Acme Chat',
    context_length: 200000,
    architecture: { input_modalities: ['text'], output_modalities: ['text'] },
    supported_endpoint_types: ['openai', 'anthropic'],
  },
  {
    id: 'acme/vision-chat',
    name: 'Acme Vision',
    context_length: 100000,
    architecture: { input_modalities: ['text', 'image', 'file'], output_modalities: ['text'] },
    supported_endpoint_types: ['openai'],
  },
  {
    id: 'acme/no-modalities-chat',
    name: 'Acme Unstated',
    architecture: {},
    supported_endpoint_types: ['openai-response'],
  },
  {
    id: 'acme/embed',
    name: 'Acme Embed',
    architecture: { input_modalities: ['text'], output_modalities: [] },
    supported_endpoint_types: ['embeddings'],
  },
  {
    id: 'acme/text-to-image',
    name: 'Acme Image',
    architecture: { input_modalities: ['text'], output_modalities: ['image'] },
    supported_endpoint_types: ['image-generation'],
  },
  {
    id: 'acme/video',
    name: 'Acme Video',
    architecture: { input_modalities: ['text', 'image'], output_modalities: ['video'] },
    supported_endpoint_types: ['openai-video'],
  },
  {
    id: 'acme/rerank',
    name: 'Acme Rerank',
    architecture: { input_modalities: ['text'], output_modalities: [] },
    supported_endpoint_types: ['jina-rerank'],
  },
  {
    id: 'acme/image-only-output',
    name: 'Acme Mislabeled',
    architecture: { input_modalities: ['text'], output_modalities: ['image'] },
    supported_endpoint_types: ['openai'],
  },
  {
    id: 'acme/unknown-endpoint',
    name: 'Acme Unknown',
    architecture: { input_modalities: ['text'], output_modalities: ['text'] },
    supported_endpoint_types: ['mystery-endpoint'],
  },
];

const stateDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'orca-catalog-'));
const liveFetch = () => (async () => new Response(JSON.stringify({ data: MIXED }), {
  status: 200,
  headers: { 'content-type': 'application/json' },
})) as any;
const failFetch = () => (async () => new Response('', { status: 500 })) as any;

afterEach(() => {
  resetOrcaRouterCatalogCache();
  vi.restoreAllMocks();
});

describe('OrcaRouter catalog fixtures', () => {
  it('selects exactly the text-capable chat entries', async () => {
    const catalog = await discoverOrcaRouterModels({
      env: envWithKey, credential, fetchImpl: liveFetch(), stateDir: stateDir(), useCache: false,
    });
    expect(catalog.models.map((entry) => entry.id)).toEqual([
      'acme/text-chat',
      'acme/vision-chat',
      'acme/no-modalities-chat',
    ]);
  });

  it('selects exactly the image-capable chat entries when image input is required', async () => {
    const catalog = await discoverOrcaRouterModels({
      env: envWithKey, credential, modality: 'image', fetchImpl: liveFetch(), stateDir: stateDir(), useCache: false,
    });
    expect(catalog.models.map((entry) => entry.id)).toEqual(['acme/vision-chat']);
  });

  it('routes non-chat capabilities to their exact endpoint only', async () => {
    const cases = [
      ['embedding', ['acme/embed']],
      ['image', ['acme/text-to-image']],
      ['video', ['acme/video']],
      ['rerank', ['acme/rerank']],
    ] as const;
    for (const [capability, expected] of cases) {
      resetOrcaRouterCatalogCache();
      const catalog = await discoverOrcaRouterModels({
        env: envWithKey, credential, capability, fetchImpl: liveFetch(), stateDir: stateDir(), useCache: false,
      });
      expect(catalog.models.map((entry) => entry.id)).toEqual(expected);
      expect(catalog.catalog_source).toContain(`capability=${capability}`);
    }
  });

  it('rejects entries with unknown endpoints and unusable ids', async () => {
    const catalog = await discoverOrcaRouterModels({
      env: envWithKey,
      credential,
      fetchImpl: (async () => new Response(JSON.stringify({
        data: [
          ...MIXED,
          { id: '', supported_endpoint_types: ['openai'] },
          { id: '../escape', supported_endpoint_types: ['openai'] },
          { id: 'acme/' + 'x'.repeat(300), supported_endpoint_types: ['openai'] },
          null,
        ],
      }), { status: 200 })) as any,
      stateDir: stateDir(),
      useCache: false,
    });
    expect(catalog.models.map((entry) => entry.id)).toEqual([
      'acme/text-chat',
      'acme/vision-chat',
      'acme/no-modalities-chat',
    ]);
  });

  it('caps the number of catalog items it will process', async () => {
    const flood = Array.from({ length: ORCAROUTER_MAX_CATALOG_ITEMS + 50 }, (_, index) => ({
      id: `acme/model-${index}`,
      architecture: { input_modalities: ['text'], output_modalities: ['text'] },
      supported_endpoint_types: ['openai'],
    }));
    const catalog = await discoverOrcaRouterModels({
      env: envWithKey,
      credential,
      fetchImpl: (async () => new Response(JSON.stringify({ data: flood }), { status: 200 })) as any,
      stateDir: stateDir(),
      useCache: false,
    });
    expect(catalog.models).toHaveLength(ORCAROUTER_MAX_CATALOG_ITEMS);
  });

  it('uses this deployment’s last-known-good catalog before the seed', async () => {
    const dir = stateDir();
    const first = await discoverOrcaRouterModels({
      env: envWithKey, credential, fetchImpl: liveFetch(), stateDir: dir, useCache: true,
    });
    expect(first.source).toBe('live');
    expect(fs.existsSync(path.join(dir, 'catalog-chat.json'))).toBe(true);

    resetOrcaRouterCatalogCache();
    const second = await discoverOrcaRouterModels({
      env: envWithKey, credential, fetchImpl: failFetch(), stateDir: dir, useCache: true,
    });
    expect(second.source).toBe('last-known-good');
    expect(second.degraded).toBe(true);
    expect(second.models.map((entry) => entry.id)).toEqual(first.models.map((entry) => entry.id));
    expect(second.models.some((entry) => entry.verified_seed)).toBe(false);
  });

  it('ignores last-known-good when caching is disabled, so degradation is explicit', async () => {
    const dir = stateDir();
    await discoverOrcaRouterModels({
      env: envWithKey, credential, fetchImpl: liveFetch(), stateDir: dir, useCache: true,
    });
    resetOrcaRouterCatalogCache();
    const degraded = await discoverOrcaRouterModels({
      env: envWithKey, credential, fetchImpl: failFetch(), stateDir: dir, useCache: false,
    });
    expect(degraded.source).toBe('seed');
  });

  it('bounds an oversized response and reports a distinct reason', async () => {
    const huge = new Response('x', {
      status: 200,
      headers: { 'content-length': String(10 * 1024 * 1024) },
    });
    const catalog = await discoverOrcaRouterModels({
      env: envWithKey, credential, fetchImpl: (async () => huge) as any, stateDir: stateDir(), useCache: false,
    });
    expect(catalog.source).toBe('seed');
    expect(catalog.error).toBe('catalog_too_large');
  });

  it('reports a timeout distinctly from a generic network failure', async () => {
    const abort = Object.assign(new Error('aborted'), { name: 'AbortError' });
    const catalog = await discoverOrcaRouterModels({
      env: envWithKey, credential, fetchImpl: (async () => { throw abort; }) as any, stateDir: stateDir(), useCache: false,
    });
    expect(catalog.error).toBe('catalog_timeout');
    expect(catalog.models.length).toBeGreaterThan(0);
  });
});
