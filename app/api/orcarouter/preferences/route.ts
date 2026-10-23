/**
 * /api/orcarouter/preferences
 *
 * GET   current model selection
 * POST  { model } — only a model that is currently in the compatible catalog
 *
 * @license Apache-2.0
 *
 * Validation re-reads the catalog rather than trusting the client. When the
 * catalog is unreachable the API refuses the change; a stale or invented model
 * id must never be persisted.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { discoverOrcaRouterModels } from '@/lib/providers/orcarouter';
import {
  getOrcaRouterModel,
  resolveOrcaRouterCredential,
  setOrcaRouterModel,
} from '@/lib/providers/orcarouter-credentials';
import { NO_STORE, crossOriginRefused, providerAdminDisabled, readJsonBody } from '../_shared';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function GET(): Promise<NextResponse> {
  const disabled = providerAdminDisabled();
  if (disabled) return disabled;
  return NextResponse.json({ model: await getOrcaRouterModel() }, { headers: NO_STORE });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const disabled = providerAdminDisabled();
  if (disabled) return disabled;
  const crossOrigin = crossOriginRefused(request);
  if (crossOrigin) return crossOrigin;

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return parsed.response;
  const model = parsed.value?.model;
  if (typeof model !== 'string' || !model) {
    return epProblem(400, 'invalid_model', 'model is required');
  }

  const credential = await resolveOrcaRouterCredential();
  if (!credential.ok) {
    return epProblem(credential.reason === 'needs_reauth' ? 409 : 401, credential.reason,
      'Configure an OrcaRouter credential before choosing a model');
  }
  const catalog = await discoverOrcaRouterModels({ capability: 'chat', credential });
  // A degraded catalog is a seed or last-known-good list. It may keep the
  // selector usable, but it must not become a persisted choice: only a model
  // verified against the live catalog may be stored.
  if (catalog.degraded) {
    return epProblem(503, 'catalog_unavailable', 'Cannot verify the model against the live catalog right now');
  }
  if (!catalog.models.some((entry) => entry.id === model)) {
    return epProblem(400, 'incompatible_model', 'The selected model is not in the current chat catalog');
  }

  try {
    const settings = await setOrcaRouterModel(model);
    return NextResponse.json(settings, { headers: NO_STORE });
  } catch {
    return epProblem(503, 'preferences_write_failed', 'Could not store the model selection');
  }
}
