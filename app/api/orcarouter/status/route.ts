/**
 * GET /api/orcarouter/status
 *
 * @license Apache-2.0
 *
 * Credential and origin status for the OrcaRouter provider panel. Returns a
 * masked indicator only: the key never leaves the server.
 */

import { NextResponse } from 'next/server';
import { getOrcaRouterEnv } from '@/lib/env';
import {
  ORCAROUTER_CYBER_MODELS,
  ORCAROUTER_DEFAULT_MODEL,
  ORCAROUTER_DISPLAY_NAME,
  ORCAROUTER_FALLBACK_MODEL,
  ORCAROUTER_PROVIDER_ID,
  resolveOrcaRouterOrigins,
} from '@/lib/providers/orcarouter';
import {
  getOrcaRouterModel,
  orcaRouterCredentialStatus,
} from '@/lib/providers/orcarouter-credentials';
import { NO_STORE, providerAdminDisabled } from '../_shared';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function GET(): Promise<NextResponse> {
  const disabled = providerAdminDisabled();
  if (disabled) return disabled;

  let credential;
  let origins;
  try {
    credential = await orcaRouterCredentialStatus();
    origins = resolveOrcaRouterOrigins(getOrcaRouterEnv());
  } catch (error: any) {
    // Origin misconfiguration is an operator error, not a client error.
    return NextResponse.json(
      { error: 'provider_misconfigured', detail: String(error?.message || 'invalid OrcaRouter configuration') },
      { status: 503, headers: NO_STORE },
    );
  }

  return NextResponse.json({
    provider: ORCAROUTER_PROVIDER_ID,
    display_name: ORCAROUTER_DISPLAY_NAME,
    credential,
    origins,
    models: {
      default: ORCAROUTER_DEFAULT_MODEL,
      cyber: [...ORCAROUTER_CYBER_MODELS],
      fallback: ORCAROUTER_FALLBACK_MODEL,
      selected: await getOrcaRouterModel(),
    },
    catalog_source: `${origins.api}/models?capability=chat`,
    docs: {
      provider_page: 'https://www.orcarouter.ai/cyber',
      cyber_models: 'https://www.orcarouter.ai/models?tier=cyber',
    },
  }, { headers: NO_STORE });
}
