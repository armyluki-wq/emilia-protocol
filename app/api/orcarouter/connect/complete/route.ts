/**
 * /api/orcarouter/connect/complete
 *
 * POST { attempt_id, code, state? }
 *
 * @license Apache-2.0
 *
 * Exchanges the code displayed by the consent screen and persists the durable
 * OrcaRouter key returned by the AUTH origin. The response is masked; the key
 * never reaches the browser.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { getOrcaRouterEnv } from '@/lib/env';
import { resolveOrcaRouterOrigins } from '@/lib/providers/orcarouter';
import {
  completeOrcaRouterAuthorization,
  OrcaRouterPkceError,
} from '@/lib/providers/orcarouter-pkce';
import { ORCAROUTER_MASKED_KEY, saveOrcaRouterPkceKey } from '@/lib/providers/orcarouter-credentials';
import { NO_STORE, crossOriginRefused, providerAdminDisabled, readJsonBody } from '../../_shared';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

const STATUS_BY_CODE: Record<string, number> = {
  invalid_request: 400,
  unknown_attempt: 404,
  expired: 410,
  state_mismatch: 400,
  code_rejected: 403,
  scope_not_granted: 403,
  rate_limited: 429,
  network_error: 502,
  server_error: 502,
  invalid_grant_response: 502,
};

export async function POST(request: NextRequest): Promise<NextResponse> {
  const disabled = providerAdminDisabled();
  if (disabled) return disabled;
  const crossOrigin = crossOriginRefused(request);
  if (crossOrigin) return crossOrigin;

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return parsed.response;
  const attemptId = parsed.value?.attempt_id;
  const code = parsed.value?.code;
  const state = parsed.value?.state;
  if (typeof attemptId !== 'string' || !attemptId) {
    return epProblem(400, 'invalid_request', 'attempt_id is required');
  }

  try {
    const origins = resolveOrcaRouterOrigins(getOrcaRouterEnv());
    const completed = await completeOrcaRouterAuthorization({
      origins,
      attemptId,
      code,
      state: typeof state === 'string' ? state : null,
      save: async (key, scope) => {
        const status = await saveOrcaRouterPkceKey(key, scope);
        return {
          masked: status.masked ?? ORCAROUTER_MASKED_KEY,
          generation: status.generation || '',
        };
      },
    });
    return NextResponse.json({ credential: completed }, { headers: NO_STORE });
  } catch (error) {
    if (error instanceof OrcaRouterPkceError) {
      return epProblem(STATUS_BY_CODE[error.code] || 502, error.code, error.message);
    }
    return epProblem(502, 'connect_failed', 'The OrcaRouter connection could not be completed');
  }
}
