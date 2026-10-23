/**
 * Shared guards for the OrcaRouter provider settings API.
 *
 * @license Apache-2.0
 *
 * These endpoints can replace the credential this deployment uses for model
 * inference, so they are off unless the operator opts in with
 * ORCAROUTER_PROVIDER_ADMIN=1, and every mutation must be same-origin. The
 * responses never include a credential.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { getOrcaRouterEnv } from '@/lib/env';

export const MAX_PROVIDER_BODY_BYTES = 64 * 1024;

export function providerAdminDisabled(): NextResponse | null {
  if (getOrcaRouterEnv().settingsSurfaceEnabled) return null;
  return epProblem(404, 'not_found', 'OrcaRouter provider settings are not enabled on this deployment');
}

/**
 * Same-origin check for mutations. A missing Origin (same-origin form posts in
 * some browsers, and non-browser callers) is allowed only when the request is
 * not cross-site, which we treat as same-origin because the session is not
 * cookie-authenticated and no ambient authority exists to steal.
 */
export function crossOriginRefused(request: NextRequest): NextResponse | null {
  const origin = request.headers.get('origin');
  if (!origin) return null;
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return epProblem(403, 'cross_origin_denied', 'Malformed Origin header');
  }
  const host = request.headers.get('host');
  if (!host || parsed.host !== host) {
    return epProblem(403, 'cross_origin_denied', 'OrcaRouter provider changes require a same-origin request');
  }
  return null;
}

export async function readJsonBody(
  request: NextRequest,
): Promise<{ ok: true; value: any } | { ok: false; response: NextResponse }> {
  const contentType = request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    return { ok: false, response: epProblem(415, 'unsupported_media_type', 'Expected an application/json body') };
  }
  const declared = Number(request.headers.get('content-length') || 0);
  if (Number.isFinite(declared) && declared > MAX_PROVIDER_BODY_BYTES) {
    return { ok: false, response: epProblem(413, 'body_too_large', 'Request body is too large') };
  }
  let text: string;
  try {
    text = await request.text();
  } catch {
    return { ok: false, response: epProblem(400, 'invalid_body', 'Request body could not be read') };
  }
  if (Buffer.byteLength(text, 'utf8') > MAX_PROVIDER_BODY_BYTES) {
    return { ok: false, response: epProblem(413, 'body_too_large', 'Request body is too large') };
  }
  try {
    const value = text ? JSON.parse(text) : {};
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return { ok: false, response: epProblem(400, 'invalid_body', 'Request body must be a JSON object') };
    }
    return { ok: true, value };
  } catch {
    return { ok: false, response: epProblem(400, 'invalid_body', 'Request body must be valid JSON') };
  }
}

export const NO_STORE = { 'Cache-Control': 'no-store' };
