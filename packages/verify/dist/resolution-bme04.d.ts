type Obj = Record<string, any>;
export declare const BME04_RESOLUTION_VERSION = "EP-RESOLUTION-BME04-v1";
export declare const BME04_CONTEXT_TYPE = "ep.resolution.bme04.v1";
export declare const BME04_SOURCE_REVISION = "draft-morrison-binding-moment-envelope-04";
export declare const BME04_ACTION_MAPPING = "BME04-JCS-ACTION-v1";
export interface Bme04ResolutionOptions {
    acceptedProfile?: string;
    sourceRevision?: string;
    actionMapping?: string;
    bindingMomentJson?: string;
    actionJson?: string;
    principalKeys?: Record<string, Obj>;
    rpId?: string;
    allowedOrigins?: string[];
    expectedNonce?: string;
    expectedInitiator?: string;
    evaluationTime?: string;
}
export declare function computeBme04Digest(rawJson: string): string | null;
/** Raw JSON only: callers must not erase duplicate-member evidence before verification. */
export declare function verifyBme04ResolutionReceipt(receiptJson: string, opts?: Bme04ResolutionOptions): {
    valid: boolean;
    authorizes_action: boolean;
    outcome: string | null;
    requires_successor: boolean;
    checks: Record<string, boolean>;
    reason: string;
} | {
    valid: boolean;
    authorizes_action: boolean;
    outcome: string | null;
    requires_successor: boolean;
    checks: Record<string, boolean>;
};
export {};
//# sourceMappingURL=resolution-bme04.d.ts.map