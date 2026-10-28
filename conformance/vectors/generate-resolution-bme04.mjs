// SPDX-License-Identifier: Apache-2.0
// Synthetic public test key, never a production principal. Run only to regenerate this suite.
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { canonicalize } from '../../packages/verify/index.js';
import { computeBme04Digest, BME04_RESOLUTION_VERSION as PROFILE, BME04_CONTEXT_TYPE as CTX,
  BME04_SOURCE_REVISION as SOURCE, BME04_ACTION_MAPPING as MAPPING } from '../../packages/verify/resolution-bme04.js';
const hash = value => computeBme04Digest(JSON.stringify(value));
const actions = [{disclose:['travel_dates'],recipient:'booking.example'},
  {disclose:['passport_number','travel_dates'],recipient:'booking.example'}];
const envelope = {synopsis:'Share the travel dates and withhold the passport number.',
  findings:['The booking service asks for dates and passport number.','Dates are enough to hold the reservation.','The passport number is only needed at check-in.'],
  recommendations:['Release the travel dates now.','Withhold the passport number until check-in.'],offer:'Ask for detail on any item.',
  question:{stem:'What should be shared with the booking service?',options:[
    {label:'Share dates only',reasoning:'Holds the booking and keeps the passport number private.',action_digest:hash(actions[0])},
    {label:'Share dates and passport number',reasoning:'Avoids a second request at check-in.',action_digest:hash(actions[1])}],
    recommended_idx:0,hatches:{free_text:true,dialogue:true}}};
const publicSeed = crypto.createHash('sha256').update('EMILIA public BME04 conformance fixture key; NOT FOR PRODUCTION').digest();
const ecdh = crypto.createECDH('prime256v1'); ecdh.setPrivateKey(publicSeed); const q=ecdh.getPublicKey();
const privateKey = crypto.createPrivateKey({format:'jwk',key:{kty:'EC',crv:'P-256',d:publicSeed.toString('base64url'),x:q.subarray(1,33).toString('base64url'),y:q.subarray(33).toString('base64url')}});
const publicKey = crypto.createPublicKey(privateKey).export({type:'spki',format:'der'}).toString('base64url');
const principal='ep:principal:bme04-fixture', keyId='ep:key:bme04-fixture', rpId='localhost', origin='https://localhost';
const baseContext={ep_version:'1.0',context_type:CTX,source_revision:SOURCE,action_mapping:MAPPING,
 principal,principal_key_id:keyId,initiator:'spiffe://example.test/agent/1',nonce:'bme04-synthetic-nonce-0001',
 issued_at:'2026-10-26T10:00:00Z',expires_at:'2026-10-26T10:10:00Z',
 resolution:{envelope_digest:hash(envelope),resolution:'option',option_idx:0}};
const options={acceptedProfile:PROFILE,sourceRevision:SOURCE,actionMapping:MAPPING,bindingMomentJson:JSON.stringify(envelope),
 actionJson:JSON.stringify(actions[0]),principalKeys:{[keyId]:{principal,public_key:publicKey}},rpId,allowedOrigins:[origin],
 expectedNonce:baseContext.nonce,expectedInitiator:baseContext.initiator,evaluationTime:'2026-10-26T10:05:00Z'};
function sign(context, signingKey = privateKey, clientMutation = x => x){
 const challenge=crypto.createHash('sha256').update(canonicalize(context)).digest('base64url');
 const client=Buffer.from(clientMutation(JSON.stringify({type:'webauthn.get',challenge,origin})));
 const auth=Buffer.concat([crypto.createHash('sha256').update(rpId).digest(),Buffer.from([5,0,0,0,0])]);
 const signature=crypto.sign(signingKey.asymmetricKeyType === 'ml-dsa-65' ? null : 'sha256',Buffer.concat([auth,crypto.createHash('sha256').update(client).digest()]),signingKey).toString('base64url');
 return {profile:PROFILE,signoff:{'@type':'ep.signoff',context,webauthn:{authenticator_data:auth.toString('base64url'),client_data_json:client.toString('base64url'),signature}}};
}
const vectors=[];
function add(id, mutate=(c)=>{}, valid=false, authority=false, outcome){
 const c={context:structuredClone(baseContext),envelope:structuredClone(envelope),options:structuredClone(options)};
 mutate(c); const receipt=sign(c.context, c.signingKey, c.clientMutation); c.after?.(receipt);
 vectors.push({id,receipt_json:c.rawReceipt??c.rawAfter?.(JSON.stringify(receipt))??JSON.stringify(receipt),options:{...c.options,bindingMomentJson:c.rawEnvelope??JSON.stringify(c.envelope)},expected:{valid,authorizes_action:authority,...(outcome?{outcome}:{})}});
}
add('accept_option',()=>{},true,true,'option');
for(const kind of ['declined','answer','question']) add('accept_'+kind,c=>{c.context.resolution={envelope_digest:hash(c.envelope),resolution:kind,...(kind==='answer'?{answer:'Use a different recipient.'}:{})};delete c.options.actionJson;},true,false,kind);
add('actual_action_mismatch_keeps_evidence',c=>{c.options.actionJson=JSON.stringify(actions[1]);},true,false,'option');
for(const field of ['actionJson','expectedNonce','expectedInitiator','evaluationTime']) add('missing_'+field,c=>{delete c.options[field];},true,false,'option');
for(const field of ['acceptedProfile','sourceRevision','actionMapping']){
 add('missing_'+field,c=>{delete c.options[field];});add('wrong_'+field,c=>{c.options[field]='other';});
}
for(const field of ['source_revision','action_mapping','context_type']) add('signed_wrong_'+field,c=>{c.context[field]='other';});
add('outer_profile_relabel',c=>{c.after=r=>r.profile='EP-RESOLUTION-v1';});
add('unsigned_context_type_tamper',c=>{c.after=r=>r.signoff.context.context_type='ep.resolution.v1';});
add('unsigned_outcome_tamper',c=>{c.after=r=>r.signoff.context.resolution.option_idx=1;});
add('malformed_signature',c=>{c.after=r=>r.signoff.webauthn.signature='AAAA';});
add('wrong_principal_pin',c=>{c.options.principalKeys[keyId].principal='ep:principal:other';});
add('missing_key_pin',c=>{c.options.principalKeys={};});
add('wrong_key_pin',c=>{c.options.principalKeys[keyId].public_key='AAAA';});
add('wrong_rp',c=>{c.options.rpId='other.example';});
add('wrong_origin',c=>{c.options.allowedOrigins=['https://other.example'];});
for(const field of ['rpId','allowedOrigins']) add('missing_'+field,c=>{delete c.options[field];});
add('wrong_nonce_replay_context',c=>{c.options.expectedNonce='fresh-next-ceremony';});
add('wrong_initiator',c=>{c.options.expectedInitiator='spiffe://example.test/agent/other';});
add('expired',c=>{c.options.evaluationTime='2026-10-26T11:00:00Z';});
add('future',c=>{c.options.evaluationTime='2026-10-26T09:59:59Z';});
add('impossible_calendar',c=>{c.context.issued_at='2026-02-30T10:00:00Z';});
add('reversed_window',c=>{c.context.expires_at='2026-10-26T09:00:00Z';});
add('missing_option_digest',c=>{delete c.envelope.question.options[0].action_digest;c.context.resolution.envelope_digest=hash(c.envelope);});
add('malformed_unselected_digest',c=>{c.envelope.question.options[1].action_digest='sha256:ABC';c.context.resolution.envelope_digest=hash(c.envelope);});
add('substituted_envelope_digest',c=>{c.envelope.question.options[0].action_digest=hash(actions[1]);});
add('signed_index_action_mismatch',c=>{c.context.resolution.option_idx=1;},true,false,'option');
add('signed_substituted_digest_withholds_authority',c=>{c.envelope.question.options[0].action_digest=hash(actions[1]);c.context.resolution.envelope_digest=hash(c.envelope);},true,false,'option');
add('unknown_option_member',c=>{c.envelope.question.options[0].extra=true;c.context.resolution.envelope_digest=hash(c.envelope);});
for(const field of ['option_idx','action_digest','answer'])add('decline_with_'+field,c=>{c.context.resolution={envelope_digest:hash(c.envelope),resolution:'declined',[field]:field==='option_idx'?0:'value'};});
add('decline_other_envelope',c=>{c.context.resolution={envelope_digest:'sha256:'+'f'.repeat(64),resolution:'declined'};});
add('missing_decline_envelope',c=>{c.context.resolution={resolution:'declined'};});
add('disabled_answer_hatch',c=>{c.envelope.question.hatches.free_text=false;c.context.resolution={envelope_digest:hash(c.envelope),resolution:'answer',answer:'alternative'};});
add('disabled_question_hatch',c=>{c.envelope.question.hatches.dialogue=false;c.context.resolution={envelope_digest:hash(c.envelope),resolution:'question'};});
add('out_of_range_index',c=>{c.context.resolution.option_idx=2;});
add('negative_index',c=>{c.context.resolution.option_idx=-1;});
add('boolean_index',c=>{c.context.resolution.option_idx=true;});
add('unknown_native_resolution',c=>{c.context.resolution.resolution='approved';});
add('duplicate_envelope_member',c=>{c.rawEnvelope=JSON.stringify(c.envelope).replace('"synopsis":','"synopsis":"duplicate","synopsis":');});
add('escaped_duplicate_option_member',c=>{c.rawEnvelope=JSON.stringify(c.envelope).replace('"label":','"la\\u0062el":"duplicate","label":');});
add('duplicate_action_member',c=>{c.options.actionJson='{"recipient":"a","recipient":"b"}';});
add('duplicate_receipt_member',c=>{c.rawReceipt='{"profile":"x","profile":"y"}';});
add('unpaired_surrogate_envelope',c=>{c.rawEnvelope=JSON.stringify(c.envelope).replace('"offer":','"offer":"\\ud800","old_offer":');});
add('unpaired_surrogate_action',c=>{c.options.actionJson='{"x":"\\udc00"}';});
add('fractional_action',c=>{c.options.actionJson='{"x":0.5}';});
add('rounded_fraction_action',c=>{c.options.actionJson='{"x":1.00000000000000001}';});
add('rounded_underflow_action',c=>{c.options.actionJson='{"x":1e-1000}';});
add('unsafe_integer_action',c=>{c.options.actionJson='{"x":9007199254740993}';});
add('too_deep_action',c=>{c.options.actionJson='{"x":'+ '['.repeat(65)+'0'+']'.repeat(65)+'}';});
for(const numeric of ['1.0','1e0','10e-1','-0'])add('exact_integer_'+numeric,c=>{const a={quantity:Number(numeric)};c.options.actionJson='{"quantity":'+numeric+'}';c.envelope.question.options[0].action_digest=hash(a);c.context.resolution.envelope_digest=hash(c.envelope);},true,true,'option');
add('utf16_key_order',c=>{const a={'\ue000':1,'\ud800\udc00':2};c.options.actionJson=JSON.stringify(a);c.envelope.question.options[0].action_digest=hash(a);c.context.resolution.envelope_digest=hash(c.envelope);},true,true,'option');
add('no_unicode_normalization',c=>{const a={'e\u0301':'decomposed','é':'composed'};c.options.actionJson=JSON.stringify(a);c.envelope.question.options[0].action_digest=hash(a);c.context.resolution.envelope_digest=hash(c.envelope);},true,true,'option');
for(const field of ['authenticator_data','client_data_json','signature']) {
 for (const ending of ['=', '\n', '!'])add('noncanonical_'+field+'_'+JSON.stringify(ending),c=>{c.after=r=>r.signoff.webauthn[field]+=ending;});
}
add('noncanonical_key_pin',c=>{c.options.principalKeys[keyId].public_key+='=';});
add('signed_duplicate_client_challenge',c=>{c.clientMutation=raw=>raw.replace('"challenge":','"challenge":"x","challenge":');});
add('signed_client_surrogate',c=>{c.clientMutation=raw=>raw.replace(/^\{/,'{"extra":"\\ud800",');});
add('signed_client_fraction',c=>{c.clientMutation=raw=>raw.replace(/^\{/,'{"extra":1.00000000000000001,');});
add('signed_client_cross_origin',c=>{c.clientMutation=raw=>raw.replace(/^\{/,'{"crossOrigin":true,');});
add('signed_client_wrong_origin',c=>{c.clientMutation=raw=>raw.replace(origin,'https://other.example');});
// Time restrictions avoid language-dependent truncation and ambiguous offsets.
for (const [id, field, value] of [
 ['submillisecond_issued','issued_at','2026-10-26T10:00:00.0009Z'],
 ['submillisecond_expiry','expires_at','2026-10-26T10:10:00.0009Z'],
 ['year_zero','issued_at','0000-01-01T00:00:00Z'],
 ['unknown_offset','issued_at','2026-10-26T10:00:00-00:00'],
 ['invalid_offset_hour','issued_at','2026-10-26T10:00:00+24:00'],
 ['invalid_offset_minute','issued_at','2026-10-26T10:00:00+00:60'],
 ['invalid_month','issued_at','2026-13-01T10:00:00Z'],
 ['invalid_hour','issued_at','2026-10-26T24:00:00Z'],
 ['leap_second','issued_at','2026-10-26T10:00:60Z'],
 ['timestamp_trailing_lf','issued_at','2026-10-26T10:00:00Z\n'],
]) add(id,c=>{c.context[field]=value;});
for (const at of ['2026-10-26T10:00:00.0001Z','2026-10-26T10:10:00.0001Z'])
 add('submillisecond_evaluation_'+at,c=>{c.options.evaluationTime=at;});
add('millisecond_before_issue',c=>{c.context.issued_at='2026-10-26T10:00:00.001Z';c.options.evaluationTime='2026-10-26T10:00:00.000Z';});
add('millisecond_after_expiry',c=>{c.options.evaluationTime='2026-10-26T10:10:00.001Z';});
add('millisecond_at_issue',c=>{c.context.issued_at='2026-10-26T10:00:00.001Z';c.options.evaluationTime='2026-10-26T10:00:00.001Z';},true,true,'option');
add('millisecond_at_expiry',c=>{c.context.expires_at='2026-10-26T10:10:00.001Z';c.options.evaluationTime='2026-10-26T10:10:00.001Z';},true,true,'option');
add('equivalent_numeric_offset',c=>{c.context.issued_at='2026-10-26T12:00:00+02:00';},true,true,'option');
for(const ending of ['\n','\r\n']) add('unselected_digest_trailing_'+JSON.stringify(ending),c=>{c.envelope.question.options[1].action_digest+=ending;c.context.resolution.envelope_digest=hash(c.envelope);});
for(const member of ['nonce','option_idx','signature'])add('duplicate_nested_'+member,c=>{c.rawAfter=raw=>raw.replace('"'+member+'":','"'+member+'":null,"'+member+'":');});
for(const field of ['expectedNonce','expectedInitiator','evaluationTime'])add('empty_'+field,c=>{c.options[field]='';});
add('rounded_recommended_index',c=>{c.rawEnvelope=JSON.stringify(c.envelope).replace('"recommended_idx":0','"recommended_idx":0.000000000000000000001');});
add('rounded_resolution_index',c=>{c.rawAfter=raw=>raw.replace('"option_idx":0','"option_idx":0.000000000000000000001');});
add('answer_missing_text',c=>{c.context.resolution={envelope_digest:hash(c.envelope),resolution:'answer'};});
add('question_with_index',c=>{c.context.resolution={envelope_digest:hash(c.envelope),resolution:'question',option_idx:0};});
add('option_with_answer',c=>{c.context.resolution.answer='extra';});
// Correctly signed but outside this profile's explicitly closed P-256 algorithm.
const p384 = crypto.generateKeyPairSync('ec',{namedCurve:'secp384r1'});
add('signed_p384_refused',c=>{c.signingKey=p384.privateKey;c.options.principalKeys[keyId].public_key=p384.publicKey.export({type:'spki',format:'der'}).toString('base64url');});
// The Ed25519 SPKI is a second valid key type which must never enter ES256.
const ed25519 = crypto.generateKeyPairSync('ed25519');
add('ed25519_key_refused',c=>{c.options.principalKeys[keyId].public_key=ed25519.publicKey.export({type:'spki',format:'der'}).toString('base64url');});
// Requires Node with ML-DSA support only when regenerating these fixtures.
const pq=crypto.generateKeyPairSync('ml-dsa-65');
add('signed_mldsa65_refused',c=>{c.signingKey=pq.privateKey;c.options.principalKeys[keyId].public_key=pq.publicKey.export({type:'spki',format:'der'}).toString('base64url');});
const digestBoundaries = [
 {id:'depth_64_containers',kind:'depth',count:63,valid:true},
 {id:'depth_65_containers',kind:'depth',count:64,valid:false},
 {id:'node_count_100000',kind:'nodes',count:99998,valid:true},
 {id:'node_count_100001',kind:'nodes',count:99999,valid:false},
 {id:'raw_bytes_1048576',kind:'bytes',count:1048576,valid:true},
 {id:'raw_bytes_1048577',kind:'bytes',count:1048577,valid:false},
].map(({valid,...c})=>{
 const raw=c.kind==='depth'?'{"a":'+'['.repeat(c.count)+']'.repeat(c.count)+'}':
   c.kind==='nodes'?'{"a":['+Array(c.count).fill('0').join(',')+']}':
   '{"a":"'+'x'.repeat(c.count-8)+'"}';
 // These constructed bytes are already canonical, so this assertion is
 // independent of the implementation's parse/canonicalize helper.
 return {...c,digest:valid?'sha256:'+crypto.createHash('sha256').update(raw).digest('hex'):null};
});
const suite={profile:PROFILE,source:{url:'https://www.ietf.org/archive/id/draft-morrison-binding-moment-envelope-04.txt',sha256:'94ffe86a54ac0d869fd4e97cece67b12d2a1d556f00fd6b20b307ef1ee03a5ef'},
 canonicalization:[{id:'upstream_action_1',json:JSON.stringify(actions[0]),digest:'sha256:ff91e3166e64b892004d4b43b05ad6ed7ff0819463da80c72f27f47039c033fa'},
 {id:'upstream_action_2',json:JSON.stringify(actions[1]),digest:'sha256:49be14ae6e74b950c0c7b790fa22538d45fb4853bb0f3b242b28204bee232945'},
 {id:'upstream_envelope',json:JSON.stringify(envelope),digest:'sha256:0db384ab1b682c115d79babfefa91f014ad80c007d00c79119d748f32be232d1',canonical_bytes:895}],digest_boundaries:digestBoundaries,vectors};
writeFileSync(new URL('./resolution.bme04.v1.json',import.meta.url),JSON.stringify(suite,null,2)+'\n');console.log(vectors.length+' vectors');
