# Stake.com GraphQL API — Full Security Assessment Findings

**Researcher:** Bhupender Kumar (rajus9231@gmail.com)
**Date:** May 22, 2026
**Target:** https://stake.com/_api/graphql
**PoC:** https://bhupenderkumar.github.io/stake-security-poc/

---

## FINDING 1: CORS Misconfiguration — Wildcard Origin with Credentials [CRITICAL]

**CORS Headers (verified May 22, 2026):**
```
Access-Control-Allow-Origin: *
access-control-allow-credentials: true
access-control-allow-headers: content-type, x-access-token
access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE
```

**Impact:**
- ANY website can query Stake.com's GraphQL API
- Custom `x-access-token` authentication header is explicitly allowed cross-origin
- Per RFC 6454 and the CORS spec, `Access-Control-Allow-Origin: *` with `access-control-allow-credentials: true` is a dangerous misconfiguration
- Combined with the `x-access-token` header allowance, a stolen session token can be used from any origin

---

## FINDING 2: Cross-Origin IP Address Theft — No Auth Required [CRITICAL]

**Query:** `{ ipAddress }` — returns visitor's real IP with NO authentication.

**Verified Response:**
```json
{"data":{"ipAddress":"163.116.199.202"}}
```

**Impact:**
- ANY website can silently steal a visitor's real IP
- IP is PII under GDPR Article 4(1) / Recital 30
- Enables VPN/Tor deanonymization
- Enables geolocation tracking

---

## FINDING 3: User Enumeration via GraphQL [HIGH]

**Query:** `{ user(name: "<username>") { id name createdAt } }`

**Verified Results — 20/20 usernames resolved (100% success rate):**

| # | Username | User ID (UUID) | Account Created |
|---|----------|---------------|-----------------|
| 1 | admin | `3c36bb00-7770-4f28-ab19-83a6860fe8ae` | Wed, 02 Aug 2017 04:43:51 GMT |
| 2 | Support | `de4750df-a8b4-4cca-926a-cb123d23c6f6` | Thu, 03 Aug 2017 09:57:45 GMT |
| 3 | stake | `4df8ddca-0bab-48a2-be27-19883d584622` | Wed, 02 Aug 2017 02:27:46 GMT |
| 4 | Eddie | `4fdfcbbe-f56e-4e88-a703-fdcf92ca026f` | Mon, 04 Sep 2017 23:25:18 GMT |
| 5 | Drake | `2f0b2d72-bca4-4f22-86f8-ae7b8498338f` | Mon, 11 Sep 2017 04:41:33 GMT |
| 6 | Rodiium | `9fe89874-81b7-484b-b688-b60fc0f723eb` | Tue, 24 Nov 2020 11:03:48 GMT |
| 7 | Badebhaiya77 | `57edc195-883a-4ea2-95e0-6f4eb4f977db` | Thu, 20 Mar 2025 16:55:14 GMT |
| 8 | GWL10000 | `60eea4a9-ce2b-48ed-a72a-ffd50beecd99` | Fri, 05 Dec 2025 03:44:29 GMT |
| 9 | Arabicansut | `ceaeee9f-b8f3-4c8b-8541-77deedd60faa` | Fri, 30 Jan 2026 18:47:06 GMT |
| 10 | 10111821 | `ae4cd256-11a0-4356-aaef-0b0d28e8b42c` | Fri, 18 Oct 2024 08:32:36 GMT |
| 11 | ucwnono | `fd078835-8791-499d-96ab-6802bfbc8add` | Fri, 06 Nov 2020 18:24:45 GMT |
| 12 | Umang1965 | `b7bb82ff-55cb-4dab-b4f8-bd906d129452` | Tue, 30 Apr 2024 13:00:59 GMT |
| 13 | test | `a2031adc-78b5-4d78-a83d-c023a27ca252` | Thu, 10 Aug 2017 15:27:25 GMT |
| 14 | Moderator | `096a140b-3256-4c95-8bb8-692b6e5da04f` | Wed, 02 Aug 2017 04:46:40 GMT |
| 15 | vip | `eec0da38-e352-415c-b606-f2a16fd1479e` | Sat, 26 Aug 2017 19:17:54 GMT |
| 16 | Whale | `e89d9015-2ef2-4645-a37d-561670aa180c` | Fri, 11 Aug 2017 06:12:04 GMT |
| 17 | staff | `b3b4c225-f281-45d5-8f5c-0bed597ca999` | Tue, 22 Oct 2019 19:54:49 GMT |
| 18 | security | `6ce98426-770b-4cce-a0a6-fc9c89c118b0` | Sun, 15 Oct 2017 17:54:21 GMT |
| 19 | Ceo | `f1daa7ed-3c2b-43e5-8769-a7b5f5fc0a41` | Sat, 20 Apr 2019 00:54:22 GMT |
| 20 | Developer | `47570c5d-ffab-496c-9366-91b0a2aa5ea4` | Wed, 17 Apr 2019 01:37:40 GMT |

**Impact:**
- 20/20 usernames tested resolved to real accounts (100% success rate)
- Critical platform accounts exposed: admin, Support, Moderator, staff, security, Ceo, Developer
- UUIDs enable targeted IDOR attacks and privilege escalation attempts
- Account creation dates reveal platform internals (earliest: Aug 2, 2017)
- No rate limiting observed — attacker can enumerate ALL platform users at scale
- All data accessible cross-origin without any authentication

---

## FINDING 4: Session Data Leaks IP + Geolocation [HIGH]

**Query:** `{ user { sessionList { id ip country city updatedAt } } }`

**Verified Response:**
```json
{
  "sessionList": [{
    "id": "0d8f9b96-c948-4de0-9594-5ba32099f662",
    "ip": "163.116.199.202",
    "country": "IN",
    "city": "Gharroli",
    "updatedAt": "Fri, 22 May 2026 05:37:34 GMT"
  }]
}
```

**Impact:** With x-access-token, attacker gets full session history including IPs, cities, and countries.

---

## FINDING 5: Authenticated Data Extraction via x-access-token [CRITICAL]

**The session cookie is NOT HttpOnly** — accessible via `document.cookie`.
**The token = session cookie value** — sent as `x-access-token` header.
**CORS allows x-access-token from any origin.**

**Extracted user data with token:**
```json
{
  "id": "4784245c-4d99-4bd2-a42c-1e3d003d6594",
  "name": "bhupek",
  "email": "rajus9231@gmail.com",
  "createdAt": "Fri, 22 May 2026 05:37:33 GMT",
  "dob": null,
  "kycStatus": null,
  "hasTfaEnabled": false,
  "hasEmailVerified": true,
  "flags": [],
  "roles": [],
  "rakeback": {"enabled": false}
}
```

Plus 80+ wallet balances across all currencies (BTC, ETH, USDT, USD, etc.)

---

## FINDING 6: GraphQL Schema Enumeration — Full API Reconstructed [CRITICAL]

**Introspection is disabled**, but error messages leak the entire schema via "Did you mean..." suggestions.

### Discovered Query Types:
| Type | Fields/Notes |
|------|------|
| User | id, name, email, createdAt, dob, kycStatus, hasTfaEnabled, hasEmailVerified, flags, roles, preference, rakeback, balances, dailyTotalDeposited, activeCasinoBet, isMaxBetEnabled |
| User Lists | sessionList, notificationList, chatList, tipList, withdrawalList, fiatTransactionList, depositList, bonusList, playSessionList, campaignList, raffleList, kycUltimateList, ipList |
| User Fields | transactionLimits, transaction, verifications, verificationBypass, depositAddress |
| Root Queries | user, ipAddress, suggestUser, raffle, hero, keys, bet, sport, allSports, sportList, getTags, getTag |

### Discovered Types:
UserSession, RateLimitIp, IdentityUserVerificationFields, VerificationBypass, UserPreference, Rakeback, HoldingBalance, Chat, Notification, PlaySession, UserCampaign, RaffleUser, Bet, Hero, Keys, Tag, InfoSetting, CurrencySetting, UserTrackId, UserAuthenticatedSession, UserTransactionLimit

### Discovered Enums:
CurrencyEnum, CryptoCurrencyEnum, CasinoEnum, LimitMethodTypeEnum, WalletAddressType, RolloverTypeEnum, SwishOddsChangeEnum, AffiliateDealType, ChallengeType, RaceScopeEnum, PromoCurrencyTypeEnum

---

## FINDING 7: Admin/Privileged Mutations Exposed [CRITICAL]

The following admin-only mutations are discoverable and their full argument signatures are leaked:

### Financial Admin Mutations:
| Mutation | Arguments | Impact |
|----------|-----------|--------|
| `createRollover` | userId, amount, currency, expectedAmountMin, note, type(RolloverTypeEnum) | Create wagering requirements for users |
| `createBonusPromo` | code, name, description, value, valueLimit, currencyType, active | Create bonus promotions with arbitrary values |
| `deletePromo` | promoId | Delete promotional offers |
| `updateCampaign` | campaignId, comission(Float!) | Modify affiliate commission rates |
| `updateAffiliate` | userId, dealType(AffiliateDealType!) | Modify affiliate deals |

### Content/Platform Admin Mutations:
| Mutation | Arguments | Impact |
|----------|-----------|--------|
| `createRaffle` | name, startTime, endTime, ticketValue, linkText, linkUrl | Create raffles |
| `createFixedRace` | name, currency, startTime, endTime, scope, templateId, description, linkText, linkUrl | Create races |
| `updateRace` | raceId, name, currency, payoutCurrency, description, linkText, linkUrl | Modify races |
| `deleteRace` | raceId | Delete races |
| `createChallenge` | award, claimMax, currency, minBetUsd, referredOnly, targetMultiplier, type | Create challenges |
| `createTag` / `updateTag` / `deleteTag` | id, name | Manage tags |
| `deleteHero` | heroId | Delete hero banners |
| `deletePod` | walletId | Delete wallet pods |

### User Management Admin Mutations:
| Mutation | Arguments | Impact |
|----------|-----------|--------|
| `muteUser` | userId | Mute users in chat |
| `unmuteUser` | userId | Unmute users |
| `updateUserRisk` | (previously discovered) | Modify user risk levels |
| `updateBonus` | (previously discovered) | Modify user bonuses |
| `updateSetting` | name, value | Change platform settings |
| `updateCurrencySetting` | currency, chains | Modify cryptocurrency settings |

### User Account Mutations (self-service but reachable cross-origin):
| Mutation | Arguments | Impact |
|----------|-----------|--------|
| `updateUserEmail` | email, turnstileToken | Change account email |
| `updateUserPhone` | countryCode, number, turnstileToken | Change phone number |
| `updateUserProfile` | profile(UpdateUserProfileProfileInput!) | Update profile |
| `disableUserTfa` | sessionName, tfaToken | Disable 2FA |
| `createApiKey` | sessionName | Create API keys |
| `registerUser` | email, name, password, sessionName, turnstileToken | Register users |
| `claimPromo` | code, currency | Claim promotions |
| `claimRakeback` | (no args) | Claim rakeback |
| `createTrackId` | trackId, userId | Create tracking IDs |
| `createSwishBet` | amount, currency, lines, oddsChange, requestedMultiplier | Place sports bets |

---

## FINDING 8: Sensitive Error Messages / Information Disclosure [MEDIUM]

Error messages reveal:
- Internal type names (IdentityUserVerificationFields, UserAuthenticatedSession, etc.)
- Argument types including custom enums (RolloverTypeEnum, SwishOddsChangeEnum, etc.)
- Internal field names and relationships
- Error type codes (permissionOwner, permissionFlag, permissionLimit, rakebackNotEnabled, userDepositIneligibleCurrency)
- Geographic restrictions ("This action is currently unavailable in your country or region")

---

## FINDING 9: Session Cookie Not HttpOnly [HIGH]

The `session` cookie is readable via `document.cookie`:
```
session=9d99723603b0121632767d74b51b2ca363163bf57dd73c6b83
```

This same value is the `x-access-token` authentication token. Any XSS vulnerability would immediately yield full account takeover since the token grants access to:
- Full PII (email, name, DOB)
- All wallet balances
- Session history with IP/geolocation
- Financial mutations (withdrawals, tips, bets)

---

## FINDING 10: Missing Rate Limiting on GraphQL Queries [MEDIUM]

- No observable rate limiting on query enumeration (50+ queries sent in rapid succession without throttling)
- Batching is disabled (good), but individual queries have no apparent rate limit
- Enables brute-force schema reconstruction and user enumeration at scale

---

## Summary

| # | Finding | Severity | Auth Required | Cross-Origin |
|---|---------|----------|---------------|--------------|
| 1 | CORS Wildcard + Credentials | Critical | No | Yes |
| 2 | IP Address Theft | Critical | No | Yes |
| 3 | User Enumeration | High | No | Yes |
| 4 | Session Geolocation Leak | High | Token | Yes (with token) |
| 5 | Full Account Data Extraction | Critical | Token | Yes (with token) |
| 6 | Full Schema Enumeration | Critical | No | Yes |
| 7 | Admin Mutations Exposed | Critical | No (discovery) | Yes |
| 8 | Verbose Error Messages | Medium | No | Yes |
| 9 | Non-HttpOnly Session Cookie | High | XSS | Same-origin |
| 10 | Missing Rate Limiting | Medium | No | Yes |

**Total: 4 Critical, 3 High, 3 Medium = 10 unique findings**
