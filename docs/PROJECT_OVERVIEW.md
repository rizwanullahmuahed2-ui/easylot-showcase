# EasyLot: Project Overview

## Scope

EasyLot is an Afghanistan-focused airtime storefront with a Dari interface, AFN pricing, cryptocurrency checkout, and an authenticated administrative area. It coordinates two external providers rather than implementing a cryptocurrency wallet or telecom billing system itself.

Customers pay with cryptocurrency, and confirmed orders proceed to mobile airtime delivery.

## Customer journey

1. Enter an Afghan mobile number and choose an available amount.
2. Validate the network and denomination against the airtime catalog.
3. Show the selected AFN amount and final AFN total using current admin pricing.
4. Preserve the quote's pricing and create a hosted USD invoice.
5. Verify the payment callback and confirm settlement directly with the payment provider.
6. Claim the stored order before requesting mobile airtime delivery.
7. Display the provider outcome through protected order tracking.

The provider's local conversion and denomination rules determine delivered airtime. The site's manually configured AFN rate does not override the telecom provider's conversion.

## Administration

An administrator controls the AFN-per-USD rate, customer markup, and manual top-up requests. Manual delivery has its own authorization and records and requires explicit confirmation. Customer markup is not applied to admin manual requests.

The implementation includes password hashing, protected sessions, origin checks and login throttling. The current owner's first-time setup depends on trusted hosting identity; this bootstrap needs deliberate adaptation on a different host.

## Reliability decisions

Accepted orders retain their quoted prices. Concurrent delivery attempts use an atomic database claim for the same stored request. Provider responses that are ambiguous or interrupted are retained for review rather than retried automatically.

These controls do not imply exactly-once delivery across external services or independent database copies. Provider reports and financial reconciliation remain necessary. Balance checks do not reserve funds across different orders.

## Validation evidence

The source snapshot was checked on 10 October 2026 using 33 passing automated tests and a successful Worker build. Mocked provider responses and isolated databases covered:

- Payment signature checks, settled-payment matching and callback handling.
- Unauthorized tracking and administrator access.
- Login sessions, throttling and origin validation.
- Afghan phone/network validation.
- AFN conversion, exact selected amounts and pricing snapshots.
- Concurrent top-up claims and review of ambiguous outcomes.
- Independence of manual admin delivery from customer payment.

The full test suite is available during private source review. No claim of independent security certification, load-tested scale or universal provider availability is made.

## Implementation status

Implemented: customer/admin interfaces, provider adapters, pricing controls, persistence, payment verification, tracking, manual delivery and mocked tests.

Future work: production VPS adapter, coordinated live-data migration, additional local integrations, a durable delivery queue, scheduled reconciliation and cross-order balance reservation. Refunds currently follow a manual support process.

## Source review

Employers and technical reviewers can request access from the project owner. The private repository contains implementation modules, tests, schema migrations and installation/deployment guides. Production credentials and customer records are kept separate from both repository exports.
