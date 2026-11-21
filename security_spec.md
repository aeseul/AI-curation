# Security Specification (Phase 0: Payload-First Security TDD)

## 1. Data Invariants
1. `users/{userId}` can only be read or written by the authenticated, email-verified user whose `request.auth.uid == userId`. Collection `list` on `/users` is disabled (`false`).
2. `users/{userId}/private/{docId}` isolates PII (`email`) and is strictly restricted to `userId == request.auth.uid` (`get`, `create`, `update`, `delete`). `list` is disabled.
3. `users/{userId}/favorites/{favoriteId}` and `users/{userId}/recommendations/{recommendationId}` require the parent `/users/{userId}` document to exist on `create`, and must enforce `userId == request.auth.uid` on both read (`list` via `resource.data.userId == request.auth.uid`) and write.
4. All document IDs (`userId`, `favoriteId`, `recommendationId`, `docId`) must match `^[a-zA-Z0-9_\\-]+$` and have length `<= 128`.
5. All timestamps (`createdAt`, `updatedAt`) must equal `request.time` on `create` (`updatedAt == request.time` on `update`, and `createdAt` immutable).
6. No arbitrary shadow fields are permitted (`keys().hasOnly(...)` on create, `affectedKeys().hasOnly(...)` on update).

## 2. Dirty Dozen Adversarial Payloads (Must Return PERMISSION_DENIED)
1. **Unauthenticated Write**: Creating `/users/user123` with `request.auth == null`.
2. **Unverified Email Write**: Creating `/users/user123` with `request.auth.token.email_verified == false`.
3. **Cross-User Profile Read**: User A reading `/users/userB`.
4. **Cross-User PII Read**: User A reading `/users/userB/private/info`.
5. **Users Collection Scrape**: Calling `list` on `/users`.
6. **UID Spoofing on Create**: User A creating `/users/userA/favorites/fav1` with `userId: "userB"`.
7. **Shadow Field Injection**: Creating `/users/userA` with extra field `isAdmin: true`.
8. **ID Poisoning**: Creating `/users/userA/favorites/../../bad$id` or 500-char ID.
9. **Client Timestamp Forgery**: Creating `/users/userA` with `createdAt` not equal to `request.time`.
10. **Immutable Field Mutation**: Updating `/users/userA/favorites/fav1` to change `createdAt` or `userId`.
11. **Oversized String DoW**: Creating `/users/userA` with 10KB `nickname`.
12. **Orphaned Subcollection Write**: Creating `/users/userA/favorites/fav1` when `/users/userA` does not exist.
