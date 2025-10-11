# Phase 3 계획: 블록체인 통합

## 📋 개요

Phase 3는 SAGE 프로젝트의 블록체인 통합을 완성하는 단계입니다. Phase 2에서 구축한 DID 시스템을 실제 블록체인과 연결하여 탈중앙화된 신원 관리를 구현합니다.

## 🎯 목표

### 핵심 목표
1. **온체인 DID 등록**: 블록체인에 DID Document 등록
2. **실시간 DID 조회**: 스마트 컨트랙트를 통한 DID 정보 조회
3. **Nonce 추적**: 블록체인 기반 replay attack 방지
4. **이벤트 리스닝**: 온체인 DID 업데이트 자동 동기화

### Phase 2 대비 개선사항
- BlockchainDIDResolver placeholder → 실제 구현
- 메모리 기반 nonce → 블록체인 기반 nonce
- 로컬 DID 조회 → 온체인 DID 조회

## 📦 작업 분해

### Task 3-1: 블록체인 클라이언트 통합 및 트랜잭션 서명

**목표**: 이더리움/EVM 호환 블록체인과 통신하는 클라이언트 구현

**구현 내용**:
1. 블록체인 클라이언트 인터페이스 정의
   - RPC 연결 관리
   - 트랜잭션 전송
   - 이벤트 리스닝

2. 트랜잭션 서명
   - Secp256k1 서명을 이더리움 트랜잭션에 적용
   - EIP-155 (Replay protection) 지원
   - Gas 추정 및 관리

3. 스마트 컨트랙트 ABI 인터페이스
   - DID Registry 컨트랙트 인터페이스
   - 메서드 호출 인코딩/디코딩

**새 파일**:
- `src/blockchain/mod.rs` - 블록체인 모듈 루트
- `src/blockchain/client.rs` - 블록체인 클라이언트
- `src/blockchain/transaction.rs` - 트랜잭션 서명 및 전송
- `src/blockchain/contract.rs` - 스마트 컨트랙트 인터페이스

**의존성 추가**:
```toml
ethers = { version = "2.0", features = ["abigen"] }
tokio = { version = "1.0", features = ["full"] }
```

---

### Task 3-2: 온체인 DID 등록 및 조회 구현

**목표**: BlockchainDIDResolver를 실제 스마트 컨트랙트와 연동

**구현 내용**:
1. DID Registry 스마트 컨트랙트 인터페이스
   - `registerDID(string did, bytes document)` - DID 등록
   - `getDIDDocument(string did) returns (bytes)` - DID 조회
   - `updateDIDDocument(string did, bytes document)` - DID 업데이트
   - `revokeDID(string did)` - DID 폐기

2. BlockchainDIDResolver 구현
   - 컨트랙트를 통한 DID Document 조회
   - 캐싱 레이어 (로컬 캐시 + TTL)
   - 오류 처리 및 재시도 로직

3. DID 등록 워크플로우
   - DID Document JSON → 바이트 인코딩
   - 트랜잭션 서명 및 전송
   - 트랜잭션 확인 대기
   - 이벤트 확인

**수정 파일**:
- `src/did/resolver.rs` - BlockchainDIDResolver 구현

**새 파일**:
- `src/blockchain/did_registry.rs` - DID Registry 컨트랙트 인터페이스

---

### Task 3-3: Nonce 추적 시스템

**목표**: 블록체인 타임스탬프 기반 replay attack 방지

**구현 내용**:
1. NonceTracker 구현
   - 블록체인에서 사용된 nonce 조회
   - 로컬 nonce 캐시
   - Nonce 유효성 검증

2. 온체인 Nonce 저장
   - 스마트 컨트랙트에 사용된 nonce 기록
   - 블록 타임스탬프 기반 만료

3. VerificationService 통합
   - verify_nonce() 메서드 업데이트
   - 블록체인 기반 검증

**새 파일**:
- `src/blockchain/nonce_tracker.rs` - Nonce 추적 시스템

**수정 파일**:
- `src/core/verification_service.rs` - Nonce 검증 로직 업데이트

---

### Task 3-4: 이벤트 리스닝 및 자동 동기화

**목표**: 온체인 DID 변경사항을 자동으로 감지하고 로컬 캐시 업데이트

**구현 내용**:
1. 이벤트 리스너
   - `DIDRegistered` 이벤트
   - `DIDUpdated` 이벤트
   - `DIDRevoked` 이벤트

2. 이벤트 핸들러
   - 이벤트 파싱
   - DID Document 업데이트
   - 캐시 무효화

3. 백그라운드 동기화
   - 주기적 체인 스캔
   - 누락된 이벤트 복구

**새 파일**:
- `src/blockchain/events.rs` - 이벤트 리스닝 및 처리

---

### Task 3-5: 통합 테스트 및 문서화

**목표**: Phase 3 기능의 종합 테스트 및 완전한 문서화

**구현 내용**:
1. 통합 테스트
   - 로컬 블록체인 (Hardhat/Anvil) 테스트
   - DID 등록 → 조회 → 업데이트 → 폐기 전체 워크플로우
   - Nonce 추적 테스트
   - 이벤트 리스닝 테스트

2. 문서화
   - Phase 3 완료 보고서
   - 블록체인 통합 가이드
   - 스마트 컨트랙트 배포 가이드
   - API 문서 업데이트

**새 파일**:
- `tests/phase3_integration.rs` - Phase 3 통합 테스트
- `docs/phase3_completion.md` - Phase 3 완료 문서
- `docs/blockchain_integration.md` - 블록체인 통합 가이드

---

## 🏗️ 아키텍처

### Phase 3 전체 구조

```
┌─────────────────────────────────────────────────────────────┐
│                    SAGE Application Layer                    │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                  rs-sage-core (Phase 1-3)                    │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Crypto     │  │     Core     │  │     DID      │      │
│  │  (Phase 1)   │  │  (Phase 1-2) │  │  (Phase 2)   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                              ↓                                │
│                    ┌──────────────┐                          │
│                    │  Blockchain  │  ← Phase 3               │
│                    │   (Phase 3)  │                          │
│                    └──────────────┘                          │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│              Ethereum / EVM Compatible Blockchain            │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │            DID Registry Smart Contract                │   │
│  │                                                        │   │
│  │  • registerDID(did, document)                         │   │
│  │  • getDIDDocument(did) → document                     │   │
│  │  • updateDIDDocument(did, document)                   │   │
│  │  • revokeDID(did)                                     │   │
│  │  • useNonce(did, nonce)                               │   │
│  │  • isNonceUsed(did, nonce) → bool                     │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### DID 등록 시퀀스

```
Client                rs-sage-core           Blockchain
  │                        │                      │
  │ 1. Generate KeyPair    │                      │
  ├───────────────────────►│                      │
  │                        │                      │
  │ 2. Create DID          │                      │
  ├───────────────────────►│                      │
  │                        │                      │
  │ 3. Create DID Document │                      │
  ├───────────────────────►│                      │
  │                        │                      │
  │ 4. Register on-chain   │                      │
  ├───────────────────────►│ 5. Sign Transaction │
  │                        ├─────────────────────►│
  │                        │ 6. Send Transaction  │
  │                        ├─────────────────────►│
  │                        │                      │
  │                        │ 7. Wait for Receipt  │
  │                        │◄─────────────────────┤
  │                        │                      │
  │ 8. Return DID          │                      │
  │◄───────────────────────┤                      │
```

### DID 검증 시퀀스

```
Verifier              rs-sage-core           Blockchain
  │                        │                      │
  │ 1. Receive Message     │                      │
  ├───────────────────────►│                      │
  │                        │                      │
  │ 2. Extract DID         │                      │
  │                        │                      │
  │ 3. Resolve DID         │                      │
  ├───────────────────────►│ 4. Query Contract   │
  │                        ├─────────────────────►│
  │                        │ 5. Get Document     │
  │                        │◄─────────────────────┤
  │                        │                      │
  │                        │ 6. Check Nonce      │
  │                        ├─────────────────────►│
  │                        │ 7. Nonce Status     │
  │                        │◄─────────────────────┤
  │                        │                      │
  │ 8. Verify Signature    │                      │
  │                        │                      │
  │ 9. Return Result       │                      │
  │◄───────────────────────┤                      │
```

---

## 🔧 기술 스택

### 블록체인 관련
- **ethers-rs**: 이더리움 클라이언트 라이브러리
- **Solidity**: 스마트 컨트랙트 언어 (별도 프로젝트)
- **Hardhat/Foundry**: 스마트 컨트랙트 개발 및 테스트

### Rust 의존성
```toml
[dependencies]
# Existing dependencies...

# Blockchain integration (Phase 3)
ethers = { version = "2.0", features = ["abigen", "ws"] }
tokio = { version = "1.0", features = ["full", "sync"] }
async-trait = "0.1"
futures = "0.3"

[dev-dependencies]
# Existing dev-dependencies...

# Blockchain testing
ethers-solc = "2.0"
```

---

## 📊 예상 타임라인

| Task | 예상 시간 | 우선순위 |
|------|----------|----------|
| Task 3-1: 블록체인 클라이언트 | 1-2일 | 높음 |
| Task 3-2: DID 온체인 등록/조회 | 2-3일 | 높음 |
| Task 3-3: Nonce 추적 시스템 | 1일 | 중간 |
| Task 3-4: 이벤트 리스닝 | 1일 | 낮음 |
| Task 3-5: 통합 테스트 및 문서화 | 1-2일 | 높음 |

**총 예상 시간**: 6-9일

---

## ⚠️ 고려사항

### 블록체인 선택
- **개발 환경**: Hardhat/Anvil 로컬 노드
- **테스트넷**: Sepolia (Ethereum) 또는 Mumbai (Polygon)
- **메인넷**: 프로젝트 요구사항에 따라 결정

### Gas 최적화
- DID Document 크기 최소화
- 배치 트랜잭션 고려
- Layer 2 솔루션 검토 (Optimism, Arbitrum)

### 보안
- Private key 관리 (절대 하드코딩 금지)
- 트랜잭션 서명 검증
- Reentrancy 공격 방지 (스마트 컨트랙트)

### 성능
- DID Document 캐싱 전략
- RPC 요청 최적화
- 병렬 트랜잭션 처리

---

## ✅ 완료 기준

Phase 3는 다음 조건을 만족해야 완료됩니다:

1. **기능 완성도**
   - [ ] 블록체인 클라이언트 구현 및 테스트
   - [ ] DID 온체인 등록/조회 동작
   - [ ] Nonce 추적 시스템 동작
   - [ ] 이벤트 리스닝 동작

2. **테스트**
   - [ ] 모든 단위 테스트 통과
   - [ ] Phase 3 통합 테스트 통과
   - [ ] 로컬 블록체인 테스트 통과
   - [ ] 테스트넷 검증 (선택)

3. **문서화**
   - [ ] Phase 3 완료 보고서
   - [ ] 블록체인 통합 가이드
   - [ ] API 문서 업데이트
   - [ ] 스마트 컨트랙트 문서

4. **코드 품질**
   - [ ] 모든 public API에 rustdoc 주석
   - [ ] 에러 처리 완전성
   - [ ] 성능 벤치마크 (기본)

---

## 🚀 시작하기

Phase 3를 시작하려면:

1. 새 브랜치 생성: `feat/phase3-blockchain-integration`
2. Task 3-1부터 순차적으로 진행
3. 각 Task 완료 후 커밋 및 푸시
4. Phase 3 완료 후 PR 생성 → dev 병합

---

**작성일**: 2025-10-11
**예상 완료일**: 2025-10-20
**담당**: Claude (AI Assistant)
