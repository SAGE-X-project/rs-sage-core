# rs-sage-core 설계 문서

> **SAGE Crypto Core 라이브러리 완전 재구현 설계 문서 모음**

## 📚 문서 구조

이 디렉토리는 rs-sage-core를 sage/ Go 구현과 동일한 기능을 제공하도록 리팩토링하기 위한 모든 설계 문서를 포함합니다.

### 📖 문서 읽는 순서

1. **[IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md)** ⭐ **시작 지점**
   - 전체 프로젝트 개요
   - Phase 1-4 로드맵
   - 의존성 설계
   - 마일스톤

2. **[QUICK_START_GUIDE.md](./QUICK_START_GUIDE.md)** 🚀 **바로 시작**
   - 즉시 구현 시작 가이드
   - Day-by-Day 체크리스트
   - 유용한 명령어
   - 문제 해결

3. **[PHASE_1_DESIGN.md](./PHASE_1_DESIGN.md)** 📋 **Phase 1 상세**
   - Core 모듈 구조
   - CryptoManager + KeyStorage
   - RFC 9421 확장
   - 상세 코드 예제

4. **PHASE_2_DESIGN.md** (작성 예정)
   - DID 시스템 설계
   - Ethereum/Solana 연동
   - 블록체인 클라이언트

5. **PHASE_3_DESIGN.md** (작성 예정)
   - 메시지 처리 시스템
   - Nonce, Dedupe, Order
   - 검증 파이프라인

6. **PHASE_4_DESIGN.md** (작성 예정)
   - Core 통합
   - 공개 API
   - 상호운용성 테스트

## 🎯 프로젝트 목표

### 현재 상태 (As-Is)
- 라인 수: ~3,554 LOC
- 모듈: crypto, rfc9421, formats, ffi, wasm
- 범위: 기본 암호화 + RFC 9421 HTTP 서명

### 목표 상태 (To-Be)
- 라인 수: ~10,000-15,000 LOC
- 모듈: core, crypto, rfc9421, did, message, formats, ffi, wasm
- 범위: 완전한 AI 에이전트 보안 통신 시스템

## 📊 구현 진행 상황

### Phase 1: 핵심 인프라 (5-7일)
- [ ] 프로젝트 구조 재설계
- [ ] Core 모듈 (Message, VerificationService)
- [ ] CryptoManager + KeyStorage
- [ ] RFC 9421 확장 (MessageBuilder)

### Phase 2: DID 시스템 (10-14일)
- [ ] DID 기본 구조
- [ ] Ethereum 블록체인 연동
- [ ] Solana 블록체인 연동
- [ ] MultiChain 통합

### Phase 3: 메시지 처리 (4-6일)
- [ ] NonceManager
- [ ] DedupeDetector
- [ ] OrderManager
- [ ] 검증 파이프라인

### Phase 4: 통합 & 테스트 (5-8일)
- [ ] Core 통합 레이어
- [ ] 공개 API 설계
- [ ] 문서화
- [ ] Go 구현과 상호운용성

**총 예상 시간**: 24-35일

## 🏗️ 최종 아키텍처

```
rs-sage-core/
├── src/
│   ├── lib.rs
│   ├── core/                    # 🆕 통합 레이어
│   │   ├── mod.rs
│   │   ├── message.rs
│   │   ├── verification_service.rs
│   │   └── types.rs
│   ├── crypto/                  # ✏️ 확장
│   │   ├── mod.rs
│   │   ├── keys.rs
│   │   ├── manager.rs          # 🆕
│   │   └── storage/            # 🆕
│   ├── rfc9421/                 # ✏️ 확장
│   │   ├── message_builder.rs  # 🆕
│   │   └── validator.rs        # 🆕
│   ├── did/                     # 🆕 DID 시스템
│   │   ├── mod.rs
│   │   ├── types.rs
│   │   ├── manager.rs
│   │   ├── resolver.rs
│   │   ├── registry.rs
│   │   └── chain/
│   │       ├── ethereum.rs
│   │       └── solana.rs
│   └── message/                 # 🆕 메시지 처리
│       ├── nonce.rs
│       ├── dedupe.rs
│       └── order.rs
├── tests/integration/
└── docs/design/                 # 이 디렉토리
```

## 🔑 핵심 개념

### 1. Core 통합 레이어
모든 기능을 통합하는 단일 진입점:
```rust
let core = Core::new();
let keypair = core.generate_keypair(KeyType::Ed25519)?;
let message = core.message_builder()
    .agent_did("did:sage:eth:0x123")
    .body(b"data")
    .keypair(keypair)
    .build()?;
```

### 2. DID (Decentralized Identifier) 시스템
블록체인 기반 에이전트 신원 관리:
```rust
// Ethereum에 DID 등록
let result = core.register_agent(
    Chain::Ethereum,
    &RegistrationRequest { /* ... */ }
).await?;

// DID로 공개키 조회
let metadata = core.resolve_agent("did:sage:eth:0x123").await?;
```

### 3. 메시지 무결성 보장
RFC 9421 + 추가 검증:
- **Nonce**: 재전송 공격 방지
- **Dedupe**: 중복 메시지 탐지
- **Order**: 순서 보장

### 4. 블록체인 멀티체인 지원
- Ethereum (Sepolia, Mainnet)
- Solana (Devnet, Mainnet)

## 📋 구현 체크리스트

### 단계별 완료 기준

**Phase 1 완료**:
- [ ] Core 모듈 구조 완성
- [ ] CryptoManager로 키 생성/저장/로드 가능
- [ ] MessageBuilder로 서명된 메시지 생성 가능
- [ ] 모든 유닛 테스트 통과

**Phase 2 완료**:
- [ ] DID 생성 및 파싱 기능
- [ ] Ethereum 테스트넷에서 DID 등록/조회
- [ ] Solana 테스트넷에서 DID 등록/조회
- [ ] MultiChain 통합 동작

**Phase 3 완료**:
- [ ] Nonce 생성 및 검증
- [ ] 중복 메시지 탐지
- [ ] 순서 보장 로직
- [ ] 통합 검증 파이프라인

**Phase 4 완료**:
- [ ] Core API 완성
- [ ] Go 구현과 서명 상호 검증 성공
- [ ] 전체 통합 테스트 통과
- [ ] 문서 완성

## 🛠️ 개발 도구

### 필수 도구
```bash
# Rust 툴체인
rustup update stable

# 유용한 도구
cargo install cargo-watch
cargo install cargo-expand
cargo install cargo-tarpaulin  # 코드 커버리지
```

### 개발 워크플로우
```bash
# 자동 빌드 감시
cargo watch -x check -x test

# 포맷 및 Lint
cargo fmt && cargo clippy

# 전체 테스트
cargo test --all-features

# 문서 생성
cargo doc --no-deps --open
```

## 📖 참조 자료

### 내부 참조
- [sage/ Go 구현](../../sage/pkg/agent/)
- [기존 rs-sage-core](../../src/)

### 외부 참조
- [RFC 9421 Specification](https://www.rfc-editor.org/rfc/rfc9421.html)
- [DID Core Specification](https://www.w3.org/TR/did-core/)
- [Ethereum Smart Contracts](https://docs.soliditylang.org/)
- [Solana Programs](https://docs.solana.com/developing/on-chain-programs/overview)

### Rust 리소스
- [The Rust Book](https://doc.rust-lang.org/book/)
- [Async Book](https://rust-lang.github.io/async-book/)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [ethers-rs Docs](https://docs.rs/ethers/)

## 🤝 기여 가이드

### 코드 스타일
- `cargo fmt`로 자동 포맷
- `cargo clippy`로 Lint 통과
- 모든 public API에 문서 주석
- 테스트 커버리지 >80%

### 커밋 메시지
```
feat(phase1): implement Message type
fix(crypto): resolve key storage race condition
docs(design): add Phase 2 detailed design
test(did): add Ethereum integration tests
```

### Pull Request
1. Feature 브랜치 생성: `feat/phase1-core`
2. 구현 및 테스트
3. 문서 업데이트
4. PR 생성 및 리뷰 요청

## 📞 지원

### 질문이 있을 때
1. 설계 문서 먼저 확인
2. 기존 sage/ Go 코드 참조
3. Issue 생성 또는 팀 문의

### 버그 발견 시
1. Issue 등록 (재현 방법 포함)
2. 가능하면 테스트 케이스 작성
3. Fix PR 제출

## 🎓 학습 경로

### 초급 (Day 1-7: Phase 1)
- Rust 기본 문법
- 모듈 시스템
- Trait과 제네릭
- 에러 처리

### 중급 (Day 8-21: Phase 2)
- 비동기 프로그래밍 (Tokio)
- async/await 패턴
- 블록체인 SDK 사용
- 네트워크 프로그래밍

### 고급 (Day 22-35: Phase 3-4)
- 복잡한 상태 관리
- 동시성 패턴
- 성능 최적화
- 시스템 통합

## 📈 성공 지표

| 지표 | 목표 | 측정 |
|------|------|------|
| 코드 커버리지 | >80% | `cargo tarpaulin` |
| 문서 커버리지 | >90% | `cargo doc` |
| 빌드 시간 | <60초 | `cargo build --timings` |
| 테스트 통과율 | 100% | `cargo test` |
| Clippy 경고 | 0개 | `cargo clippy` |

## 🗓️ 타임라인

```
Week 1: Phase 1 (핵심 인프라)
Week 2-3: Phase 2 (DID 시스템)
Week 4: Phase 3 (메시지 처리)
Week 5: Phase 4 (통합 & 테스트)
```

---

## 🚀 시작하기

**지금 바로 시작하려면**:

1. [QUICK_START_GUIDE.md](./QUICK_START_GUIDE.md) 읽기
2. Phase 1 Day 1 체크리스트 따라하기
3. 문제 발생 시 [PHASE_1_DESIGN.md](./PHASE_1_DESIGN.md) 참조

**질문이 있으면**:
- 팀 채널에 문의
- Issue 등록
- 설계 문서 재확인

---

**작성일**: 2025-01-27
**최종 수정**: 2025-01-27
**버전**: 1.0
**상태**: 설계 완료, 구현 대기 중
