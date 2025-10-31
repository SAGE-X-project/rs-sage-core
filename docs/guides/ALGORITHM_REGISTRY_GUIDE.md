# Algorithm Registry Guide

## Overview

Algorithm Registry는 SAGE 프로토콜에서 지원하는 모든 암호화 알고리즘의 메타데이터와 선택 로직을 중앙에서 관리합니다.

**지원 기능:**
- 알고리즘 메타데이터 (키 크기, 서명 크기, 보안 수준)
- 성능 및 호환성 정보
- 프로토콜/체인별 추천 알고리즘
- 요구사항 기반 자동 선택

**상태:** ✅ Production Ready (v0.3.0)

---

## Quick Start

### 1. 알고리즘 메타데이터 조회

```rust
use sage_crypto_core::crypto::{AlgorithmRegistry, Algorithm};

fn main() {
    // Ed25519 메타데이터 조회
    let metadata = AlgorithmRegistry::get_metadata(Algorithm::Ed25519);

    println!("Algorithm: {}", metadata.algorithm);
    println!("Private key size: {} bytes", metadata.private_key_size);
    println!("Public key size: {} bytes", metadata.public_key_size);
    println!("Signature size: {} bytes", metadata.signature_size);
    println!("Security level: {}", metadata.security_level);
    println!("Performance: {}", metadata.performance);
    println!("Deterministic: {}", metadata.deterministic);
}
```

### 2. 추천 알고리즘 가져오기

```rust
use sage_crypto_core::crypto::AlgorithmRegistry;

fn main() {
    // 성능 우선 알고리즘
    let fast = AlgorithmRegistry::recommend_for_performance();
    println!("Fastest: {}", fast); // Ed25519

    // FIPS 준수 알고리즘
    let fips = AlgorithmRegistry::recommend_for_fips();
    println!("FIPS: {}", fips); // P-256

    // Ethereum 권장 알고리즘
    let eth = AlgorithmRegistry::recommend_for_ethereum();
    println!("Ethereum: {}", eth); // Secp256k1

    // Solana 권장 알고리즘
    let sol = AlgorithmRegistry::recommend_for_solana();
    println!("Solana: {}", sol); // Ed25519
}
```

### 3. 요구사항 기반 선택

```rust
use sage_crypto_core::crypto::AlgorithmRegistry;

fn main() {
    // Ethereum 호환 + 성능 우선
    let algo = AlgorithmRegistry::select_algorithm(
        true,  // ethereum
        false, // solana
        false, // fips
        true,  // prefer_performance
    );
    println!("Selected: {:?}", algo);

    // Ethereum + FIPS 준수
    let algo = AlgorithmRegistry::select_algorithm(
        true,  // ethereum
        false, // solana
        true,  // fips
        false, // prefer_performance
    );
    println!("Selected: {:?}", algo); // Some(P256)
}
```

---

## API Reference

### AlgorithmRegistry

정적 메서드만 제공하는 싱글톤 레지스트리입니다.

#### 메타데이터 조회

```rust
// 특정 알고리즘의 메타데이터
let metadata = AlgorithmRegistry::get_metadata(Algorithm::Ed25519);

// 모든 알고리즘 목록
let all = AlgorithmRegistry::all_algorithms();
assert_eq!(all.len(), 5);

// 모든 메타데이터 (HashMap)
let map = AlgorithmRegistry::all_metadata();
```

#### 추천 알고리즘

```rust
// 성능 우선
let algo = AlgorithmRegistry::recommend_for_performance();

// FIPS 준수
let algo = AlgorithmRegistry::recommend_for_fips();

// Ethereum 권장
let algo = AlgorithmRegistry::recommend_for_ethereum();

// Solana 권장
let algo = AlgorithmRegistry::recommend_for_solana();
```

#### 호환성 필터링

```rust
// Ethereum 호환 알고리즘
let eth_algos = AlgorithmRegistry::compatible_with_ethereum();
// [Ed25519, Secp256k1, P256]

// Solana 호환 알고리즘
let sol_algos = AlgorithmRegistry::compatible_with_solana();
// [Ed25519]

// FIPS 준수 알고리즘
let fips_algos = AlgorithmRegistry::fips_compliant_algorithms();
// [P256, Rsa2048, Rsa4096]
```

#### 보안 수준 및 성능 필터링

```rust
use sage_crypto_core::crypto::{SecurityLevel, PerformanceTier};

// 최소 보안 수준
let secure = AlgorithmRegistry::by_security_level(SecurityLevel::High);
// [Rsa4096]

// 성능 티어별
let fast = AlgorithmRegistry::by_performance_tier(PerformanceTier::Fast);
// [Ed25519]

let medium = AlgorithmRegistry::by_performance_tier(PerformanceTier::Medium);
// [Secp256k1, P256]

let slow = AlgorithmRegistry::by_performance_tier(PerformanceTier::Slow);
// [Rsa2048, Rsa4096]
```

#### 특성 확인

```rust
// 결정론적 서명 여부
let is_det = AlgorithmRegistry::is_deterministic(Algorithm::Ed25519);
assert!(is_det);

let not_det = AlgorithmRegistry::is_deterministic(Algorithm::Rsa2048);
assert!(!not_det);
```

#### 자동 선택

```rust
// 요구사항에 맞는 알고리즘 선택
let algo = AlgorithmRegistry::select_algorithm(
    ethereum,          // Ethereum 호환 필수
    solana,            // Solana 호환 필수
    fips,              // FIPS 준수 필수
    prefer_performance // 성능 우선 (true) vs 보안 우선 (false)
);
```

### AlgorithmMetadata

알고리즘의 모든 메타데이터를 담고 있는 구조체입니다.

```rust
pub struct AlgorithmMetadata {
    pub algorithm: Algorithm,
    pub private_key_size: usize,
    pub public_key_size: usize,
    pub signature_size: usize,
    pub security_level: SecurityLevel,
    pub performance: PerformanceTier,
    pub deterministic: bool,
    pub ethereum_compatible: bool,
    pub solana_compatible: bool,
    pub fips_compliant: bool,
    pub description: &'static str,
}
```

### SecurityLevel

보안 수준 (비트 강도)

```rust
pub enum SecurityLevel {
    Standard = 128,   // 128-bit
    High = 192,       // 192-bit
    VeryHigh = 256,   // 256-bit
}
```

### PerformanceTier

성능 티어

```rust
pub enum PerformanceTier {
    Fast,    // 가장 빠름
    Medium,  // 중간
    Slow,    // 느림
}
```

---

## Examples

### Example 1: 알고리즘 비교

```rust
use sage_crypto_core::crypto::{AlgorithmRegistry, Algorithm};

fn main() {
    let algorithms = vec![
        Algorithm::Ed25519,
        Algorithm::Secp256k1,
        Algorithm::P256,
        Algorithm::Rsa2048,
    ];

    println!("Algorithm Comparison:");
    println!("{:<15} {:<10} {:<10} {:<15} {:<10}",
        "Algorithm", "Sig Size", "Security", "Performance", "FIPS");
    println!("{}", "-".repeat(70));

    for algo in algorithms {
        let meta = AlgorithmRegistry::get_metadata(algo);
        println!("{:<15} {:<10} {:<10} {:<15} {:<10}",
            algo,
            meta.signature_size,
            format!("{:?}", meta.security_level),
            format!("{:?}", meta.performance),
            meta.fips_compliant
        );
    }
}
```

출력:
```
Algorithm Comparison:
Algorithm       Sig Size   Security   Performance     FIPS
----------------------------------------------------------------------
Ed25519         64         Standard   Fast            false
Secp256k1       64         Standard   Medium          false
P-256           64         Standard   Medium          true
RSA-2048        256        Standard   Slow            true
```

### Example 2: 프로토콜별 알고리즘 선택

```rust
use sage_crypto_core::crypto::AlgorithmRegistry;

fn select_for_protocol(protocol: &str) -> String {
    match protocol {
        "ethereum" => {
            let algo = AlgorithmRegistry::recommend_for_ethereum();
            format!("Ethereum: {} (native support)", algo)
        }
        "solana" => {
            let algo = AlgorithmRegistry::recommend_for_solana();
            format!("Solana: {} (required)", algo)
        }
        "enterprise" => {
            let algo = AlgorithmRegistry::recommend_for_fips();
            format!("Enterprise: {} (FIPS compliant)", algo)
        }
        "performance" => {
            let algo = AlgorithmRegistry::recommend_for_performance();
            format!("Performance: {} (fastest)", algo)
        }
        _ => "Unknown protocol".to_string(),
    }
}

fn main() {
    println!("{}", select_for_protocol("ethereum"));
    println!("{}", select_for_protocol("solana"));
    println!("{}", select_for_protocol("enterprise"));
    println!("{}", select_for_protocol("performance"));
}
```

### Example 3: 요구사항 기반 자동 선택

```rust
use sage_crypto_core::crypto::AlgorithmRegistry;

struct Requirements {
    ethereum: bool,
    solana: bool,
    fips: bool,
    performance_critical: bool,
}

impl Requirements {
    fn select_algorithm(&self) -> Option<String> {
        AlgorithmRegistry::select_algorithm(
            self.ethereum,
            self.solana,
            self.fips,
            self.performance_critical,
        ).map(|a| a.to_string())
    }
}

fn main() {
    // 사용 사례 1: DeFi 애플리케이션
    let defi = Requirements {
        ethereum: true,
        solana: false,
        fips: false,
        performance_critical: true,
    };
    println!("DeFi app: {:?}", defi.select_algorithm());
    // Some("Ed25519") - Ethereum 호환 + 가장 빠름

    // 사용 사례 2: 기업 시스템
    let enterprise = Requirements {
        ethereum: true,
        solana: false,
        fips: true,
        performance_critical: false,
    };
    println!("Enterprise: {:?}", enterprise.select_algorithm());
    // Some("P-256") - Ethereum 호환 + FIPS 준수

    // 사용 사례 3: Solana NFT
    let nft = Requirements {
        ethereum: false,
        solana: true,
        fips: false,
        performance_critical: true,
    };
    println!("Solana NFT: {:?}", nft.select_algorithm());
    // Some("Ed25519") - Solana는 Ed25519만 지원

    // 사용 사례 4: 불가능한 요구사항
    let impossible = Requirements {
        ethereum: false,
        solana: true,
        fips: true,
        performance_critical: false,
    };
    println!("Impossible: {:?}", impossible.select_algorithm());
    // None - Solana는 Ed25519만 지원하지만 FIPS 준수 필요
}
```

### Example 4: 통계 및 분석

```rust
use sage_crypto_core::crypto::{AlgorithmRegistry, PerformanceTier};

fn main() {
    let all = AlgorithmRegistry::all_algorithms();

    // 성능별 분포
    let fast = AlgorithmRegistry::by_performance_tier(PerformanceTier::Fast).len();
    let medium = AlgorithmRegistry::by_performance_tier(PerformanceTier::Medium).len();
    let slow = AlgorithmRegistry::by_performance_tier(PerformanceTier::Slow).len();

    println!("Performance Distribution:");
    println!("  Fast: {} ({:.1}%)", fast, (fast as f64 / all.len() as f64) * 100.0);
    println!("  Medium: {} ({:.1}%)", medium, (medium as f64 / all.len() as f64) * 100.0);
    println!("  Slow: {} ({:.1}%)", slow, (slow as f64 / all.len() as f64) * 100.0);

    // 블록체인 호환성
    let eth = AlgorithmRegistry::compatible_with_ethereum().len();
    let sol = AlgorithmRegistry::compatible_with_solana().len();

    println!("\nBlockchain Compatibility:");
    println!("  Ethereum: {} algorithms", eth);
    println!("  Solana: {} algorithms", sol);

    // FIPS 준수
    let fips = AlgorithmRegistry::fips_compliant_algorithms().len();
    println!("\nFIPS Compliance:");
    println!("  FIPS-compliant: {} ({:.1}%)",
        fips, (fips as f64 / all.len() as f64) * 100.0);
}
```

---

## 알고리즘 비교표

| Algorithm | Private Key | Public Key | Signature | Security | Performance | Deterministic | Ethereum | Solana | FIPS |
|-----------|-------------|------------|-----------|----------|-------------|---------------|----------|--------|------|
| **Ed25519** | 32 B | 32 B | 64 B | 128-bit | ⚡ Fast | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| **Secp256k1** | 32 B | 33 B | 64 B | 128-bit | 🔶 Medium | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| **P-256** | 32 B | 33 B | 64 B | 128-bit | 🔶 Medium | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes |
| **RSA-2048** | 256 B | 256 B | 256 B | 128-bit | 🐌 Slow | ❌ No | ❌ No | ❌ No | ✅ Yes |
| **RSA-4096** | 512 B | 512 B | 512 B | 192-bit | 🐌 Slow | ❌ No | ❌ No | ❌ No | ✅ Yes |

---

## 선택 가이드라인

### 언제 어떤 알고리즘을 사용할까?

#### **Ed25519 권장:**
- ✅ 성능이 중요한 경우
- ✅ Solana 블록체인 사용
- ✅ 간단하고 안전한 서명 필요
- ✅ 작은 키 크기 선호
- ❌ FIPS 140-2 준수 필요 (사용 불가)

#### **Secp256k1 권장:**
- ✅ Ethereum 블록체인 사용
- ✅ Bitcoin 호환 필요
- ✅ 결정론적 서명 (RFC 6979)
- ❌ FIPS 140-2 준수 필요 (사용 불가)
- ❌ Solana 사용 (사용 불가)

#### **P-256 권장:**
- ✅ FIPS 140-2 준수 필요
- ✅ 기업 환경
- ✅ NIST 표준 선호
- ✅ Ethereum 호환 필요
- ❌ Solana 사용 (사용 불가)
- ❌ 최고 성능 필요 (Medium)

#### **RSA-2048/4096 권장:**
- ✅ 레거시 시스템 호환
- ✅ FIPS 140-2 준수 필요
- ✅ HSM 통합
- ✅ 높은 보안 수준 (RSA-4096)
- ❌ 성능이 중요한 경우 (사용 불가)
- ❌ 블록체인 사용 (사용 불가)
- ❌ 작은 서명 크기 필요 (사용 불가)

---

## 성능 벤치마크

### Apple M1 기준 (대략적)

| Algorithm | Key Gen | Sign | Verify | Total (Sign+Verify) |
|-----------|---------|------|--------|---------------------|
| Ed25519 | ~20 μs | ~30 μs | ~70 μs | **~100 μs** ⚡ |
| Secp256k1 | ~50 μs | ~80 μs | ~150 μs | **~230 μs** 🔶 |
| P-256 | ~50 μs | ~80 μs | ~150 μs | **~230 μs** 🔶 |
| RSA-2048 | ~100 ms | ~1 ms | ~50 μs | **~1.05 ms** 🐌 |
| RSA-4096 | ~800 ms | ~8 ms | ~100 μs | **~8.1 ms** 🐌 |

**결론:** Ed25519가 약 **80배 빠름** (vs RSA-4096)

---

## 보안 고려사항

### 1. 알고리즘 선택 시 주의

```rust
// ❌ 잘못된 선택
// Solana에서 P-256 사용 시도
if let Some(algo) = AlgorithmRegistry::select_algorithm(
    false, true, true, false
) {
    // 이 코드는 실행되지 않음 (None 반환)
    unreachable!();
}

// ✅ 올바른 선택
// Solana는 Ed25519만 지원
let algo = AlgorithmRegistry::recommend_for_solana();
assert_eq!(algo, Algorithm::Ed25519);
```

### 2. 결정론적 서명

```rust
// 결정론적 알고리즘 확인
let is_det = AlgorithmRegistry::is_deterministic(Algorithm::Ed25519);
assert!(is_det);

// 결정론적 서명 장점:
// - Nonce 재사용 공격 방지
// - 테스트 가능성 향상
// - 재현 가능한 서명
```

### 3. 보안 수준

```rust
use sage_crypto_core::crypto::SecurityLevel;

// 최소 보안 수준 설정
let min_security = SecurityLevel::Standard; // 128-bit

let secure_algos = AlgorithmRegistry::by_security_level(min_security);
println!("Secure algorithms: {:?}", secure_algos);
```

---

## Troubleshooting

### "No algorithm found"

**문제:** `select_algorithm()`이 `None` 반환

**해결책:**
```rust
// 요구사항이 충돌하는 경우
let result = AlgorithmRegistry::select_algorithm(
    false, true, true, false
);
// Solana는 Ed25519만 지원, 하지만 FIPS는 P-256/RSA 요구
assert!(result.is_none());

// 요구사항을 완화
let result = AlgorithmRegistry::select_algorithm(
    false, true, false, true // FIPS 비활성화
);
assert_eq!(result, Some(Algorithm::Ed25519));
```

### 성능 최적화

```rust
// ✅ Good: 메타데이터 캐싱
let metadata = AlgorithmRegistry::get_metadata(algorithm);
// 여러 번 사용

// ⚠️ 주의: 반복 조회
for _ in 0..1000 {
    let _ = AlgorithmRegistry::get_metadata(algorithm); // 괜찮음 (빠름)
}
```

---

## Related Documentation

- [Cryptographic Keys Guide](api_usage_guide.md)
- [Multi-Key Management](MULTI_KEY_GUIDE.md)
- [Blockchain Integration](ethereum_integration.md)
- [Ed25519 Guide](ED25519_GUIDE.md)
- [P-256 Guide](P256_GUIDE.md)
- [Secp256k1 Guide](SECP256K1_GUIDE.md)
- [RSA Guide](RSA_GUIDE.md)

---

## Support

- **GitHub Issues**: https://github.com/sage-x-project/sage/issues
- **Documentation**: https://github.com/sage-x-project/sage/tree/main/docs
- **Source Code**: `rs-sage-core/src/crypto/algorithm_registry.rs`

---

**Version**: 0.3.0
**Last Updated**: 2025-10-27
**Status**: Production Ready
